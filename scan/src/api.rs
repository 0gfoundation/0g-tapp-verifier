//! HTTP interface over the caches.
//!
//! Every read is served from memory: reads never fetch evidence or call the
//! Attestation Service, so no amount of reading can be turned into load on the
//! nodes or the AS. The one exception is `POST /api/verify`, which exists
//! precisely to do that work on demand — and is therefore bounded three ways
//! (per-target cooldown with single-flight, chain-registered targets only, a
//! global concurrency cap) plus per-caller quotas. See [`verify`].
//!
//! Every attestation result is reported with the time it was taken. A cached
//! result describes the node as it was at that moment and nothing more.

use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::{chain, keys, status};

/// Shared, in-memory view of both caches. The refresh loop swaps these; readers
/// only ever take the read lock.
pub struct Shared {
    pub registry: chain::Registry,
    pub store: status::Store,
    /// Native balance in wei per signer address, refreshed every round. A plain
    /// chain read, kept apart from attestation results because it changes on its
    /// own schedule and costs nothing.
    pub balances: BTreeMap<String, String>,
    /// The RPC the page hands to a wallet when adding the chain. Held here rather
    /// than hardcoded in the page.
    pub rpc_url: String,
    /// API keys for the one privileged operation here: writing an AS policy.
    pub api_keys: keys::KeyStore,
    /// Where those keys are persisted.
    pub keys_path: std::path::PathBuf,
    /// The registry's admin address — the only signature that may mint a key. Read
    /// from the chain at startup so the authority is the one the chain records.
    pub admin: Option<String>,
    /// Signatures already spent, digest → when seen. A timestamp window alone lets
    /// the same signature be replayed until it expires; remembering it for the width
    /// of the window makes each one single-use without a round trip.
    pub spent: BTreeMap<String, i64>,
    /// Shared with the proxy so the authz check is not a public key-testing oracle.
    pub authz_secret: Option<String>,
    /// The reference values in force. Replaced by the refresh loop, so publishing a
    /// set upstream identifies existing measurements without re-attesting anything.
    pub ref_sets: Arc<Vec<crate::refvalues::RefSet>>,
    /// Where those values came from and the state they were in — served with every
    /// verdict, since "unknown image" only means something next to what it was
    /// compared against.
    pub refs_from: crate::refsource::Provenance,
    /// Unix seconds of the last completed refresh round.
    pub refreshed_at: i64,
    /// For the on-demand endpoint only: reading teeUrls and syncing the chain.
    pub scanner: Arc<chain::Scanner>,
    /// For the on-demand endpoint only: where evidence is evaluated.
    pub as_endpoint: String,
    /// The on-demand endpoint's own bounds. An `Arc` so a handler can clone it
    /// out and wait on its locks without holding this `RwLock` across the wait.
    pub verify: Arc<VerifyState>,
    /// Whether a match on a dev reference set counts as verified. Dev images can
    /// carry an SSH key into the TD; mainnet accepts production sets only.
    pub accept_dev: bool,
}

pub type AppState = Arc<RwLock<Shared>>;

// ─── On-demand verification ──────────────────────────────────────────────────

/// Seconds a fresh result answers repeat requests for the same (app_id, signer).
/// This is what makes the endpoint safe to expose: a node that just rebooted is
/// discovered by all five KMS nodes at once, and one attestation must serve all
/// of them rather than five concurrent quote generations hitting the node.
const VERIFY_COOLDOWN_SECS: i64 = 60;

/// Per-caller request metering, fixed one-minute windows. The quotas are QoS
/// tiers, not a security boundary — authorisation comes from the structural
/// limits (cooldown, chain-registered targets only, the concurrency cap), so a
/// stolen key yields nothing but a bigger quota.
const QUOTA_WINDOW_SECS: i64 = 60;
const ANON_PER_WINDOW: u32 = 6;
const KEYED_PER_WINDOW: u32 = 60;

/// A forced chain sync (for a target the cached registry does not know yet) runs
/// at most this often, whoever asks.
const FORCED_SYNC_MIN_SECS: i64 = 10;

/// Everything that bounds `POST /api/verify`.
pub struct VerifyState {
    /// Global cap on targets being attested on demand at once — the same kind of
    /// limit the refresh loop runs under, protecting this service, the AS and
    /// the nodes. Over capacity answers 429 rather than queueing without bound.
    slots: tokio::sync::Semaphore,
    /// The relay's own, smaller cap. A relay call cannot share results (every one
    /// carries a fresh nonce), so it must not be able to occupy the slots
    /// `/api/verify` and the KMS depend on.
    relay_slots: tokio::sync::Semaphore,
    /// Relay targets that just failed to answer, until when to answer for them without
    /// trying: a blackholed teeUrl would otherwise hold a relay slot for the full
    /// connect timeout on every call, and its timing would tell refused from filtered.
    unreachable: tokio::sync::Mutex<HashMap<String, i64>>,
    /// Single-flight per (app_id, signer): concurrent requests for one target
    /// serialise on its lock, and the latecomers find the fresh result inside
    /// the cooldown instead of repeating the work. Entries are only created for
    /// targets the chain knows, so the map is bounded by the registry.
    targets: tokio::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// Request counters per caller, pruned as windows expire.
    quota: tokio::sync::Mutex<HashMap<String, Window>>,
    /// When a forced chain sync last ran.
    last_sync: tokio::sync::Mutex<i64>,
}

struct Window {
    start: i64,
    count: u32,
}

impl VerifyState {
    pub fn new(concurrency: usize) -> Self {
        Self {
            slots: tokio::sync::Semaphore::new(concurrency),
            relay_slots: tokio::sync::Semaphore::new((concurrency / 2).max(1)),
            unreachable: Default::default(),
            targets: Default::default(),
            quota: Default::default(),
            last_sync: tokio::sync::Mutex::new(0),
        }
    }
}

/// Count one request against a caller's window. `Err(seconds)` when over quota —
/// the time until that window ends, for a Retry-After header.
fn count_request(
    windows: &mut HashMap<String, Window>,
    caller: &str,
    limit: u32,
    now: i64,
) -> Result<(), i64> {
    windows.retain(|_, w| now - w.start < QUOTA_WINDOW_SECS);
    let w = windows
        .entry(caller.to_string())
        .or_insert(Window { start: now, count: 0 });
    if w.count >= limit {
        return Err((w.start + QUOTA_WINDOW_SECS - now).max(1));
    }
    w.count += 1;
    Ok(())
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/health", get(health))
        .route("/api/apps", get(list_apps))
        .route("/api/apps/:app_id", get(app_detail))
        .route("/api/apps/:app_id/cert", get(app_cert))
        .route("/api/apps/:app_id/events", get(app_events))
        // Relay to a node for callers who cannot reach it (its port is open only
        // to this service and its operators). Does work, so bounded like verify.
        .route("/api/apps/:app_id/nodes/:signer/evidence", get(relay_evidence))
        .route("/api/apps/:app_id/nodes/:signer/info", get(relay_info))
        // The one endpoint that does work instead of reading a cache. Mounted
        // twice: consumers configure a base URL and POST `{base}/verify`, and a
        // base of the bare host must work as well as one ending in /api.
        .route("/api/verify", post(verify))
        .route("/verify", post(verify))
        // Key management. Minting and revoking require a signature from the
        // registry's admin; listing is metadata only and carries no secret.
        .route("/api/keys", get(list_keys).post(issue_key))
        .route("/api/keys/revoke", post(revoke_key))
        // Called by the proxy in front of the AS, never by a browser.
        .route("/internal/authz", get(authz))
        .with_state(state)
}

async fn index() -> Html<&'static str> {
    Html(include_str!("index.html"))
}

/// Re-derive `image` and `closest` from the stored measurements against the
/// currently loaded reference values, so a verdict is never older than the values
/// it was reached against.
///
/// `ANY_BSA` is renamed rather than hidden. It is the name of a matching device, not
/// of something a node measured — but on a UKI image it is the ONLY component, so
/// dropping it left an unidentified node showing no measurements at all, which is
/// exactly when someone needs the digest in order to publish or fix a reference
/// value. It is presented as `uki`, which is the reference-value key it is compared
/// against.
fn refreshed_verdict(entry: &status::Entry, sets: &[crate::refvalues::RefSet]) -> serde_json::Value {
    let mut v = serde_json::to_value(entry).unwrap_or(json!({}));
    let Some(a) = &entry.attested else { return v };
    let (image, closest) = a.identify(sets);
    if let Some(obj) = v.get_mut("attested").and_then(|a| a.as_object_mut()) {
        obj.insert("image".into(), json!(image));
        obj.insert("closest".into(), json!(closest));
        // Also derived: the registration this is compared against can change.
        obj.insert("signer_ok".into(), json!(a.signer_ok(&entry.signer)));
        if let Some(m) = obj.get_mut("measured").and_then(|m| m.as_object_mut()) {
            if let Some(bsa) = m.remove(crate::refvalues::ANY_BSA) {
                // Only meaningful on a UKI image; on a grub one these digests are
                // the shim and grub entries, already listed under their own names.
                if a.boot_format == "uki" {
                    m.insert("uki".into(), bsa);
                }
            }
            m.retain(|k, _| !k.starts_with('_'));
        }
    }
    v
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let s = state.read().await;
    Json(json!({
        "contract": s.registry.contract,
        "chain_id": s.registry.chain_id,
        "scanned_to_block": s.registry.scanned_to,
        "events": s.registry.events.len(),
        "apps": s.registry.apps().len(),
        "refreshed_at": s.refreshed_at,
        "now": now(),
        // Everything a wallet needs to offer a top-up, so the page holds no
        // hardcoded chain config of its own.
        "chain": { "id": s.registry.chain_id, "rpc": s.rpc_url },
        // An "image unknown" verdict is only meaningful next to the set of values it
        // was compared against, and the state they were in.
        "reference_values": s.refs_from,
    }))
}

/// Per-app summary for the listing.
#[derive(Serialize)]
struct AppSummary {
    app_id: String,
    /// True when the plaintext app id could not be recovered and this is a hash.
    unnamed: bool,
    events: usize,
    /// Distinct signers that have ever served this app, current ones included.
    signers_ever: usize,
    /// Node signers currently registered on chain. These, and only these, can
    /// obtain the app's KMS key — which is why the count of registered nodes and
    /// the count of VERIFIED ones are reported separately and never merged.
    signers: Vec<String>,
    latest_block: u64,
    /// Current signers that answered with evidence. Registration alone says
    /// nothing about whether a node is up — most registered nodes on the live
    /// registry cannot be reached at all — so "alive" means reachable, not
    /// registered.
    reachable: usize,
    /// Current signers whose boot chain matched a published reference set.
    identified: usize,
    /// Current signers the NODE failed for: unreachable, no such app. This is the
    /// only failure count that says anything about the app.
    failed: usize,
    /// Current signers where evidence arrived but WE could not finish verifying —
    /// an AS error, a reference-value lookup timing out. Counted apart because it
    /// establishes nothing either way, and reporting it as a node failure would
    /// dress our own outage up as theirs.
    verifier_errors: usize,
    /// Age in seconds of the OLDEST cached result, so the listing never looks
    /// fresher than its stalest entry.
    oldest_result_age: Option<i64>,
}

async fn list_apps(State(state): State<AppState>) -> impl IntoResponse {
    let s = state.read().await;
    let now = now();
    let summaries: Vec<AppSummary> = s
        .registry
        .apps()
        .into_iter()
        .map(|app_id| {
            let t = s.registry.timeline(&app_id);
            let signers = t.current_signers();
            // Only CURRENT signers count towards the summary. Results for retired
            // ones stay in the store (they are the sole record of what a since-gone
            // identity attested), but counting them would make an app look busier
            // and staler than it is.
            let cached: Vec<&status::Entry> = signers
                .iter()
                .filter_map(|signer| s.store.get(&app_id, signer))
                .collect();
            // The image itself is deliberately NOT summarised here: it belongs to
            // one machine, and an app's nodes may run on different machines. The
            // per-signer detail is where an image is named.
            let identified: Vec<Option<String>> = cached
                .iter()
                .map(|e| e.image(&s.ref_sets))
                .collect();
            AppSummary {
                unnamed: app_id.starts_with("0x") && app_id.len() == 66,
                events: t.entries.len(),
                signers_ever: t.signers.len(),
                latest_block: t.latest_block(),
                reachable: cached.iter().filter(|e| e.attested.is_some()).count(),
                identified: identified.iter().flatten().count(),
                failed: cached
                    .iter()
                    .filter(|e| e.error.is_some() && !e.verifier_fault)
                    .count(),
                verifier_errors: cached.iter().filter(|e| e.verifier_fault).count(),
                oldest_result_age: cached.iter().map(|e| e.age_secs(now)).max(),
                signers,
                app_id,
            }
        })
        .collect();
    Json(summaries)
}

async fn app_detail(
    State(state): State<AppState>,
    Path(app_id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let s = state.read().await;
    let timeline = s.registry.timeline(&app_id);
    if timeline.entries.is_empty() {
        return Err(StatusCode::NOT_FOUND);
    }

    // The signer is the unit: each one carries its chain registration, its
    // verification result, and its trace. Current and retired signers differ in
    // exactly one way — whether the result can be produced again — so they are
    // reported the same shape rather than as two different kinds of thing. A
    // retired signer's cached result and trace are the only record that will ever
    // exist of it, so they are served with a flag, not omitted.
    //
    // The trace itself is left to the events endpoint: it runs to thousands of
    // entries, and a detail view should not have to ship them.
    let signers: Vec<serde_json::Value> = timeline
        .signers
        .iter()
        .map(|h| {
            let entry = s.store.get(&app_id, &h.signer);
            let mut status = entry
                .map(|e| refreshed_verdict(e, &s.ref_sets))
                .unwrap_or(json!(null));
            let (trace_events, trace_shown) = trace_counts(entry, &app_id);
            // The payloads themselves are served by /events, not duplicated here.
            if let Some(a) = status.get_mut("attested").and_then(|a| a.as_object_mut()) {
                a.remove("events");
            }
            json!({
                "signer": h.signer,
                "intervals": h.intervals,
                "code_updates": h.code_updates,
                "current": h.is_current(),
                "balance_wei": s.balances.get(&h.signer.to_lowercase()),
                // A retired signer's RTMRs are gone with its instance.
                "reverifiable": h.is_current(),
                "status": status,
                "trace_events": trace_events,
                "trace_shown": trace_shown,
            })
        })
        .collect();

    // Attested per signer, and only app-level under `kms`. One value is served when
    // every current signer that attested a key attested the same one; otherwise the
    // per-signer entries are the answer and are never averaged away here.
    // `tls_key_source` says how to read several: expected under `local`, a finding
    // under `kms`.
    let tls_keys = current_tls_keys(&s, &app_id);
    Ok(Json(json!({
        "app_id": timeline.app_id,
        "signers": signers,
        "history": timeline.entries,
        "current_signers": timeline.current_signers(),
        "tls_public_key": (tls_keys.len() == 1).then(|| tls_keys[0].clone()),
        "tls_key_source": app_key_source(&s, &app_id),
        "now": now(),
    })))
}

/// Distinct TLS public-key hashes attested by the app's CURRENT signers.
fn current_tls_keys(s: &Shared, app_id: &str) -> Vec<String> {
    let mut keys: Vec<String> = s
        .registry
        .timeline(app_id)
        .current_signers()
        .iter()
        .filter_map(|signer| s.store.get(app_id, signer))
        .filter_map(|e| e.attested.as_ref())
        .filter_map(|a| a.tls_public_key.clone())
        .collect();
    keys.sort();
    keys.dedup();
    keys
}

/// Where this app's nodes derive their TLS key — which decides whether several
/// distinct keys is an anomaly or the normal state.
///
/// `kms` derives from `(app_id, "tls")`, so every node of the app holds the same key
/// and two of them differing means something is wrong. `local` derives from each
/// node's own signer, which is per-node and re-derived at every boot, so a multi-node
/// app has as many keys as nodes and always will. Treating that as disagreement would
/// condemn every `local` app, including the KMS cluster — which cannot use `kms` at
/// all, since deriving that key means reaching the cluster it is part of.
///
/// Read from the `claim_config` event, because `report_data` does not carry it:
/// `runtime_data` holds only nonce, signer and tls_public_key.
///
/// Answers `kms` only when every current signer that attested a key says so. A node
/// claimed before the field existed reports nothing and is read as `local`, which is
/// what such a node actually does — `local` has always been the default.
fn app_key_source(s: &Shared, app_id: &str) -> &'static str {
    let mut saw_signer = false;
    let all_kms = s
        .registry
        .timeline(app_id)
        .current_signers()
        .iter()
        .filter_map(|signer| s.store.get(app_id, signer))
        .filter_map(|e| e.attested.as_ref())
        .filter(|a| a.tls_public_key.is_some())
        .all(|a| {
            saw_signer = true;
            node_key_source(&a.events) == "kms"
        });
    if saw_signer && all_kms {
        "kms"
    } else {
        "local"
    }
}

/// One node's key source, from the newest `claim_config` in its trace. Kept apart
/// from the app-level rollup so the reading itself can be tested.
///
/// Newest wins: `claim_config` can appear more than once in a boot (the pre-baked
/// mode re-claims when the process restarts), and it is the last one that describes
/// how the node is running now.
fn node_key_source(events: &[crate::attest::RuntimeEvent]) -> &'static str {
    match events
        .iter()
        .rev()
        .find(|e| e.operation == "claim_config")
        .and_then(|e| e.payload.get("tls_key_source"))
        .and_then(|v| v.as_str())
    {
        Some("kms") => "kms",
        _ => "local",
    }
}

/// The app's TLS public-key hash in exactly the shape pinning tools consume:
/// `sha256//<base64>`, one line, text/plain. The whole point is a consumer that
/// needs no tooling —
///
///   curl --pinnedpubkey "$(curl -s https://scan/api/apps/X/cert)" https://node:8443/
///
/// Base64, not the hex we store: curl's `--pinnedpubkey`, okhttp's
/// `CertificatePinner` and Go's `VerifyPeerCertificate` all take base64 of the
/// sha256, and publishing hex would put a conversion step back into every
/// consumer — and then it is not one command any more.
async fn app_cert(
    State(state): State<AppState>,
    Path(app_id): Path<String>,
) -> (StatusCode, String) {
    let s = state.read().await;
    if s.registry.timeline(&app_id).entries.is_empty() {
        return (StatusCode::NOT_FOUND, "no such app\n".into());
    }
    let keys = current_tls_keys(&s, &app_id);
    match keys.as_slice() {
        [] => (
            StatusCode::NOT_FOUND,
            "no attested TLS key for this app (nodes predate 0.4.0, or no certificate was issued)\n"
                .into(),
        ),
        [key] => match hex::decode(key.trim_start_matches("0x")) {
            Ok(bytes) => (
                StatusCode::OK,
                format!(
                    "sha256//{}\n",
                    base64::engine::general_purpose::STANDARD.encode(bytes)
                ),
            ),
            Err(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "stored TLS key is not hex\n".into(),
            ),
        },
        // Several keys means opposite things depending on where they came from, so
        // this branches rather than condemning both cases.
        many => match app_key_source(&s, &app_id) {
            // Normal, and permanent: a local key is derived per node and re-derived
            // every boot, so a multi-node app has one key per node and always will.
            // All of them are legitimate, which curl can express directly —
            // --pinnedpubkey takes several hashes separated by ';' and accepts a peer
            // matching any. Refusing here would leave every local-key app, the KMS
            // cluster included, with no way to be pinned at all.
            "local" => {
                let mut pins = Vec::with_capacity(many.len());
                for key in many {
                    match hex::decode(key.trim_start_matches("0x")) {
                        Ok(bytes) => pins.push(format!(
                            "sha256//{}",
                            base64::engine::general_purpose::STANDARD.encode(bytes)
                        )),
                        Err(_) => {
                            return (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "stored TLS key is not hex\n".into(),
                            )
                        }
                    }
                }
                (StatusCode::OK, format!("{}\n", pins.join(";")))
            }
            // A kms key is derived from (app_id, "tls"), so every node of the app
            // should hold the same one. Two that differ is a real finding, and
            // refusing to pick is the point: serving either would quietly vouch for
            // a node the other may be impersonating.
            _ => (
                StatusCode::CONFLICT,
                format!(
                    "this app's nodes derive their TLS key from the KMS, so they should all \
                     hold the SAME one — these differ, and picking between them is not this \
                     service's call:\n{}\n",
                    many.join("\n")
                ),
            ),
        },
    }
}

#[derive(Deserialize)]
struct EventQuery {
    /// Restrict to one node.
    signer: Option<String>,
    /// Restrict to one measured operation (start_app, get_app_secret_key, …).
    operation: Option<String>,
    /// Which slice of the machine's trace to return: `app` (this app plus the
    /// unattributable machine-scoped events — the default), `others` (what the
    /// other apps on the same machine did), or `all`.
    scope: Option<String>,
    #[serde(default = "default_limit")]
    limit: usize,
}

fn default_limit() -> usize {
    200
}

/// Which apps' events a scope admits.
///
/// The trace belongs to the CVM, not to one app: every app on the machine measures
/// into the same RTMR3. Operations that carry no app id at all (docker_login,
/// add_to_whitelist, claim_config, withdraw_balance) cannot be attributed to any
/// one app, so they are shown under EVERY app on the machine rather than hidden or
/// arbitrarily assigned.
fn in_scope(scope: &str, event_app: Option<&str>, app_id: &str) -> bool {
    match (scope, event_app) {
        ("all", _) => true,
        // Unattributable: belongs to no app, so it is everyone's business.
        (_, None) => true,
        ("others", Some(a)) => a != app_id,
        // "app" and anything unrecognised.
        (_, Some(a)) => a == app_id,
    }
}

/// `(measured on this machine, what the trace shows for this app)`.
///
/// Both numbers come from one list through one filter — the same `in_scope` the
/// events endpoint applies — because the label sits directly above those rows. Counting
/// the machine there instead once printed "5 measured operations" above three rows: the
/// two events belonging to another app on the same CVM were counted but not shown.
fn trace_counts(entry: Option<&status::Entry>, app_id: &str) -> (usize, usize) {
    entry
        .and_then(|e| e.attested.as_ref())
        .map(|a| {
            (
                a.events.len(),
                a.events
                    .iter()
                    .filter(|ev| in_scope("app", ev.app_id(), app_id))
                    .count(),
            )
        })
        .unwrap_or((0, 0))
}

/// The measured runtime event log, newest last. Paged because a long-lived node's
/// log runs to thousands of entries — RTMR3 only ever appends.
async fn app_events(
    State(state): State<AppState>,
    Path(app_id): Path<String>,
    Query(q): Query<EventQuery>,
) -> Result<impl IntoResponse, StatusCode> {
    let s = state.read().await;
    let entries: Vec<&status::Entry> = s
        .store
        .for_app(&app_id)
        .into_iter()
        .filter(|e| {
            q.signer
                .as_deref()
                .map(|w| e.signer.eq_ignore_ascii_case(w))
                .unwrap_or(true)
        })
        .collect();
    if entries.is_empty() {
        return Err(StatusCode::NOT_FOUND);
    }

    let scope = q.scope.as_deref().unwrap_or("app");
    let nodes: Vec<serde_json::Value> = entries
        .iter()
        .map(|e| {
            let (total, matched, events) = match &e.attested {
                Some(a) => {
                    let filtered: Vec<&crate::attest::RuntimeEvent> = a
                        .events
                        .iter()
                        .filter(|ev| {
                            in_scope(scope, ev.app_id(), &app_id)
                                && q.operation
                                    .as_deref()
                                    .map(|op| ev.operation == op)
                                    .unwrap_or(true)
                        })
                        .collect();
                    // Newest are the interesting ones, so drop from the front and
                    // say how many were dropped.
                    let skip = filtered.len().saturating_sub(q.limit);
                    (a.event_count, filtered.len(), filtered.into_iter().skip(skip).collect::<Vec<_>>())
                }
                None => (0, 0, vec![]),
            };
            json!({
                "signer": e.signer,
                "checked_at": e.checked_at,
                "error": e.error,
                // The trace covers the whole machine; these three numbers say how
                // much of it this response actually shows.
                "trace_total": total,
                "in_scope": matched,
                "returned": events.len(),
                "events": events,
            })
        })
        .collect();

    Ok(Json(
        json!({"app_id": app_id, "scope": scope, "nodes": nodes, "now": now()}),
    ))
}


#[derive(Deserialize)]
struct VerifyRequest {
    app_id: String,
    signer: String,
}

/// Attest one node now and return the verdict — for consumers whose decision
/// cannot wait for the polling loop. A tapp node re-derives its signer on every
/// restart, so anything gating on "this signer is verified" (the KMS admitting a
/// freshly rebooted node, for one) would otherwise stall until the next round.
///
/// Public by design. What keeps that safe is structural, not caller identity:
///
/// 1. a fresh result inside [`VERIFY_COOLDOWN_SECS`] is returned as-is, and
///    concurrent requests for one target single-flight into one attestation;
/// 2. the target must be a CURRENT node of the app on chain, and its teeUrl is
///    read from the chain — a URL in the request would be an SSRF primitive, so
///    there is none, and unregistered targets are refused before any fetch;
/// 3. at most [`VerifyState::slots`] attestations run at once; over capacity is
///    429, not a queue.
///
/// The API key (`Authorization: Bearer` or `x-api-key`) only selects a bigger
/// request quota.
async fn verify(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<VerifyRequest>,
) -> Response {
    let (app_id, signer) = match parse_target(&req.app_id, &req.signer) {
        Ok(t) => t,
        Err(r) => return r,
    };
    let verify_state = state.read().await.verify.clone();
    if let Err(r) = charge_caller(&state, &verify_state, &headers, peer).await {
        return r;
    }
    let latest_block = match resolve_current_target(&state, &verify_state, &app_id, &signer).await {
        Ok(b) => b,
        Err(r) => return r,
    };

    // Single-flight: whoever holds the target's lock does the work; the others
    // wait here and then hit the cooldown check below.
    let flight = {
        let mut targets = verify_state.targets.lock().await;
        targets
            .entry(format!("{app_id}|{signer}"))
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    };
    let _flight = flight.lock().await;

    {
        let s = state.read().await;
        if let Some(entry) = s.store.get(&app_id, &signer) {
            if entry.age_secs(now()) < VERIFY_COOLDOWN_SECS {
                return verdict_response(&s, entry, true);
            }
        }
    }

    let Ok(_permit) = verify_state.slots.try_acquire() else {
        return too_many(5);
    };

    let (scanner, as_endpoint, ref_sets) = {
        let s = state.read().await;
        (s.scanner.clone(), s.as_endpoint.clone(), s.ref_sets.clone())
    };
    let entry =
        crate::attest_one(&scanner, &app_id, &signer, latest_block, &as_endpoint, &ref_sets).await;

    // Into the shared store, so the page and the summaries serve it too. Not
    // saved to disk here: the refresh loop persists on its own schedule, and a
    // lost on-demand result is regenerated by the next request.
    let mut s = state.write().await;
    s.store.put(entry.clone());
    let s = s.downgrade();
    verdict_response(&s, &entry, false)
}

fn parse_target(app_id: &str, signer: &str) -> Result<(String, String), Response> {
    let signer = signer.trim().to_lowercase();
    if signer.parse::<ethers::types::Address>().is_err() {
        return Err((StatusCode::BAD_REQUEST, "signer must be a 0x… address\n").into_response());
    }
    let app_id = app_id.trim().to_string();
    if app_id.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "app_id must not be empty\n").into_response());
    }
    Ok((app_id, signer))
}

/// Count the request against its caller's quota.
///
/// Caller class: a presented key that verifies buys the keyed quota; anything
/// else — no key, bad key — is metered per IP, so this is not a key-testing
/// oracle: guessing is capped by the anonymous quota itself. The key check is
/// read-only (no last-used stamp) so the hot path never takes the write lock.
async fn charge_caller(
    state: &AppState,
    verify_state: &VerifyState,
    headers: &HeaderMap,
    peer: SocketAddr,
) -> Result<(), Response> {
    let (caller, limit) = match presented_key(headers) {
        Some(secret) => match state.read().await.api_keys.check(secret, now()) {
            Some(id) => (format!("key:{id}"), KEYED_PER_WINDOW),
            None => (anon_caller(headers, peer), ANON_PER_WINDOW),
        },
        None => (anon_caller(headers, peer), ANON_PER_WINDOW),
    };
    let mut windows = verify_state.quota.lock().await;
    count_request(&mut windows, &caller, limit, now()).map_err(too_many)
}

/// The latest registry block for the app, when `signer` is one of its CURRENT
/// nodes; 404 otherwise. The cached registry lags the chain by up to one sync
/// interval, and "this signer just changed" is exactly when these endpoints get
/// called — so an unknown target forces one sync (rate-limited globally) before
/// it is refused.
async fn resolve_current_target(
    state: &AppState,
    verify_state: &VerifyState,
    app_id: &str,
    signer: &str,
) -> Result<u64, Response> {
    let mut latest_block = current_target_block(state, app_id, signer).await;
    if latest_block.is_none() {
        let due = {
            let mut last = verify_state.last_sync.lock().await;
            let n = now();
            (n - *last >= FORCED_SYNC_MIN_SECS).then(|| *last = n).is_some()
        };
        if due {
            let scanner = state.read().await.scanner.clone();
            match scanner.sync().await {
                Ok((registry, added)) => {
                    if added > 0 {
                        tracing::info!("forced sync for {app_id}/{signer}: {added} new event(s)");
                    }
                    // Never roll the shared view back behind a concurrent sync.
                    let mut s = state.write().await;
                    if registry.scanned_to >= s.registry.scanned_to {
                        s.registry = registry;
                    }
                }
                Err(e) => tracing::warn!("forced chain sync failed: {e}"),
            }
            latest_block = current_target_block(state, app_id, signer).await;
        }
    }
    latest_block.ok_or_else(|| {
        (StatusCode::NOT_FOUND, "not a current node of this app on chain\n").into_response()
    })
}

// ─── Relay ───────────────────────────────────────────────────────────────────
//
// Nodes keep their management port closed to everyone but this service and their
// operators. Anyone else reaches a node's evidence through here. That costs no
// trust: evidence verifies itself (the quote is Intel-signed and commits to the
// signer and the event log), and the one thing a relay could still do — hand back
// an old quote as a new one — is what the caller's nonce rules out, because the
// node writes it into report_data. So the nonce goes to the node untouched and a
// relayed answer is never a cached one.
//
// Bounded like `/api/verify`: current on-chain nodes only, with the teeUrl read
// from the chain rather than the request, the per-caller quota, and a concurrency
// cap of its own; node calls time out. The teeUrl is still the registrant's choice
// and may name an internal address (legitimately: a node in this service's VPC), so
// a failure is reported only as "unreachable" or "answered with an error" — the raw
// connection error would let a registrant probe what is reachable from here.

/// The longest challenge GetEvidence accepts.
const MAX_NONCE_BYTES: usize = 64;

#[derive(Deserialize)]
struct EvidenceQuery {
    nonce: Option<String>,
}

/// A caller's challenge: hex, `0x` optional, at most [`MAX_NONCE_BYTES`].
fn parse_nonce(raw: Option<&str>) -> Result<Vec<u8>, String> {
    let Some(raw) = raw.map(str::trim).filter(|r| !r.is_empty()) else {
        return Ok(Vec::new());
    };
    let bytes = hex::decode(raw.strip_prefix("0x").unwrap_or(raw))
        .map_err(|_| "nonce must be hex".to_string())?;
    if bytes.len() > MAX_NONCE_BYTES {
        return Err(format!(
            "nonce is {} bytes; at most {MAX_NONCE_BYTES}",
            bytes.len()
        ));
    }
    Ok(bytes)
}

/// Everything before a node is contacted on a caller's behalf: a well-formed,
/// current target, the caller's quota, and its teeUrl from the chain.
async fn relay_target(
    state: &AppState,
    verify_state: &VerifyState,
    headers: &HeaderMap,
    peer: SocketAddr,
    app_id: &str,
    signer: &str,
) -> Result<(String, String, String), Response> {
    let (app_id, signer) = parse_target(app_id, signer)?;
    charge_caller(state, verify_state, headers, peer).await?;
    resolve_current_target(state, verify_state, &app_id, &signer).await?;
    let scanner = state.read().await.scanner.clone();
    let tee_url = scanner.node_tee_url(&app_id, &signer).await.map_err(|e| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            format!("cannot read teeUrl from chain: {e}\n"),
        )
            .into_response()
    })?;
    Ok((app_id, signer, tee_url))
}

fn no_store(body: serde_json::Value) -> Response {
    (
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        Json(body),
    )
        .into_response()
}

/// `GET /api/apps/:app_id/nodes/:signer/evidence?nonce=0x…` — the node's evidence,
/// fetched now with the caller's nonce, returned as the node sent it. Verify it
/// yourself (e.g. `tapp-cli verify-app`); this endpoint vouches for nothing.
async fn relay_evidence(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path((app_id, signer)): Path<(String, String)>,
    Query(q): Query<EvidenceQuery>,
) -> Response {
    let nonce = match parse_nonce(q.nonce.as_deref()) {
        Ok(n) => n,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("{e}\n")).into_response(),
    };
    let verify_state = state.read().await.verify.clone();
    let (app_id, signer, tee_url) =
        match relay_target(&state, &verify_state, &headers, peer, &app_id, &signer).await {
            Ok(t) => t,
            Err(r) => return r,
        };
    let key = format!("{app_id}|{signer}");
    if let Some(r) = held_unreachable(&verify_state, &key).await {
        return r;
    }
    let Ok(_permit) = verify_state.relay_slots.try_acquire() else {
        return too_many(5);
    };
    match crate::attest::fetch_evidence_for(&tee_url, &app_id, nonce.clone()).await {
        Ok(r) => no_store(json!({
            "app_id": app_id,
            "signer": signer,
            "tee_url": tee_url,
            "nonce": (!nonce.is_empty()).then(|| format!("0x{}", hex::encode(&nonce))),
            "tee_type": r.tee_type,
            "timestamp": r.timestamp,
            "relayed_at": now(),
            "evidence": base64::engine::general_purpose::STANDARD.encode(&r.evidence),
        })),
        Err(e) => {
            hold_if_unreachable(&verify_state, &key, &e).await;
            node_failure(&app_id, &signer, e)
        }
    }
}

/// How long a target that did not answer is answered for without trying again.
const UNREACHABLE_HOLD_SECS: i64 = 30;

/// `Some(response)` while `key` is held as unreachable.
async fn held_unreachable(verify_state: &VerifyState, key: &str) -> Option<Response> {
    let mut held = verify_state.unreachable.lock().await;
    let now = now();
    held.retain(|_, until| *until > now);
    held.contains_key(key)
        .then(|| (StatusCode::BAD_GATEWAY, "node unreachable\n").into_response())
}

async fn hold_if_unreachable(verify_state: &VerifyState, key: &str, e: &crate::attest::NodeFailure) {
    if matches!(e, crate::attest::NodeFailure::Unreachable(_)) {
        verify_state
            .unreachable
            .lock()
            .await
            .insert(key.to_string(), now() + UNREACHABLE_HOLD_SECS);
    }
}

/// What a caller learns about a node call that failed: which of two classes, never the
/// detail, which goes to this service's log.
fn node_failure(app_id: &str, signer: &str, e: crate::attest::NodeFailure) -> Response {
    tracing::warn!("relay {app_id}/{signer}: {e}");
    let msg = match e {
        crate::attest::NodeFailure::Unreachable(_) => "node unreachable\n",
        crate::attest::NodeFailure::Refused(_) => "node answered with an error\n",
    };
    (StatusCode::BAD_GATEWAY, msg).into_response()
}

/// `GET /api/apps/:app_id/nodes/:signer/info` — the node's public configuration,
/// fetched now. Not attested: informational, and what matters in it (owner, KMS
/// cluster, trust anchors) is in the event log, where it is.
async fn relay_info(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path((app_id, signer)): Path<(String, String)>,
) -> Response {
    let verify_state = state.read().await.verify.clone();
    let (app_id, signer, tee_url) =
        match relay_target(&state, &verify_state, &headers, peer, &app_id, &signer).await {
            Ok(t) => t,
            Err(r) => return r,
        };
    let key = format!("{app_id}|{signer}");
    if let Some(r) = held_unreachable(&verify_state, &key).await {
        return r;
    }
    let Ok(_permit) = verify_state.relay_slots.try_acquire() else {
        return too_many(5);
    };
    match crate::attest::fetch_tapp_info(&tee_url).await {
        Ok(r) => {
            let c = r.config.unwrap_or_default();
            let server = c.server.unwrap_or_default();
            no_store(json!({
                "app_id": app_id,
                "signer": signer,
                "tee_url": tee_url,
                "attested": false,
                "version": r.version,
                "owner": server.owner_address,
                "permission_enabled": server.permission_enabled,
                "kbs_enabled": c.kbs_enabled,
                "kbs_node_urls": c.kbs.map(|k| k.node_urls).unwrap_or_default(),
                "scan_url": c.scan_url,
                "scan_public_key": c.scan_public_key,
                "relayed_at": now(),
            }))
        }
        Err(e) => {
            hold_if_unreachable(&verify_state, &key, &e).await;
            node_failure(&app_id, &signer, e)
        }
    }
}

/// `Some(latest registry block for the app)` when the signer is one of the app's
/// CURRENT nodes in the cached registry, `None` otherwise. Current is the bar:
/// a removed or replaced signer has no claim on anything, however recently.
async fn current_target_block(state: &AppState, app_id: &str, signer: &str) -> Option<u64> {
    let s = state.read().await;
    let t = s.registry.timeline(app_id);
    t.current_signers()
        .iter()
        .any(|c| c.eq_ignore_ascii_case(signer))
        .then(|| t.latest_block())
}

/// The API key a request presents: `Authorization: Bearer …` or `x-api-key` —
/// the KMS sends the latter, tooling tends to send the former.
fn presented_key(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .or_else(|| headers.get("x-api-key").and_then(|v| v.to_str().ok()))
        .map(str::trim)
        .filter(|v| !v.is_empty())
}

/// The anonymous caller identity: the LAST hop of X-Forwarded-For when a proxy
/// put one there, the socket peer otherwise. Last, not first: the standard
/// appending proxy (`$proxy_add_x_forwarded_for`) puts the address it actually
/// saw at the end, while everything before it is client-supplied — metering the
/// first hop would let each spoofed value mint its own quota. A caller reaching
/// this port directly can still write the header; see the README for what the
/// quota does and does not promise.
fn anon_caller(headers: &HeaderMap, peer: SocketAddr) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next_back())
        .map(|ip| format!("ip:{}", ip.trim()))
        .unwrap_or_else(|| format!("ip:{}", peer.ip()))
}

fn too_many(retry_after: i64) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(axum::http::header::RETRY_AFTER, retry_after.to_string())],
        "over quota or capacity — try again later\n",
    )
        .into_response()
}

/// One node's verdict, without the trace: the events run to thousands of entries
/// and megabytes, and an admission decision needs none of them — they stay on
/// the events endpoint.
fn verdict_response(s: &Shared, entry: &status::Entry, cached: bool) -> Response {
    let (code, mut body) = verdict_parts(entry, &s.ref_sets, cached, s.accept_dev);
    if let Some(obj) = body.as_object_mut() {
        obj.insert("reference_values".into(), json!(s.refs_from));
    }
    (code, Json(body)).into_response()
}

/// The wire contract, as a pure function so it has tests. Top-level `verified` +
/// `reason` are what an admission gate consumes (0g-kms reads exactly these);
/// `status` is the full per-signer shape `/api/apps/:app_id` serves, minus the
/// trace, for consumers that want the evidence behind the bool.
///
/// `verified` means all of: evidence obtained and quote verified, the quote
/// attests the registered signer, the runtime event log replays, and the boot
/// chain matches a published reference set. That last one is deliberate — the
/// bar is "runs what was declared", and an image nobody published values for
/// was not declared.
///
/// A failure on OUR side (`verifier_fault`: chain RPC down, AS hiccup) is 503,
/// never a 200 verdict: such a result says nothing about the node, and a gate
/// reading 200+false as a definite negative would blame the node for this
/// service's outage. A node-fault failure (unreachable, no such app) IS a
/// statement about the node: 200, `verified: false`, the error as the reason.
fn verdict_parts(
    entry: &status::Entry,
    sets: &[crate::refvalues::RefSet],
    cached: bool,
    accept_dev: bool,
) -> (StatusCode, serde_json::Value) {
    let mut status = refreshed_verdict(entry, sets);
    if let Some(a) = status.get_mut("attested").and_then(|a| a.as_object_mut()) {
        a.remove("events");
    }
    let (verified, reason) = match &entry.attested {
        None => (
            false,
            entry
                .error
                .clone()
                .unwrap_or_else(|| "attestation failed".into()),
        ),
        Some(a) if !a.signer_ok(&entry.signer) => (
            false,
            format!(
                "the quote attests {}, not the registered signer",
                a.attested_signer.as_deref().unwrap_or("nothing")
            ),
        ),
        Some(a) if !a.runtime_replay_ok => (
            false,
            "the runtime event log does not replay against the signed RTMRs".into(),
        ),
        // What an AS policy used to enforce, and the local verdict must not drop: a
        // DEBUG TD's memory is open to its host, whatever image it runs.
        Some(a) if a.td_debug == Some(true) => (
            false,
            "the TD runs with DEBUG: its host can read and write its memory".into(),
        ),
        Some(a) if a.td_debug.is_none() => (
            false,
            "the TD's DEBUG attribute is not known for this result; it needs re-attesting".into(),
        ),
        Some(a) if a.tcb_status == "Revoked" => (false, "the platform TCB is revoked".into()),
        Some(a) => match a.identify(sets).0 {
            Some(label) if !accept_dev && crate::refvalues::is_dev(&label) => (
                false,
                "the boot chain matches a dev image, which this network does not accept".into(),
            ),
            Some(_) => (true, String::new()),
            None => (
                false,
                "the boot chain matches no published reference set".into(),
            ),
        },
    };
    // Reported, not failed: clouds roll firmware out behind Intel, so a TCB trailing
    // the latest is common on healthy nodes. The advisories say what is outstanding.
    let warnings: Vec<String> = match &entry.attested {
        Some(a) if a.tcb_status != "UpToDate" && a.tcb_status != "Revoked" => vec![format!(
            "TCB {} (advisories: {})",
            a.tcb_status,
            a.advisories.join(", ")
        )],
        _ => vec![],
    };
    let image_env = entry
        .attested
        .as_ref()
        .and_then(|a| a.identify(sets).0)
        .map(|l| if crate::refvalues::is_dev(&l) { "dev" } else { "prod" });
    let code = if entry.error.is_some() && entry.verifier_fault {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::OK
    };
    (
        code,
        json!({
            "app_id": entry.app_id,
            "signer": entry.signer,
            "cached": cached,
            "verified": verified,
            "reason": reason,
            "warnings": warnings,
            "image_env": image_env,
            "status": status,
            "now": now(),
        }),
    )
}

// ─── API keys ────────────────────────────────────────────────────────────────

fn random_hex(bytes: usize) -> String {
    use rand::RngCore;
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

/// Signed requests follow the convention tapp-server already uses: the message is
/// `method:args…:unix_timestamp`, signed with personal_sign, accepted inside a
/// window. No challenge round trip — a caller builds the message itself.
const SIGN_WINDOW_SECS: i64 = 120;

#[derive(Deserialize)]
struct SignedRequest {
    /// The exact signed message.
    message: String,
    /// Its personal_sign signature, 0x-prefixed.
    signature: String,
}

/// Verify a signed request came from the registry admin, recently, and only once.
///
/// A timestamp window on its own leaves the signature replayable until it expires,
/// which for key issuing would mint duplicates; spent signatures are therefore
/// remembered for the width of the window. That is all the state a challenge
/// endpoint was buying, without the extra round trip.
async fn admin_says(
    state: &AppState,
    expect_method: &str,
    req: &SignedRequest,
) -> Result<Vec<String>, (StatusCode, String)> {
    let bad = |m: &str| (StatusCode::BAD_REQUEST, m.to_string());
    let mut s = state.write().await;
    let admin = s
        .admin
        .clone()
        .ok_or((StatusCode::SERVICE_UNAVAILABLE, "admin address unknown".into()))?;

    let parts: Vec<String> = req.message.split(':').map(str::to_string).collect();
    if parts.len() < 2 || parts[0] != expect_method {
        return Err(bad(&format!("message must start with {expect_method}:")));
    }
    let timestamp: i64 = parts
        .last()
        .and_then(|t| t.trim().parse().ok())
        .ok_or_else(|| bad("message must end with a unix timestamp"))?;
    let now = now();
    if (now - timestamp).abs() > SIGN_WINDOW_SECS {
        return Err(bad("timestamp outside the accepted window"));
    }

    let signature: ethers::types::Signature = req
        .signature
        .parse()
        .map_err(|_| bad("signature is not readable"))?;
    let recovered = signature
        .recover(req.message.as_str())
        .map_err(|_| bad("signature does not recover"))?;
    let recovered = format!("0x{}", hex::encode(recovered.as_bytes()));
    if !recovered.eq_ignore_ascii_case(&admin) {
        tracing::warn!("{expect_method} refused: signed by {recovered}, admin is {admin}");
        return Err((
            StatusCode::FORBIDDEN,
            "only the registry admin may do this".into(),
        ));
    }

    // Single use. Prune first so the set stays the size of one window.
    s.spent.retain(|_, seen| now - *seen <= SIGN_WINDOW_SECS);
    let digest = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(req.signature.as_bytes()));
    if s.spent.insert(digest, now).is_some() {
        return Err(bad("this signature has already been used"));
    }
    Ok(parts)
}

/// Mint a key for `issue_key:<label>:<30|90|never>:<timestamp>`. The secret is in
/// this response and nowhere else, ever.
async fn issue_key(
    State(state): State<AppState>,
    Json(req): Json<SignedRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let parts = admin_says(&state, "issue_key", &req).await?;
    if parts.len() != 4 {
        return Err((
            StatusCode::BAD_REQUEST,
            "expected issue_key:<label>:<30|90|never>:<timestamp>".into(),
        ));
    }
    let label = parts[1].trim().to_string();
    if label.is_empty() || label.len() > 64 {
        return Err((StatusCode::BAD_REQUEST, "label must be 1-64 chars".into()));
    }
    let ttl = keys::Ttl::parse(&parts[2]).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let mut s = state.write().await;
    let issued_by = s.admin.clone().unwrap_or_default();
    let secret = format!("tsk_{}", random_hex(24));
    let record = s.api_keys.mint(&label, ttl, &issued_by, now(), secret.clone());
    let path = s.keys_path.clone();
    if let Err(e) = s.api_keys.save(&path) {
        tracing::error!("could not persist api keys: {e}");
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "could not store the key".into()));
    }
    tracing::info!("issued key {} ({}) to {issued_by}", record.id, ttl.label());
    Ok(Json(json!({
        "key": secret,
        "id": record.id,
        "label": record.label,
        "expires_at": record.expires_at,
        "note": "shown once — it is stored here only as a hash",
    })))
}

async fn list_keys(State(state): State<AppState>) -> impl IntoResponse {
    let s = state.read().await;
    Json(json!({ "admin": s.admin, "keys": s.api_keys.list() }))
}

/// Revoke, from `revoke_key:<id>:<timestamp>` — the same authority as issuing.
async fn revoke_key(
    State(state): State<AppState>,
    Json(req): Json<SignedRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let parts = admin_says(&state, "revoke_key", &req).await?;
    if parts.len() != 3 {
        return Err((
            StatusCode::BAD_REQUEST,
            "expected revoke_key:<id>:<timestamp>".into(),
        ));
    }
    let id = parts[1].clone();
    let mut s = state.write().await;
    s.api_keys
        .revoke(&id, now())
        .map_err(|e| (StatusCode::NOT_FOUND, e.to_string()))?;
    let path = s.keys_path.clone();
    s.api_keys
        .save(&path)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    tracing::info!("revoked key {id}");
    Ok(StatusCode::NO_CONTENT)
}

/// The proxy's authorisation subrequest: 204 to let a policy write through, 403 to
/// refuse. Deliberately says nothing else — it is reachable and must not become a
/// way to learn about keys.
async fn authz(State(state): State<AppState>, headers: HeaderMap) -> StatusCode {
    let mut s = state.write().await;
    // Only the proxy may ask, so this cannot be used from outside as an oracle for
    // testing candidate keys.
    if let Some(expected) = s.authz_secret.clone() {
        let given = headers.get("x-authz-secret").and_then(|v| v.to_str().ok());
        if given != Some(expected.as_str()) {
            return StatusCode::FORBIDDEN;
        }
    }
    let presented = headers
        .get("x-forwarded-authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .unwrap_or("");
    if presented.is_empty() {
        return StatusCode::FORBIDDEN;
    }
    let now = now();
    match s.api_keys.accept(presented, now) {
        Some(key) => {
            let id = key.id.clone();
            let path = s.keys_path.clone();
            // Record the use; failing to persist must not refuse a valid key.
            if let Err(e) = s.api_keys.save(&path) {
                tracing::warn!("could not record key use: {e}");
            }
            tracing::info!("policy write authorised by key {id}");
            StatusCode::NO_CONTENT
        }
        None => StatusCode::FORBIDDEN,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attest::RuntimeEvent;
    use std::collections::BTreeMap;

    fn ev(operation: &str, app: Option<&str>) -> RuntimeEvent {
        let payload = match app {
            Some(a) => json!({"operation": operation, "app_id": a}),
            // docker_login, claim_config, … carry no app id at all.
            None => json!({"operation": operation}),
        };
        RuntimeEvent {
            operation: operation.into(),
            payload,
            digest: None,
            digest_matches: true,
        }
    }

    /// A claim_config event that states a key source, as tapp-server measures it.
    fn claim_with_source(source: &str) -> RuntimeEvent {
        RuntimeEvent {
            operation: "claim_config".into(),
            payload: json!({
                "operation": "claim_config",
                "owner": "0xowner",
                "tls_key_source": source,
            }),
            digest: None,
            digest_matches: true,
        }
    }

    #[test]
    fn a_node_that_claimed_kms_is_read_as_kms() {
        assert_eq!(node_key_source(&[claim_with_source("kms")]), "kms");
    }

    #[test]
    fn a_claim_without_the_field_reads_as_local() {
        // Nodes claimed before tls_key_source existed say nothing, and local has
        // always been the default — so that is what they are actually doing.
        assert_eq!(node_key_source(&[ev("claim_config", None)]), "local");
    }

    #[test]
    fn a_node_that_never_claimed_reads_as_local() {
        assert_eq!(node_key_source(&[ev("start_app", Some("mine"))]), "local");
    }

    #[test]
    fn the_newest_claim_decides() {
        // Pre-baked mode re-claims on a process restart, so several claim_config
        // events in one boot are normal. The last one is how the node is running.
        assert_eq!(
            node_key_source(&[claim_with_source("kms"), claim_with_source("local")]),
            "local"
        );
        assert_eq!(
            node_key_source(&[claim_with_source("local"), claim_with_source("kms")]),
            "kms"
        );
    }

    #[test]
    fn an_unrecognised_source_reads_as_local_rather_than_kms() {
        // Refusing to serve a pin is the consequence of reading "kms", so a value
        // nobody recognises must not land there: a typo would take every local app
        // with it.
        assert_eq!(node_key_source(&[claim_with_source("KMS")]), "local");
        assert_eq!(node_key_source(&[claim_with_source("")]), "local");
    }

    fn entry_with(events: Vec<RuntimeEvent>) -> status::Entry {
        status::Entry {
            app_id: "mine".into(),
            signer: "0xaaa".into(),
            tee_url: "http://node:50051".into(),
            checked_at: 1,
            app_latest_block: 1,
            error: None,
            verifier_fault: false,
            attested: Some(status::Attested {
                tcb_status: "UpToDate".into(),
                advisories: vec![],
                attested_signer: Some("0xaaa".into()),
                tls_public_key: None,
                boot_format: "uki".into(),
                measured: BTreeMap::new(),
                runtime_replay_ok: true,
                td_debug: Some(false),
                event_count: events.len(),
                events,
                note: String::new(),
            }),
        }
    }

    /// The label above the trace must count the rows the trace will render. A
    /// machine-wide total there reads as a claim about this app: a node that had run
    /// a previous app id showed "5 measured operations" over three rows.
    #[test]
    fn the_trace_label_counts_only_what_the_trace_shows() {
        let e = entry_with(vec![
            ev("claim_config", None),
            ev("docker_login", None),
            ev("start_app", Some("other")),
            ev("stop_app", Some("other")),
            ev("start_app", Some("mine")),
        ]);
        let (total, shown) = trace_counts(Some(&e), "mine");
        assert_eq!(total, 5);
        // This app's one operation, plus the two that belong to no app.
        assert_eq!(shown, 3);
    }

    /// Every event is either shown here or attributed to another app — the difference
    /// the page prints as "N more from other apps" must not include the shared ones,
    /// which are shown under every app on the machine.
    #[test]
    fn the_remainder_is_exactly_the_other_apps_events() {
        let events = vec![
            ev("docker_login", None),
            ev("start_app", Some("mine")),
            ev("start_app", Some("other")),
        ];
        let e = entry_with(events);
        let (total, shown) = trace_counts(Some(&e), "mine");
        assert_eq!(total - shown, 1);
    }

    #[test]
    fn a_node_that_never_attested_counts_nothing() {
        assert_eq!(trace_counts(None, "mine"), (0, 0));
    }

    // ─── /api/verify quotas ──────────────────────────────────────────────────

    #[test]
    fn the_quota_refuses_the_request_after_the_limit_with_a_sane_retry() {
        let mut w = HashMap::new();
        for _ in 0..ANON_PER_WINDOW {
            assert!(count_request(&mut w, "ip:1.2.3.4", ANON_PER_WINDOW, 1000).is_ok());
        }
        let retry = count_request(&mut w, "ip:1.2.3.4", ANON_PER_WINDOW, 1030).unwrap_err();
        // The window opened at 1000, so it ends at 1060 — 30s from now.
        assert_eq!(retry, 30);
        // Retry-After must never be zero or negative, even at the window's edge.
        let retry = count_request(&mut w, "ip:1.2.3.4", ANON_PER_WINDOW, 1059).unwrap_err();
        assert!(retry >= 1);
    }

    #[test]
    fn a_new_window_starts_clean() {
        let mut w = HashMap::new();
        for _ in 0..ANON_PER_WINDOW {
            count_request(&mut w, "ip:1.2.3.4", ANON_PER_WINDOW, 1000).unwrap();
        }
        assert!(count_request(&mut w, "ip:1.2.3.4", ANON_PER_WINDOW, 1000 + QUOTA_WINDOW_SECS).is_ok());
        // …and the expired windows were pruned rather than accumulating forever.
        assert_eq!(w.len(), 1);
    }

    #[test]
    fn callers_are_metered_apart() {
        let mut w = HashMap::new();
        for _ in 0..ANON_PER_WINDOW {
            count_request(&mut w, "ip:1.2.3.4", ANON_PER_WINDOW, 1000).unwrap();
        }
        assert!(count_request(&mut w, "ip:1.2.3.4", ANON_PER_WINDOW, 1000).is_err());
        // A different IP, and a key holder, are unaffected.
        assert!(count_request(&mut w, "ip:5.6.7.8", ANON_PER_WINDOW, 1000).is_ok());
        assert!(count_request(&mut w, "key:kabc", KEYED_PER_WINDOW, 1000).is_ok());
    }

    // ─── /api/verify wire contract ───────────────────────────────────────────
    //
    // The consumer (0g-kms's admission gate) reads exactly: HTTP status, then
    // top-level `verified` and `reason`. These tests pin that shape — each side
    // testing only against its own mock is how the seam breaks.

    use crate::refvalues::{RefSet, ANY_BSA};

    fn matching_set() -> Vec<RefSet> {
        vec![RefSet {
            label: "gcp/uki/v0.8.0/prod.json".into(),
            values: [(ANY_BSA.to_string(), vec!["u-digest".to_string()])].into(),
        }]
    }

    fn good_entry() -> status::Entry {
        status::Entry {
            app_id: "mine".into(),
            signer: "0xaaa".into(),
            tee_url: "https://node:50052".into(),
            checked_at: 1000,
            app_latest_block: 1,
            error: None,
            verifier_fault: false,
            attested: Some(status::Attested {
                tcb_status: "UpToDate".into(),
                advisories: vec![],
                attested_signer: Some("0xAAA".into()),
                tls_public_key: None,
                boot_format: "uki".into(),
                measured: [(ANY_BSA.to_string(), vec!["u-digest".to_string()])].into(),
                runtime_replay_ok: true,
                td_debug: Some(false),
                event_count: 3,
                events: vec![
                    ev("claim_config", None),
                    ev("start_app", Some("mine")),
                    ev("get_app_secret_key", Some("mine")),
                ],
                note: String::new(),
            }),
        }
    }

    fn with_attested(f: impl FnOnce(&mut status::Attested)) -> status::Entry {
        let mut e = good_entry();
        f(e.attested.as_mut().unwrap());
        e
    }

    #[test]
    fn a_debug_td_is_never_verified() {
        let (_, body) = verdict_parts(&with_attested(|a| a.td_debug = Some(true)), &matching_set(), false, true);
        assert_eq!(body["verified"], json!(false));
        assert!(body["reason"].as_str().unwrap().contains("DEBUG"));
        // A result stored before the attribute was recorded is unknown, not "off".
        let (_, body) = verdict_parts(&with_attested(|a| a.td_debug = None), &matching_set(), false, true);
        assert_eq!(body["verified"], json!(false));
    }

    #[test]
    fn a_trailing_tcb_warns_and_a_revoked_one_fails() {
        let e = with_attested(|a| {
            a.tcb_status = "OutOfDate".into();
            a.advisories = vec!["INTEL-SA-00837".into()];
        });
        let (_, body) = verdict_parts(&e, &matching_set(), false, true);
        assert_eq!(body["verified"], json!(true));
        assert_eq!(body["warnings"][0], json!("TCB OutOfDate (advisories: INTEL-SA-00837)"));
        let (_, body) = verdict_parts(&with_attested(|a| a.tcb_status = "Revoked".into()), &matching_set(), false, true);
        assert_eq!(body["verified"], json!(false));
    }

    #[test]
    fn a_dev_image_is_verified_only_where_dev_is_accepted() {
        let dev = vec![RefSet {
            label: "gcp/uki/v0.8.0-r3/dev.json".into(),
            values: [(ANY_BSA.to_string(), vec!["u-digest".to_string()])].into(),
        }];
        let (_, body) = verdict_parts(&good_entry(), &dev, false, false);
        assert_eq!(body["verified"], json!(false));
        assert_eq!(body["image_env"], json!("dev"));
        let (_, body) = verdict_parts(&good_entry(), &dev, false, true);
        assert_eq!(body["verified"], json!(true));
        let (_, body) = verdict_parts(&good_entry(), &matching_set(), false, false);
        assert_eq!((body["verified"].clone(), body["image_env"].clone()), (json!(true), json!("prod")));
    }

    #[test]
    fn a_good_node_is_verified_with_an_empty_reason_and_no_trace() {
        let (code, body) = verdict_parts(&good_entry(), &matching_set(), false, true);
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body["verified"], json!(true));
        assert_eq!(body["reason"], json!(""));
        assert_eq!(body["cached"], json!(false));
        // The megabytes stay on the events endpoint.
        assert!(body["status"]["attested"].get("events").is_none());
        // …but the evidence behind the bool is served.
        assert_eq!(body["status"]["attested"]["signer_ok"], json!(true));
        assert_eq!(
            body["status"]["attested"]["image"],
            json!("gcp/uki/v0.8.0/prod.json")
        );
    }

    #[test]
    fn each_failed_check_reads_as_a_definite_negative_with_its_reason() {
        // Signer mismatch: the registered identity is not the one in the quote.
        let mut e = good_entry();
        e.attested.as_mut().unwrap().attested_signer = Some("0xbbb".into());
        let (code, body) = verdict_parts(&e, &matching_set(), false, true);
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body["verified"], json!(false));
        assert!(body["reason"].as_str().unwrap().contains("0xbbb"));

        // Unknown image: runs something nobody published values for.
        let (code, body) = verdict_parts(&good_entry(), &[], false, true);
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body["verified"], json!(false));
        assert!(body["reason"].as_str().unwrap().contains("reference set"));

        // Replay mismatch.
        let mut e = good_entry();
        e.attested.as_mut().unwrap().runtime_replay_ok = false;
        let (_, body) = verdict_parts(&e, &matching_set(), false, true);
        assert_eq!(body["verified"], json!(false));
    }

    #[test]
    fn a_node_fault_is_a_200_negative_but_our_fault_is_a_503() {
        // The node's failure is a statement about the node.
        let e = status::Entry::failed(
            "mine", "0xaaa", "https://node:50052", 1, 1000,
            "connection refused".into(), false,
        );
        let (code, body) = verdict_parts(&e, &matching_set(), true, true);
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body["verified"], json!(false));
        assert_eq!(body["reason"], json!("connection refused"));
        assert_eq!(body["cached"], json!(true));

        // Our failure says nothing about the node and must not read as a
        // verdict: the consumer's 5xx path serves stale positives instead of
        // caching a negative.
        let e = status::Entry::failed(
            "mine", "0xaaa", "", 1, 1000,
            "cannot read teeUrl from chain: RPC down".into(), true,
        );
        let (code, body) = verdict_parts(&e, &matching_set(), false, true);
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["verified"], json!(false));
    }
}

#[cfg(test)]
mod relay_tests {
    use super::*;

    #[test]
    fn no_nonce_is_an_empty_challenge() {
        assert_eq!(parse_nonce(None), Ok(Vec::new()));
        assert_eq!(parse_nonce(Some("")), Ok(Vec::new()));
        assert_eq!(parse_nonce(Some("  ")), Ok(Vec::new()));
    }

    #[test]
    fn a_nonce_reaches_the_node_as_the_bytes_the_caller_chose() {
        assert_eq!(parse_nonce(Some("0x00ff10")), Ok(vec![0x00, 0xff, 0x10]));
        assert_eq!(parse_nonce(Some("00FF10")), Ok(vec![0x00, 0xff, 0x10]));
    }

    #[test]
    fn a_nonce_the_node_would_refuse_is_refused_here() {
        assert!(parse_nonce(Some(&"ab".repeat(MAX_NONCE_BYTES))).is_ok());
        assert!(parse_nonce(Some(&"ab".repeat(MAX_NONCE_BYTES + 1))).is_err());
        assert!(parse_nonce(Some("0xzz")).is_err());
        assert!(parse_nonce(Some("abc")).is_err());
    }

    #[test]
    fn a_target_is_a_named_app_and_an_address() {
        assert!(parse_target("app", "0x0000000000000000000000000000000000000001").is_ok());
        assert!(parse_target(" ", "0x0000000000000000000000000000000000000001").is_err());
        assert!(parse_target("app", "http://169.254.169.254/").is_err());
        let (a, s) = parse_target(" app ", "0xABCDEF0000000000000000000000000000000001").unwrap();
        assert_eq!((a.as_str(), s.as_str()), ("app", "0xabcdef0000000000000000000000000000000001"));
    }
}
