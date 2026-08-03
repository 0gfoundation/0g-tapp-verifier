//! Read-only HTTP interface over the caches.
//!
//! Every response is served from memory. Nothing here fetches evidence or calls
//! the Attestation Service — that only happens in the background refresh loop, so
//! no amount of reading can be turned into load on the nodes or the AS.
//!
//! Every attestation result is reported with the time it was taken. A cached
//! result describes the node as it was at that moment and nothing more.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
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
}

pub type AppState = Arc<RwLock<Shared>>;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/health", get(health))
        .route("/api/apps", get(list_apps))
        .route("/api/apps/:app_id", get(app_detail))
        .route("/api/apps/:app_id/events", get(app_events))
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
    /// Distinct images identified across this app's nodes.
    images: Vec<String>,
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
            let identified: Vec<Option<String>> = cached
                .iter()
                .map(|e| e.image(&s.ref_sets))
                .collect();
            let mut images: Vec<String> = identified.iter().flatten().cloned().collect();
            images.sort();
            images.dedup();
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
                images,
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
            let mut trace_events = 0;
            if let Some(a) = status.get_mut("attested").and_then(|a| a.as_object_mut()) {
                trace_events = a
                    .get("events")
                    .and_then(|e| e.as_array())
                    .map(|e| e.len())
                    .unwrap_or(0);
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
            })
        })
        .collect();

    Ok(Json(json!({
        "app_id": timeline.app_id,
        "signers": signers,
        "history": timeline.entries,
        "current_signers": timeline.current_signers(),
        "now": now(),
    })))
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
