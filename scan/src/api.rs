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
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::{chain, status};

/// Shared, in-memory view of both caches. The refresh loop swaps these; readers
/// only ever take the read lock.
pub struct Shared {
    pub registry: chain::Registry,
    pub store: status::Store,
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
        .with_state(state)
}

async fn index() -> Html<&'static str> {
    Html(include_str!("index.html"))
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
    /// Current signers whose last attempt failed (unreachable, no such app, …).
    failed: usize,
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
            let mut images: Vec<String> = cached
                .iter()
                .filter_map(|e| e.image().map(str::to_string))
                .collect();
            images.sort();
            images.dedup();
            AppSummary {
                unnamed: app_id.starts_with("0x") && app_id.len() == 66,
                events: t.entries.len(),
                signers_ever: t.signers.len(),
                latest_block: t.latest_block(),
                reachable: cached.iter().filter(|e| e.attested.is_some()).count(),
                identified: cached.iter().filter(|e| e.image().is_some()).count(),
                failed: cached.iter().filter(|e| e.error.is_some()).count(),
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
                .map(|e| serde_json::to_value(e).unwrap_or(json!({})))
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
