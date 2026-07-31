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
    /// Signer registrations over the app's whole life, current ones included.
    registrations: usize,
    /// Node signers currently registered on chain. These, and only these, can
    /// obtain the app's KMS key — which is why the count of registered nodes and
    /// the count of VERIFIED ones are reported separately and never merged.
    signers: Vec<String>,
    latest_block: u64,
    /// Distinct images identified across this app's nodes.
    images: Vec<String>,
    attested: usize,
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
                registrations: t.registrations.len(),
                latest_block: t.latest_block(),
                images,
                attested: cached.iter().filter(|e| e.attested.is_some()).count(),
                failed: cached.iter().filter(|e| e.error.is_some()).count(),
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
    // Node status without the event log; that has its own endpoint so a detail
    // view does not have to ship thousands of entries.
    let nodes: Vec<serde_json::Value> = timeline
        .current_signers()
        .iter()
        .map(|signer| match s.store.get(&app_id, signer) {
            Some(e) => {
                let mut v = serde_json::to_value(e).unwrap_or(json!({}));
                if let Some(a) = v.get_mut("attested").and_then(|a| a.as_object_mut()) {
                    a.remove("events");
                }
                v
            }
            None => json!({"signer": signer, "checked_at": null, "error": "not attested yet"}),
        })
        .collect();

    // Retired registrations carry whatever was cached for them while they were
    // live. That result can never be reproduced — the node's RTMRs are gone — so
    // it is served with a flag saying so rather than silently omitted.
    //
    // The store holds ONE result per (app, signer), so when the same address was
    // registered more than once it can only describe the most recent of those
    // registrations. Attaching it to the earlier ones too would date a result to a
    // stint it was not taken in.
    let latest_of_signer: std::collections::HashMap<&str, usize> = timeline
        .registrations
        .iter()
        .enumerate()
        .map(|(i, r)| (r.signer.as_str(), i))
        .collect();
    let registrations: Vec<serde_json::Value> = timeline
        .registrations
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let result = (latest_of_signer.get(r.signer.as_str()) == Some(&i))
                .then(|| s.store.get(&app_id, &r.signer))
                .flatten();
            json!({
                "signer": r.signer,
                "from_block": r.from_block,
                "to_block": r.to_block,
                "code_updates": r.code_updates,
                "current": r.is_current(),
                "last_result": result.map(|e| json!({
                    "checked_at": e.checked_at,
                    "image": e.image(),
                    "error": e.error,
                })),
                "reverifiable": r.is_current(),
            })
        })
        .collect();

    Ok(Json(json!({
        "app_id": timeline.app_id,
        "registrations": registrations,
        "history": timeline.entries,
        "current_signers": timeline.current_signers(),
        "nodes": nodes,
        "now": now(),
    })))
}

#[derive(Deserialize)]
struct EventQuery {
    /// Restrict to one node.
    signer: Option<String>,
    /// Restrict to one measured operation (start_app, get_app_secret_key, …).
    operation: Option<String>,
    /// Only events measured for this app id; the log covers the whole node.
    #[serde(default)]
    this_app_only: bool,
    #[serde(default = "default_limit")]
    limit: usize,
}

fn default_limit() -> usize {
    100
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

    let nodes: Vec<serde_json::Value> = entries
        .iter()
        .map(|e| {
            let (total, kept, events) = match &e.attested {
                Some(a) => {
                    let filtered: Vec<&crate::attest::RuntimeEvent> = a
                        .events
                        .iter()
                        .filter(|ev| {
                            q.operation
                                .as_deref()
                                .map(|op| ev.operation == op)
                                .unwrap_or(true)
                                && (!q.this_app_only || ev.app_id() == Some(app_id.as_str()))
                        })
                        .collect();
                    let skip = filtered.len().saturating_sub(q.limit);
                    (
                        a.event_count,
                        a.events.len(),
                        filtered.into_iter().skip(skip).collect::<Vec<_>>(),
                    )
                }
                None => (0, 0, vec![]),
            };
            json!({
                "signer": e.signer,
                "checked_at": e.checked_at,
                "error": e.error,
                // total_on_node vs cached makes the truncation explicit rather
                // than letting a partial log look complete.
                "total_on_node": total,
                "cached": kept,
                "events": events,
            })
        })
        .collect();

    Ok(Json(json!({"app_id": app_id, "nodes": nodes, "now": now()})))
}
