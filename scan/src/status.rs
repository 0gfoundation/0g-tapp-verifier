//! Cached attestation results — the thing that makes tappscan a trust *layer*
//! rather than another verification client.
//!
//! Attestation is expensive: a node's evidence is megabytes and grows with every
//! measured operation, because RTMR3 only ever appends. Having every viewer
//! re-fetch and re-submit that is what layer 3 exists to avoid. So results are
//! stored, served while fresh, and refreshed when there is a reason to.
//!
//! A cached result is always "as of `checked_at`", never a standing property: the
//! node may have restarted (new signer, RTMRs reset) a second later. Every
//! consumer must show that timestamp.
//!
//! Re-verification is triggered by the chain, not by a timer: a new registry
//! event for an app is the signal that something about it may have changed. The
//! age limit is only a backstop for things the chain cannot see (a node
//! restarting on its own, its platform TCB going stale).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

use crate::attest::{NodeStatus, RuntimeEvent};

// The whole trace is kept, never a window.
//
// A signer's event log IS its history: RTMR3 only appends, so one fetch yields
// every measured operation from boot onward, and there is nothing a series of
// periodic snapshots would add. But the moment the instance restarts, the log
// resets and the old trace cannot be produced again by anyone. Truncating it would
// therefore not save a re-fetchable convenience — it would destroy the only record
// that will ever exist of what a since-gone identity did.

/// One node's last attestation attempt — successful or not.
///
/// Failures are cached too, and deliberately: "the chain says this node serves
/// the app but the node says it has no such app" is a state an explorer must be
/// able to show, and caching it also stops every reader from re-triggering the
/// same failing multi-megabyte fetch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub app_id: String,
    pub signer: String,
    /// Empty when even reading the node's teeUrl from the chain failed.
    pub tee_url: String,
    /// When this attempt ran (unix seconds).
    pub checked_at: i64,
    /// Latest registry event block for this app at check time. A newer event than
    /// this means the cached result may no longer describe the app.
    pub app_latest_block: u64,
    /// `None` when the attempt succeeded; the reason it failed otherwise.
    pub error: Option<String>,
    /// `None` when the attempt failed.
    pub attested: Option<Attested>,
}

/// What a successful attestation established.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attested {
    pub ear_status: String,
    pub tcb_status: String,
    pub advisories: Vec<String>,
    pub attested_signer: Option<String>,
    pub signer_ok: bool,
    pub boot_format: String,
    /// Label of the reference set that fully matched, if any.
    pub image: Option<String>,
    /// Best partial match when nothing matched fully — the useful diagnostic.
    pub closest: Option<ClosestMatch>,
    /// The digests this node actually measured, component → digests. Kept even
    /// though it is derivable from the evidence: when an image does not match,
    /// this is what someone needs in order to fix a reference value.
    pub measured: BTreeMap<String, Vec<String>>,
    pub runtime_replay_ok: bool,

    pub event_count: usize,
    /// The signer's complete trace, oldest first.
    ///
    /// It is the CVM's log, not the app's: every app on that machine measures into
    /// the same RTMR3, so this contains other apps' operations too, plus
    /// machine-scoped ones (docker_login, add_to_whitelist, claim_config) that
    /// carry no app id at all. Splitting it per app is a presentation concern —
    /// see the events endpoint.
    pub events: Vec<RuntimeEvent>,
    /// Non-empty when the check hit a problem worth showing but still produced a
    /// result (e.g. report_data could not be read).
    pub note: String,
}

/// How close the best non-matching reference set came.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClosestMatch {
    pub label: String,
    /// Components that did NOT match — what to look at first.
    pub failed: Vec<String>,
    pub hits: usize,
    pub total: usize,
}

impl Entry {
    /// Record a failed attempt so the explorer can show it and readers stop
    /// retrying it until the chain moves or the age limit passes.
    pub fn failed(
        app_id: &str,
        signer: &str,
        tee_url: &str,
        app_latest_block: u64,
        checked_at: i64,
        error: String,
    ) -> Self {
        Self {
            app_id: app_id.to_string(),
            signer: signer.to_lowercase(),
            tee_url: tee_url.to_string(),
            checked_at,
            app_latest_block,
            error: Some(error),
            attested: None,
        }
    }

    pub fn from_status(status: &NodeStatus, app_id: &str, app_latest_block: u64) -> Self {
        let closest = status
            .matches
            .iter()
            .find(|m| !m.matched)
            .filter(|_| status.image.is_none())
            .map(|m| ClosestMatch {
                label: m.label.clone(),
                failed: m
                    .components
                    .iter()
                    .filter(|(_, ok)| !ok)
                    .map(|(c, _)| c.clone())
                    .collect(),
                hits: m.hits(),
                total: m.components.len(),
            });
        Self {
            app_id: app_id.to_string(),
            signer: status.signer.clone(),
            tee_url: status.tee_url.clone(),
            checked_at: status.checked_at,
            app_latest_block,
            error: None,
            attested: Some(Attested {
            ear_status: status.ear_status.clone(),
            tcb_status: status.tcb_status.clone(),
            advisories: status.advisories.clone(),
            attested_signer: status.attested_signer.clone(),
            signer_ok: status.signer_ok,
            boot_format: status.boot_format.to_string(),
            image: status.image.clone(),
            closest,
            measured: status
                .measured
                .0
                .iter()
                .filter(|(component, _)| !component.starts_with('_'))
                .map(|(component, digests)| {
                    (component.clone(), digests.iter().cloned().collect())
                })
                .collect(),
            runtime_replay_ok: status.runtime_replay_ok(),
            event_count: status.runtime_events.len(),
            events: status.runtime_events.clone(),
            note: status.note.clone(),
            }),
        }
    }

    pub fn age_secs(&self, now: i64) -> i64 {
        (now - self.checked_at).max(0)
    }

    /// The image this node was identified as, if the attempt succeeded and a
    /// reference set fully matched.
    pub fn image(&self) -> Option<&str> {
        self.attested.as_ref()?.image.as_deref()
    }
}

/// Why a node needs re-attesting (or does not).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// Never attested.
    Missing,
    /// The app changed on chain since the last check.
    ChainMoved,
    /// Older than the age backstop.
    Stale,
    Fresh,
}

impl Freshness {
    pub fn needs_check(self) -> bool {
        self != Freshness::Fresh
    }

    pub fn reason(self) -> &'static str {
        match self {
            Freshness::Missing => "never attested",
            Freshness::ChainMoved => "app changed on chain since the last check",
            Freshness::Stale => "older than the age limit",
            Freshness::Fresh => "fresh",
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Store {
    /// "<app_id>|<signer>" → last result.
    entries: BTreeMap<String, Entry>,
}

fn key(app_id: &str, signer: &str) -> String {
    format!("{app_id}|{}", signer.to_lowercase())
}

impl Store {
    pub fn load(path: &Path) -> Self {
        match std::fs::read(path).map(|raw| serde_json::from_slice::<Store>(&raw)) {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                tracing::warn!("status cache unreadable ({e}) — starting fresh");
                Store::default()
            }
            Err(_) => Store::default(),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).ok();
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)
            .with_context(|| format!("write {}", tmp.display()))?;
        std::fs::rename(&tmp, path).with_context(|| format!("rename into {}", path.display()))?;
        Ok(())
    }

    pub fn get(&self, app_id: &str, signer: &str) -> Option<&Entry> {
        self.entries.get(&key(app_id, signer))
    }

    pub fn put(&mut self, entry: Entry) {
        self.entries.insert(key(&entry.app_id, &entry.signer), entry);
    }

    /// Entries for one app, in signer order.
    pub fn for_app(&self, app_id: &str) -> Vec<&Entry> {
        let prefix = format!("{app_id}|");
        self.entries
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .map(|(_, v)| v)
            .collect()
    }

    /// Whether this node needs attesting. `app_latest_block` is the app's most
    /// recent registry event; `max_age` is the backstop in seconds.
    pub fn freshness(
        &self,
        app_id: &str,
        signer: &str,
        app_latest_block: u64,
        max_age: i64,
        now: i64,
    ) -> Freshness {
        let Some(entry) = self.get(app_id, signer) else {
            return Freshness::Missing;
        };
        if app_latest_block > entry.app_latest_block {
            return Freshness::ChainMoved;
        }
        if entry.age_secs(now) > max_age {
            return Freshness::Stale;
        }
        Freshness::Fresh
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(app: &str, signer: &str, checked_at: i64, block: u64) -> Entry {
        Entry {
            app_id: app.into(),
            signer: signer.to_lowercase(),
            tee_url: "http://node:50051".into(),
            checked_at,
            app_latest_block: block,
            error: None,
            attested: Some(Attested {
                ear_status: "affirming".into(),
                tcb_status: "UpToDate".into(),
                advisories: vec![],
                attested_signer: Some(signer.to_lowercase()),
                signer_ok: true,
                boot_format: "uki".into(),
                image: Some("gcp/uki/v0.3.0/dev.json".into()),
                closest: None,
                measured: BTreeMap::new(),
                runtime_replay_ok: true,
                event_count: 0,
                events: vec![],
                note: String::new(),
            }),
        }
    }

    #[test]
    fn missing_then_fresh() {
        let mut s = Store::default();
        assert_eq!(
            s.freshness("app", "0xaaa", 100, 300, 1000),
            Freshness::Missing
        );
        s.put(entry("app", "0xaaa", 1000, 100));
        assert_eq!(s.freshness("app", "0xaaa", 100, 300, 1000), Freshness::Fresh);
    }

    #[test]
    fn a_new_chain_event_forces_a_recheck_even_when_fresh() {
        let mut s = Store::default();
        s.put(entry("app", "0xaaa", 1000, 100));
        // Same second, but the app moved on chain.
        assert_eq!(
            s.freshness("app", "0xaaa", 101, 300, 1000),
            Freshness::ChainMoved
        );
    }

    #[test]
    fn age_is_only_a_backstop() {
        let mut s = Store::default();
        s.put(entry("app", "0xaaa", 1000, 100));
        assert_eq!(s.freshness("app", "0xaaa", 100, 300, 1299), Freshness::Fresh);
        assert_eq!(s.freshness("app", "0xaaa", 100, 300, 1301), Freshness::Stale);
    }

    #[test]
    fn signer_lookup_is_case_insensitive() {
        let mut s = Store::default();
        s.put(entry("app", "0xAAA", 1000, 100));
        assert!(s.get("app", "0xaaa").is_some());
        assert!(s.get("app", "0xAAA").is_some());
    }

    #[test]
    fn for_app_does_not_leak_across_similarly_named_apps() {
        let mut s = Store::default();
        s.put(entry("app", "0xaaa", 1, 1));
        s.put(entry("app-dev", "0xbbb", 1, 1));
        let mine = s.for_app("app");
        assert_eq!(mine.len(), 1);
        assert_eq!(mine[0].signer, "0xaaa");
    }

    #[test]
    fn round_trips_through_disk() {
        let dir = std::env::temp_dir().join(format!("tappscan-test-{}", std::process::id()));
        let path = dir.join("status.json");
        let mut s = Store::default();
        s.put(entry("app", "0xaaa", 1000, 100));
        s.save(&path).unwrap();
        let loaded = Store::load(&path);
        assert_eq!(loaded.get("app", "0xaaa").unwrap().checked_at, 1000);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A failed attempt is cached like any other, so readers see the reason and
    /// stop re-triggering it until the chain moves or the age limit passes.
    #[test]
    fn failures_are_cached_and_count_as_fresh() {
        let mut s = Store::default();
        s.put(Entry::failed(
            "app",
            "0xAAA",
            "http://node:50051",
            100,
            1000,
            "App app not found".into(),
        ));
        let e = s.get("app", "0xaaa").expect("cached failure");
        assert_eq!(e.error.as_deref(), Some("App app not found"));
        assert!(e.attested.is_none());
        assert_eq!(e.image(), None);
        assert_eq!(s.freshness("app", "0xaaa", 100, 300, 1000), Freshness::Fresh);
        // …but a chain change still forces a retry.
        assert_eq!(
            s.freshness("app", "0xaaa", 101, 300, 1000),
            Freshness::ChainMoved
        );
    }

    #[test]
    fn unreadable_cache_starts_fresh_instead_of_failing() {
        let dir = std::env::temp_dir().join(format!("tappscan-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("status.json");
        std::fs::write(&path, b"not json").unwrap();
        assert!(Store::load(&path).for_app("app").is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }
}
