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
    /// True when the failure was OURS, not the node's: evidence arrived and the
    /// verifier could not finish with it. Such a result says nothing about the node,
    /// must not be presented as one, and is retried rather than held for the age
    /// backstop — a transient AS hiccup should not hide an app for an hour.
    #[serde(default)]
    pub verifier_fault: bool,
    /// `None` when the attempt failed.
    pub attested: Option<Attested>,
}

/// What one attestation OBSERVED — and only that.
///
/// The test for belonging here is whether recomputing it later could give a
/// different answer. These cannot: they were read out of a signed token at
/// `checked_at`, and re-reading that same evidence a year from now yields the same
/// values.
///
/// Anything that compares an observation against something outside it is derived
/// and is NOT stored, because the outside thing moves and a stored answer then goes
/// quietly stale:
///
/// * which image this is, and which set it came closest to — needs the published
///   reference values, which change (and a set published later identifies these
///   measurements retroactively, retired signers included);
/// * whether the attested signer matches its registration — needs the chain, where
///   a node can be removed or replaced.
///
/// Both are recomputed on read. Storing them once cost a day of chasing verdicts
/// that were frozen against values that had since moved.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attested {
    /// Platform TCB level as the AS reported it, and the advisories it names.
    pub tcb_status: String,
    pub advisories: Vec<String>,
    /// The address in the quote's report_data. Whether it MATCHES the registration
    /// is derived — the chain moves.
    pub attested_signer: Option<String>,
    /// sha256 of the app's TLS public key (hex), when the node attested one
    /// (tapp-server ≥0.4.0 with a TLS certificate issued). App-level in practice
    /// but attested per signer — two signers of one app reporting different keys
    /// is an anomaly to show, not to average away.
    #[serde(default)]
    pub tls_public_key: Option<String>,
    /// grub or uki, decided structurally from `measured` alone.
    pub boot_format: String,
    /// Boot-chain digests this node measured, component → digests. The whole map,
    /// pseudo-components included: filtering here is what once made a UKI node —
    /// whose only component is a pseudo-component — store nothing at all.
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

impl Attested {
    /// Whether the quote's address is the one registered on chain for this node.
    /// Derived, not stored: a registration can be replaced or removed.
    pub fn signer_ok(&self, registered: &str) -> bool {
        self.attested_signer
            .as_deref()
            .map(|a| a.eq_ignore_ascii_case(registered))
            .unwrap_or(false)
    }

    /// Re-derive the verdict from the stored measurements against the reference
    /// values loaded right now.
    pub fn identify(
        &self,
        sets: &[crate::refvalues::RefSet],
    ) -> (Option<String>, Option<ClosestMatch>) {
        let mut measured = crate::refvalues::Measured::default();
        for (component, digests) in &self.measured {
            for d in digests {
                measured.add(component, d);
            }
        }
        let matches = crate::refvalues::match_sets(&measured, sets);
        let image = matches.iter().find(|m| m.matched).map(|m| m.label.clone());
        let closest = if image.is_some() {
            None
        } else {
            crate::refvalues::closest(&measured, sets, &matches).map(|m| ClosestMatch {
                label: m.label.clone(),
                failed: m
                    .components
                    .iter()
                    .filter(|(_, ok)| !ok)
                    .map(|(c, _)| c.clone())
                    .collect(),
                hits: m.hits(),
                total: m.components.len(),
            })
        };
        (image, closest)
    }
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
        verifier_fault: bool,
    ) -> Self {
        Self {
            app_id: app_id.to_string(),
            signer: signer.to_lowercase(),
            tee_url: tee_url.to_string(),
            checked_at,
            app_latest_block,
            error: Some(error),
            verifier_fault,
            attested: None,
        }
    }

    pub fn from_status(status: &NodeStatus, app_id: &str, app_latest_block: u64) -> Self {
        Self {
            app_id: app_id.to_string(),
            signer: status.signer.clone(),
            tee_url: status.tee_url.clone(),
            checked_at: status.checked_at,
            app_latest_block,
            error: None,
            verifier_fault: false,
            attested: Some(Attested {
            tcb_status: status.tcb_status.clone(),
            advisories: status.advisories.clone(),
            attested_signer: status.attested_signer.clone(),
            tls_public_key: status.tls_public_key.clone(),
            boot_format: status.boot_format.to_string(),
            // Every component, the ANY_BSA pseudo-component included: it is what a
            // UKI reference value matches against, so dropping it would make a
            // re-identification impossible. Display filters it, storage does not.
            measured: status
                .measured
                .0
                .iter()
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

    /// The image this node is identified as against the reference values given.
    /// Derived on every call — see [`Attested`] for why it is not stored.
    pub fn image(&self, sets: &[crate::refvalues::RefSet]) -> Option<String> {
        self.attested.as_ref()?.identify(sets).0
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
    /// The last attempt failed on our side, so nothing was established.
    VerifierFailed,
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
            Freshness::VerifierFailed => "last attempt failed on the verifier side",
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

    /// Save, keeping whichever copy of each entry is newer.
    ///
    /// Two processes legitimately hold this file: a long-running `serve` and an
    /// operator's one-off `check --force`. Writing the in-memory copy blindly makes
    /// it last-writer-wins, so a forced re-check against a running instance was
    /// silently discarded the moment the loop next saved — the check appeared to
    /// work and changed nothing. Merging costs a read and means either side can
    /// advance the other.
    pub fn save(&self, path: &Path) -> Result<()> {
        let mut merged = Store::load(path);
        for (key, entry) in &self.entries {
            let newer = merged
                .entries
                .get(key)
                .map(|existing| entry.checked_at >= existing.checked_at)
                .unwrap_or(true);
            if newer {
                merged.entries.insert(key.clone(), entry.clone());
            }
        }
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).ok();
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&merged)?)
            .with_context(|| format!("write {}", tmp.display()))?;
        std::fs::rename(&tmp, path).with_context(|| format!("rename into {}", path.display()))?;
        Ok(())
    }

    /// Take any entry on disk that is newer than the one held here.
    ///
    /// The other half of sharing the file: a running instance picks up an operator's
    /// forced re-check on its next round instead of ignoring it for an hour.
    pub fn merge_from_disk(&mut self, path: &Path) -> usize {
        let disk = Store::load(path);
        let mut taken = 0;
        for (key, entry) in disk.entries {
            let newer = self
                .entries
                .get(&key)
                .map(|mine| entry.checked_at > mine.checked_at)
                .unwrap_or(true);
            if newer {
                self.entries.insert(key, entry);
                taken += 1;
            }
        }
        taken
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
        // Our own failure is not a result to sit on. Retry it next round rather than
        // holding a transient AS hiccup for the whole age backstop.
        if entry.verifier_fault {
            return Freshness::VerifierFailed;
        }
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
            verifier_fault: false,
            attested: Some(Attested {
                tcb_status: "UpToDate".into(),
                advisories: vec![],
                attested_signer: Some(signer.to_lowercase()),
                tls_public_key: None,
                boot_format: "uki".into(),
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

    /// The round trip, which nothing covered before: a UKI node's measurements go
    /// through the store and must still identify afterwards.
    ///
    /// This is the shape that broke. A UKI image measures exactly one component, and
    /// it is the ANY_BSA pseudo-component; storage used to drop names starting with
    /// `_` — a display decision applied at write time — so a UKI node persisted an
    /// EMPTY measurement map. Nothing noticed while the verdict was computed at check
    /// time and stored beside it. The moment the verdict was derived from storage
    /// instead, every UKI node became unidentifiable.
    #[test]
    fn a_uki_measurement_survives_storage_and_still_identifies() {
        use crate::refvalues::{RefSet, ANY_BSA};

        let mut measured = crate::refvalues::Measured::default();
        measured.add(ANY_BSA, "u-digest");
        let status = crate::attest::NodeStatus {
            signer: "0xaaa".into(),
            tee_url: "http://node:50051".into(),
            checked_at: 1000,
            tcb_status: "OutOfDate".into(),
            advisories: vec![],
            attested_signer: Some("0xaaa".into()),
            tls_public_key: None,
            boot_format: "uki",
            measured,
            matches: vec![],
            runtime_events: vec![],
            replay_mismatches: 0,
            note: String::new(),
        };

        let dir = std::env::temp_dir().join(format!("tappscan-uki-{}", std::process::id()));
        let path = dir.join("status.json");
        let mut store = Store::default();
        store.put(Entry::from_status(&status, "app", 1));
        store.save(&path).unwrap();

        let reloaded = Store::load(&path);
        let entry = reloaded.get("app", "0xaaa").expect("entry survived");
        let attested = entry.attested.as_ref().expect("attested survived");
        assert!(
            attested.measured.contains_key(ANY_BSA),
            "the only component a UKI node measures must be stored, or it can never \
             be identified again: {:?}",
            attested.measured
        );

        let sets = vec![RefSet {
            label: "ali/uki/v0.3.0/dev.json".into(),
            values: [(ANY_BSA.to_string(), vec!["u-digest".to_string()])].into(),
        }];
        let (image, closest) = attested.identify(&sets);
        assert_eq!(image.as_deref(), Some("ali/uki/v0.3.0/dev.json"));
        assert!(closest.is_none());

        std::fs::remove_dir_all(&dir).ok();
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
            false,
        ));
        let e = s.get("app", "0xaaa").expect("cached failure");
        assert_eq!(e.error.as_deref(), Some("App app not found"));
        assert!(e.attested.is_none());
        assert_eq!(e.image(&[]), None);
        assert_eq!(s.freshness("app", "0xaaa", 100, 300, 1000), Freshness::Fresh);
        // …but a chain change still forces a retry.
        assert_eq!(
            s.freshness("app", "0xaaa", 101, 300, 1000),
            Freshness::ChainMoved
        );
    }

    /// A failure on OUR side is not a result to sit on: it establishes nothing, so
    /// it is retried next round instead of being held for the age backstop.
    /// Sharing the file must not mean losing work: whichever copy of an entry is
    /// newer survives, in both directions.
    #[test]
    fn saving_merges_rather_than_overwrites() {
        let dir = std::env::temp_dir().join(format!("tappscan-merge-{}", std::process::id()));
        let path = dir.join("status.json");

        // A long-running instance saves what it has.
        let mut serve = Store::default();
        serve.put(entry("app", "0xaaa", 1000, 100));
        serve.put(entry("app", "0xbbb", 1000, 100));
        serve.save(&path).unwrap();

        // An operator forces a re-check of one node, from a separate process.
        let mut cli = Store::load(&path);
        cli.put(entry("app", "0xaaa", 2000, 100));
        cli.save(&path).unwrap();

        // The loop saves its own, now-stale copy — and must not undo the operator.
        serve.save(&path).unwrap();
        let on_disk = Store::load(&path);
        assert_eq!(on_disk.get("app", "0xaaa").unwrap().checked_at, 2000);
        assert_eq!(on_disk.get("app", "0xbbb").unwrap().checked_at, 1000);

        // …and the loop picks the newer result up rather than ignoring it.
        assert_eq!(serve.merge_from_disk(&path), 1);
        assert_eq!(serve.get("app", "0xaaa").unwrap().checked_at, 2000);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_verifier_fault_is_never_fresh() {
        let mut s = Store::default();
        s.put(Entry::failed(
            "app", "0xaaa", "http://node:50051", 100, 1000,
            "AttestationEvaluate: reference value lookup timed out".into(),
            true,
        ));
        let e = s.get("app", "0xaaa").unwrap();
        assert!(e.verifier_fault);
        assert_eq!(
            s.freshness("app", "0xaaa", 100, 3600, 1001),
            Freshness::VerifierFailed
        );
        assert!(s.freshness("app", "0xaaa", 100, 3600, 1001).needs_check());
        // A node's own failure stays cached, so readers do not re-trigger it.
        s.put(Entry::failed(
            "app", "0xbbb", "http://node:50051", 100, 1000,
            "App app not found".into(), false,
        ));
        assert_eq!(s.freshness("app", "0xbbb", 100, 3600, 1001), Freshness::Fresh);
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
