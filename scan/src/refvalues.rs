//! Published reference values — the digests an audited 0g-tapp CVM image is
//! expected to measure — and matching a node's measurements against them.
//!
//! Why matching happens HERE and not in an AS policy: the AS is asked to
//! evaluate with a loose policy, so it does only what nothing else can (verify
//! the quote's signature chain to Intel, report TCB status, and replay the event
//! log against the signed RTMRs). The boot-chain comparison is then a pure
//! function of the SIGNED token plus these public files, so anyone can recompute
//! this verdict instead of trusting that some policy on our AS returned 3. It
//! also removes the need to register a policy per image × cloud × environment,
//! and lets us report WHICH component differs rather than a bare pass/fail.
//!
//! The selection rules below must mirror `../tdx-boot-chain/policy.rego`. They
//! are the security check, not a routing hint — keep them in step.

use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Component name used in `measurement.<component>.SHA-384` keys.
pub type Component = String;

/// Digests measured by a node, keyed by component.
#[derive(Debug, Default, Clone, Serialize)]
pub struct Measured(pub BTreeMap<Component, BTreeSet<String>>);

/// policy.rego matches `ref_uki` against the digest of ANY boot-services
/// application rather than pinning a device-path spelling, so UKI digests are
/// collected under this pseudo-component.
pub const ANY_BSA: &str = "_any_bsa";

impl Measured {
    pub fn add(&mut self, component: &str, digest: &str) {
        self.0
            .entry(component.to_string())
            .or_default()
            .insert(digest.to_string());
    }

    pub fn get(&self, component: &str) -> Option<&BTreeSet<String>> {
        self.0.get(component)
    }

    /// grub images measure shim+grub; UKI images fuse everything into one EFI.
    pub fn boot_format(&self) -> &'static str {
        if self.0.contains_key("grub") {
            "grub"
        } else {
            "uki"
        }
    }
}

/// One published reference-value file.
#[derive(Debug, Clone, Serialize)]
pub struct RefSet {
    /// Path relative to the reference-value root, e.g. `gcp/uki/v0.3.0/dev.json`.
    /// The path IS the image label (cloud / boot format / version / environment).
    pub label: String,
    /// component → allowed digests. Multi-value entries are OR-matched, which is
    /// how several accepted `kernel_cmdline` spellings coexist.
    pub values: BTreeMap<Component, Vec<String>>,
}

/// Map a reference-value JSON key to the component it constrains.
fn key_to_component(key: &str) -> Option<Component> {
    let rest = key.strip_prefix("measurement.")?.strip_suffix(".SHA-384")?;
    Some(match rest {
        // A UKI reference digest is compared against any boot-services app.
        "uki" => ANY_BSA.to_string(),
        other => other.to_string(),
    })
}

/// What was loaded, so a mismatch can be told apart from a stale mount.
///
/// Reference values arrive as a mounted checkout. When a new image revision ships
/// and the mount has not been pulled, every node running it reports "image unknown"
/// — our staleness wearing the node's clothes. Publishing what is loaded, and how
/// old the newest file is, makes that diagnosable instead of misleading.
#[derive(Debug, Clone, Serialize)]
pub struct Provenance {
    pub dir: String,
    pub sets: Vec<String>,
    /// Unix seconds of the most recently modified reference file.
    pub newest_file: Option<i64>,
}

pub fn provenance(dir: &Path, sets: &[RefSet]) -> Provenance {
    let newest = sets
        .iter()
        .filter_map(|s| std::fs::metadata(dir.join(&s.label)).ok())
        .filter_map(|m| m.modified().ok())
        .filter_map(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .max();
    Provenance {
        dir: dir.display().to_string(),
        sets: sets.iter().map(|s| s.label.clone()).collect(),
        newest_file: newest,
    }
}

/// Load every `*.json` under `dir` (recursively) as a reference set.
///
/// Recursive and shape-agnostic on purpose: a published set is identified by its
/// path (`<cloud>/<boot format>/<version>[-r<rev>]/<env>.json`), and new shapes —
/// an image revision suffix, a per-owner subdirectory — are picked up without a
/// code change. That is the payoff of comparing digests here rather than naming an
/// AS policy: a new revision costs verifiers nothing, where a policy id would have
/// to be learned by every one of them.
pub fn load_dir(dir: &Path) -> Result<Vec<RefSet>> {
    let mut sets = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(path) = stack.pop() {
        let entries = std::fs::read_dir(&path)
            .with_context(|| format!("read reference-value dir {}", path.display()))?;
        for entry in entries {
            let entry = entry?;
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            if p.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let raw = std::fs::read(&p).with_context(|| format!("read {}", p.display()))?;
            let parsed: BTreeMap<String, Vec<String>> = match serde_json::from_slice(&raw) {
                Ok(v) => v,
                Err(e) => {
                    // A README or an unrelated json in the tree is not an error.
                    tracing::debug!("skipping {} ({e})", p.display());
                    continue;
                }
            };
            let values: BTreeMap<Component, Vec<String>> = parsed
                .into_iter()
                .filter_map(|(k, v)| {
                    let v: Vec<String> = v.into_iter().filter(|s| !s.is_empty()).collect();
                    (!v.is_empty()).then(|| key_to_component(&k).map(|c| (c, v)))?
                })
                .collect();
            if values.is_empty() {
                continue;
            }
            sets.push(RefSet {
                label: p
                    .strip_prefix(dir)
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .into_owned(),
                values,
            });
        }
    }
    sets.sort_by(|a, b| a.label.cmp(&b.label));
    Ok(sets)
}

/// How a node's measurements compare against one reference set.
#[derive(Debug, Clone, Serialize)]
pub struct SetMatch {
    pub label: String,
    /// (component, matched) in reference-set order.
    pub components: Vec<(Component, bool)>,
    /// True only when EVERY component the set constrains matched. Partial hits
    /// are the interesting diagnostic: "this image except its initrd".
    pub matched: bool,
}

impl SetMatch {
    pub fn hits(&self) -> usize {
        self.components.iter().filter(|(_, ok)| *ok).count()
    }
}

/// Compare measurements against every reference set, best match first.
pub fn match_sets(measured: &Measured, sets: &[RefSet]) -> Vec<SetMatch> {
    let mut out: Vec<SetMatch> = sets
        .iter()
        .map(|set| {
            let components: Vec<(Component, bool)> = set
                .values
                .iter()
                .map(|(component, allowed)| {
                    let hit = measured
                        .get(component)
                        .map(|m| allowed.iter().any(|a| m.contains(a)))
                        .unwrap_or(false);
                    (component.clone(), hit)
                })
                .collect();
            let matched = !components.is_empty() && components.iter().all(|(_, ok)| *ok);
            SetMatch {
                label: set.label.clone(),
                components,
                matched,
            }
        })
        .collect();
    // Full matches first, then by how many components hit.
    out.sort_by(|a, b| {
        b.matched
            .cmp(&a.matched)
            .then(b.hits().cmp(&a.hits()))
            .then(a.label.cmp(&b.label))
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(label: &str, pairs: &[(&str, &[&str])]) -> RefSet {
        RefSet {
            label: label.to_string(),
            values: pairs
                .iter()
                .map(|(c, v)| (c.to_string(), v.iter().map(|s| s.to_string()).collect()))
                .collect(),
        }
    }

    #[test]
    fn uki_key_maps_to_any_boot_services_app() {
        assert_eq!(
            key_to_component("measurement.uki.SHA-384").as_deref(),
            Some(ANY_BSA)
        );
        assert_eq!(
            key_to_component("measurement.kernel.SHA-384").as_deref(),
            Some("kernel")
        );
        assert_eq!(key_to_component("something.else"), None);
    }

    #[test]
    fn full_match_wins_over_partial() {
        let mut m = Measured::default();
        m.add("shim", "s1");
        m.add("grub", "g1");
        m.add("kernel", "k1");

        let sets = vec![
            set("partial.json", &[("shim", &["s1"]), ("kernel", &["nope"])]),
            set("full.json", &[("shim", &["s1"]), ("grub", &["g1"])]),
        ];
        let r = match_sets(&m, &sets);
        assert_eq!(r[0].label, "full.json");
        assert!(r[0].matched);
        assert!(!r[1].matched);
        assert_eq!(r[1].hits(), 1);
    }

    #[test]
    fn multi_value_entries_or_match() {
        let mut m = Measured::default();
        m.add("kernel_cmdline", "second");
        let sets = vec![set(
            "s.json",
            &[("kernel_cmdline", &["first", "second"])],
        )];
        assert!(match_sets(&m, &sets)[0].matched);
    }

    #[test]
    fn uki_digest_matches_any_bsa_measurement() {
        let mut m = Measured::default();
        m.add(ANY_BSA, "u1");
        m.add(ANY_BSA, "u2");
        let sets = vec![set("uki.json", &[(ANY_BSA, &["u2"])])];
        assert!(match_sets(&m, &sets)[0].matched);
    }

    #[test]
    fn boot_format_is_structural() {
        let mut grub = Measured::default();
        grub.add("shim", "s");
        grub.add("grub", "g");
        assert_eq!(grub.boot_format(), "grub");

        let mut uki = Measured::default();
        uki.add(ANY_BSA, "u");
        assert_eq!(uki.boot_format(), "uki");
    }

    #[test]
    fn a_set_with_no_recognised_keys_never_matches() {
        let m = Measured::default();
        let sets = vec![RefSet {
            label: "empty.json".into(),
            values: BTreeMap::new(),
        }];
        assert!(!match_sets(&m, &sets)[0].matched);
    }
}
