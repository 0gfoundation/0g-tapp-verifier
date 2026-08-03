//! Where reference values come from.
//!
//! They decide what "verified" means, so how they arrive matters as much as what
//! they say. Two sources, and the choice is explicit:
//!
//! * **a directory** — pinned, offline, whatever the operator put there. Nothing
//!   changes underneath a verdict.
//! * **a git ref** — tracked, so a set published upstream takes effect without an
//!   ops step. This is the default, because the alternative is what actually
//!   happened during development: a mount sat three revisions behind and every node
//!   running the newer image reported "image unknown", which reads as the node's
//!   fault and is ours.
//!
//! Tracking a branch hands "what counts as verified" to whoever can merge to it.
//! That is not smuggled in: every fetch records the tree it came from and the digest
//! of each file, and those are reported alongside any verdict, so a change is visible
//! and a verdict stays reproducible against a specific state of the repository.
//!
//! A failed fetch keeps the last good set. Dropping to zero would turn every node
//! "unknown" at once — our outage wearing the fleet's clothes.

use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::refvalues::{self, RefSet};

/// GitHub's unauthenticated API allows 60 requests an hour per address. A round
/// costs one call for the tree plus one per file whose digest changed, so a steady
/// state is one call — but a token is honoured if the environment has one.
const API: &str = "https://api.github.com";
const USER_AGENT: &str = "tappscan";

#[derive(Debug, Clone)]
pub enum Source {
    /// A directory the operator provides. Never fetched, never changes on its own.
    Dir(PathBuf),
    /// A path in a git repository, tracked at a ref.
    Git {
        repo: String,
        git_ref: String,
        path: String,
        token: Option<String>,
    },
}

impl Source {
    pub fn describe(&self) -> String {
        match self {
            Source::Dir(p) => p.display().to_string(),
            Source::Git { repo, git_ref, path, .. } => format!("{repo}@{git_ref}:{path}"),
        }
    }
}

/// What a set of reference values was, and where it came from, precisely enough to
/// reproduce a verdict later.
#[derive(Debug, Clone, Serialize)]
pub struct Provenance {
    pub source: String,
    /// Tree object the files were read from — identifies the exact content, so a
    /// verdict can be checked against the same state of the repository.
    pub tree: Option<String>,
    /// Unix seconds of the last successful read.
    pub fetched_at: Option<i64>,
    /// Set label → digest of the file it was parsed from.
    pub sets: BTreeMap<String, String>,
    /// Why the last attempt failed, if it did. The sets above are then the last good
    /// ones rather than nothing, and this says so.
    pub error: Option<String>,
}

impl Provenance {
    fn empty(source: &Source) -> Self {
        Self {
            source: source.describe(),
            tree: None,
            fetched_at: None,
            sets: BTreeMap::new(),
            error: None,
        }
    }
}

/// Holds the current reference values and how they were obtained.
pub struct Tracker {
    source: Source,
    sets: Vec<RefSet>,
    provenance: Provenance,
    /// Blob digest → file contents, so a round only downloads what changed.
    cache: BTreeMap<String, Vec<u8>>,
    http: reqwest::Client,
}

impl Tracker {
    pub fn new(source: Source) -> Self {
        Self {
            provenance: Provenance::empty(&source),
            source,
            sets: Vec::new(),
            cache: BTreeMap::new(),
            http: reqwest::Client::builder()
                .user_agent(USER_AGENT)
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
        }
    }

    pub fn sets(&self) -> &[RefSet] {
        &self.sets
    }

    pub fn provenance(&self) -> &Provenance {
        &self.provenance
    }

    /// Read the source. On failure the previous values are kept and the reason is
    /// recorded — never replaced by an empty set.
    pub async fn refresh(&mut self, now: i64) -> Result<usize> {
        let outcome = match self.source.clone() {
            Source::Dir(dir) => self.read_dir(&dir),
            Source::Git { repo, git_ref, path, token } => {
                self.read_git(&repo, &git_ref, &path, token.as_deref()).await
            }
        };
        match outcome {
            Ok((sets, tree, digests)) => {
                let count = sets.len();
                self.sets = sets;
                self.provenance = Provenance {
                    source: self.source.describe(),
                    tree,
                    fetched_at: Some(now),
                    sets: digests,
                    error: None,
                };
                Ok(count)
            }
            Err(e) => {
                self.provenance.error = Some(e.to_string());
                if self.sets.is_empty() {
                    Err(e)
                } else {
                    tracing::warn!(
                        "keeping the {} reference set(s) last read; this attempt failed: {e}",
                        self.sets.len()
                    );
                    Ok(self.sets.len())
                }
            }
        }
    }

    fn read_dir(&self, dir: &PathBuf) -> Result<(Vec<RefSet>, Option<String>, BTreeMap<String, String>)> {
        let sets = refvalues::load_dir(dir)?;
        let digests = sets
            .iter()
            .map(|s| {
                let digest = std::fs::read(dir.join(&s.label))
                    .map(|b| hex::encode(<sha2::Sha256 as sha2::Digest>::digest(b))[..12].to_string())
                    .unwrap_or_default();
                (s.label.clone(), digest)
            })
            .collect();
        Ok((sets, None, digests))
    }

    async fn get_json(&self, url: &str, token: Option<&str>) -> Result<serde_json::Value> {
        let mut req = self.http.get(url);
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        let resp = req.send().await.with_context(|| format!("GET {url}"))?;
        let status = resp.status();
        if !status.is_success() {
            // Rate limiting is the likely one and is worth naming, since the effect
            // is "reference values stopped updating" rather than an obvious failure.
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("GET {url} → {status}: {}", body.chars().take(200).collect::<String>()));
        }
        resp.json().await.with_context(|| format!("decode {url}"))
    }

    async fn read_git(
        &mut self,
        repo: &str,
        git_ref: &str,
        path: &str,
        token: Option<&str>,
    ) -> Result<(Vec<RefSet>, Option<String>, BTreeMap<String, String>)> {
        let tree_url = format!("{API}/repos/{repo}/git/trees/{git_ref}?recursive=1");
        let tree = self.get_json(&tree_url, token).await?;
        let tree_sha = tree.get("sha").and_then(|s| s.as_str()).map(str::to_string);
        if tree.get("truncated").and_then(|t| t.as_bool()) == Some(true) {
            // A truncated tree could silently omit a set, which would read as an
            // unrecognised image on every node running it.
            return Err(anyhow!("{repo}@{git_ref} tree came back truncated"));
        }
        let entries = tree
            .get("tree")
            .and_then(|t| t.as_array())
            .ok_or_else(|| anyhow!("unexpected tree response"))?;

        let prefix = format!("{}/", path.trim_end_matches('/'));
        let wanted: Vec<(String, String)> = entries
            .iter()
            .filter(|e| e.get("type").and_then(|t| t.as_str()) == Some("blob"))
            .filter_map(|e| {
                let p = e.get("path")?.as_str()?;
                let sha = e.get("sha")?.as_str()?;
                let rel = p.strip_prefix(&prefix)?;
                rel.ends_with(".json").then(|| (rel.to_string(), sha.to_string()))
            })
            .collect();
        if wanted.is_empty() {
            return Err(anyhow!("no .json under {path} in {repo}@{git_ref}"));
        }

        let mut fetched = 0usize;
        for (_, sha) in &wanted {
            if self.cache.contains_key(sha) {
                continue;
            }
            // By digest, not by path: the ref can move between calls, and a blob
            // digest names exactly the bytes the tree listed.
            let blob = self
                .get_json(&format!("{API}/repos/{repo}/git/blobs/{sha}"), token)
                .await?;
            let encoded: String = blob
                .get("content")
                .and_then(|c| c.as_str())
                .ok_or_else(|| anyhow!("blob {sha} has no content"))?
                .split_whitespace()
                .collect();
            let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
                .with_context(|| format!("decode blob {sha}"))?;
            self.cache.insert(sha.clone(), bytes);
            fetched += 1;
        }
        if fetched > 0 {
            tracing::info!("fetched {fetched} reference file(s) from {repo}@{git_ref}");
        }
        // Forget blobs no longer referenced, so a long-running instance does not hold
        // every set that ever existed.
        let live: std::collections::HashSet<&String> = wanted.iter().map(|(_, s)| s).collect();
        self.cache.retain(|sha, _| live.contains(sha));

        let mut sets = Vec::new();
        let mut digests = BTreeMap::new();
        for (label, sha) in &wanted {
            let Some(bytes) = self.cache.get(sha) else { continue };
            match refvalues::parse_set(label, bytes) {
                Some(set) => {
                    digests.insert(label.clone(), sha[..12].to_string());
                    sets.push(set);
                }
                // A README or an unrelated json in the tree is not an error.
                None => tracing::debug!("{label} carries no measurement values — skipped"),
            }
        }
        sets.sort_by(|a, b| a.label.cmp(&b.label));
        if sets.is_empty() {
            return Err(anyhow!("nothing under {path} parsed as reference values"));
        }
        Ok((sets, tree_sha, digests))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_set(dir: &std::path::Path, rel: &str, digest: &str) {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(
            &p,
            format!(r#"{{"measurement.uki.SHA-384":["{digest}"]}}"#),
        )
        .unwrap();
    }

    /// The property that matters most: a failed read must never replace good values
    /// with none. Zero sets would report every node as running an unknown image at
    /// once — our outage presented as the fleet's fault.
    #[tokio::test]
    async fn a_failed_refresh_keeps_the_last_good_values() {
        let dir = std::env::temp_dir().join(format!("tappscan-refsrc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        write_set(&dir, "gcp/uki/v0.3.0/dev.json", "aa");

        let mut t = Tracker::new(Source::Dir(dir.clone()));
        assert_eq!(t.refresh(1000).await.unwrap(), 1);
        assert!(t.provenance().error.is_none());
        assert_eq!(t.provenance().fetched_at, Some(1000));

        // The source goes away.
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(t.refresh(2000).await.unwrap(), 1, "the good set must survive");
        assert!(t.provenance().error.is_some(), "and the failure must be said");
        assert_eq!(
            t.provenance().fetched_at,
            Some(1000),
            "the timestamp must still describe when the values were actually read"
        );
        assert_eq!(t.sets().len(), 1);
    }

    /// With nothing to fall back on, a failure is an error rather than a silent
    /// start with no values.
    #[tokio::test]
    async fn a_first_refresh_that_fails_is_an_error() {
        let missing = std::env::temp_dir().join("tappscan-does-not-exist-at-all");
        let mut t = Tracker::new(Source::Dir(missing));
        assert!(t.refresh(1000).await.is_err());
        assert!(t.sets().is_empty());
    }

    #[tokio::test]
    async fn a_directory_source_reports_the_files_it_read() {
        let dir = std::env::temp_dir().join(format!("tappscan-refsrc2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        write_set(&dir, "gcp/uki/v0.3.0/dev.json", "aa");
        write_set(&dir, "ali/uki/v0.3.0/dev.json", "bb");
        // Not reference values; must be skipped rather than break the read.
        std::fs::write(dir.join("README.md"), "notes").unwrap();

        let mut t = Tracker::new(Source::Dir(dir.clone()));
        assert_eq!(t.refresh(1).await.unwrap(), 2);
        let p = t.provenance();
        assert_eq!(p.sets.len(), 2);
        assert!(p.sets.contains_key("gcp/uki/v0.3.0/dev.json"));
        assert!(p.tree.is_none(), "a directory has no tree to name");
        assert!(p.source.contains("tappscan-refsrc2"));

        std::fs::remove_dir_all(&dir).ok();
    }
}
