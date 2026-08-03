//! API keys for the one privileged operation in this deployment: writing an
//! attestation policy.
//!
//! The Attestation Service has no authentication of its own, so exposing
//! `SetAttestationPolicy` exposes the ability to redefine what "verified" means —
//! and an EAR token records only which policy id was used, never a hash of it, so a
//! swap cannot be detected after the fact. Controlling who may write is therefore
//! the only real mitigation.
//!
//! Keys are **issued against an on-chain signature**: the holder of the registry's
//! `admin` address signs a challenge, and only then is a key minted. That keeps the
//! authority where it already lives rather than inventing a second one, and makes
//! every key traceable to the address that asked for it.
//!
//! Only a hash of each key is stored, so this file is not itself a list of usable
//! credentials. A key is shown exactly once, when it is issued.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

/// How long a freshly issued key lasts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ttl {
    Days30,
    Days90,
    Never,
}

impl Ttl {
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "30" | "30d" => Ok(Ttl::Days30),
            "90" | "90d" => Ok(Ttl::Days90),
            "never" | "0" => Ok(Ttl::Never),
            other => Err(anyhow!("expiry must be 30, 90 or never, not {other:?}")),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Ttl::Days30 => "30d",
            Ttl::Days90 => "90d",
            Ttl::Never => "never",
        }
    }

    fn expires_at(self, issued_at: i64) -> Option<i64> {
        match self {
            Ttl::Days30 => Some(issued_at + 30 * 86_400),
            Ttl::Days90 => Some(issued_at + 90 * 86_400),
            Ttl::Never => None,
        }
    }
}

/// One issued key. The secret itself is never here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    /// Public identifier, safe to log and to name in a revoke request.
    pub id: String,
    /// What it is for, supplied at issue time ("ci", "ops laptop", …).
    pub label: String,
    /// SHA-256 of the secret, hex. Storing the secret would make this file a
    /// credential dump; storing a hash makes it an audit record.
    hash: String,
    /// The admin address whose signature authorised this key.
    pub issued_by: String,
    pub issued_at: i64,
    /// `None` for a key that does not expire.
    pub expires_at: Option<i64>,
    pub revoked_at: Option<i64>,
    pub last_used_at: Option<i64>,
}

impl ApiKey {
    pub fn usable_at(&self, now: i64) -> bool {
        self.revoked_at.is_none() && self.expires_at.map(|e| now < e).unwrap_or(true)
    }

    /// Why a key was refused, for a log line — never returned to the caller, who
    /// gets a bare refusal either way.
    fn refusal(&self, now: i64) -> &'static str {
        if self.revoked_at.is_some() {
            "revoked"
        } else if self.expires_at.map(|e| now >= e).unwrap_or(false) {
            "expired"
        } else {
            "usable"
        }
    }
}

fn hash_of(secret: &str) -> String {
    hex::encode(Sha256::digest(secret.as_bytes()))
}

/// Compare digests without leaking where they diverge.
fn same_digest(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct KeyStore {
    #[serde(default)]
    keys: Vec<ApiKey>,
}

impl KeyStore {
    pub fn load(path: &Path) -> Self {
        match std::fs::read(path).map(|raw| serde_json::from_slice::<KeyStore>(&raw)) {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                // Refusing to start would take the whole service down over a file
                // that only gates one operation; starting with no keys fails closed.
                tracing::error!("key file unreadable ({e}) — starting with no keys");
                KeyStore::default()
            }
            Err(_) => KeyStore::default(),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).ok();
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Mint a key. Returns the secret, which is the only time it exists in one
    /// place, and the record that will be kept.
    pub fn mint(
        &mut self,
        label: &str,
        ttl: Ttl,
        issued_by: &str,
        now: i64,
        secret: String,
    ) -> ApiKey {
        let record = ApiKey {
            id: format!("k{}", &hash_of(&secret)[..10]),
            label: label.to_string(),
            hash: hash_of(&secret),
            issued_by: issued_by.to_lowercase(),
            issued_at: now,
            expires_at: ttl.expires_at(now),
            revoked_at: None,
            last_used_at: None,
        };
        self.keys.push(record.clone());
        record
    }

    /// Look a secret up and mark it used. `None` means refused — the caller is told
    /// nothing more than that.
    pub fn accept(&mut self, secret: &str, now: i64) -> Option<&ApiKey> {
        let digest = hash_of(secret);
        let found = self.keys.iter().position(|k| same_digest(&k.hash, &digest))?;
        let key = &mut self.keys[found];
        if !key.usable_at(now) {
            tracing::warn!("key {} refused: {}", key.id, key.refusal(now));
            return None;
        }
        key.last_used_at = Some(now);
        Some(&self.keys[found])
    }

    pub fn revoke(&mut self, id: &str, now: i64) -> Result<()> {
        let key = self
            .keys
            .iter_mut()
            .find(|k| k.id == id)
            .ok_or_else(|| anyhow!("no key {id}"))?;
        if key.revoked_at.is_none() {
            key.revoked_at = Some(now);
        }
        Ok(())
    }

    /// Every key's metadata. Never includes a hash — that is ours, not a reader's.
    pub fn list(&self) -> Vec<serde_json::Value> {
        self.keys
            .iter()
            .map(|k| {
                serde_json::json!({
                    "id": k.id,
                    "label": k.label,
                    "issued_by": k.issued_by,
                    "issued_at": k.issued_at,
                    "expires_at": k.expires_at,
                    "revoked_at": k.revoked_at,
                    "last_used_at": k.last_used_at,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 86_400;

    fn store_with(ttl: Ttl, now: i64) -> (KeyStore, String) {
        let mut s = KeyStore::default();
        s.mint("ci", ttl, "0xADMIN", now, "secret-abc".into());
        (s, "secret-abc".to_string())
    }

    #[test]
    fn a_key_is_accepted_until_it_expires() {
        let (mut s, secret) = store_with(Ttl::Days30, 1000);
        assert!(s.accept(&secret, 1000 + 29 * DAY).is_some());
        assert!(s.accept(&secret, 1000 + 31 * DAY).is_none());
    }

    #[test]
    fn never_expiring_means_never() {
        let (mut s, secret) = store_with(Ttl::Never, 1000);
        assert!(s.accept(&secret, 1000 + 10_000 * DAY).is_some());
    }

    #[test]
    fn revocation_takes_effect_immediately() {
        let (mut s, secret) = store_with(Ttl::Never, 1000);
        let id = s.list()[0]["id"].as_str().unwrap().to_string();
        assert!(s.accept(&secret, 1001).is_some());
        s.revoke(&id, 1002).unwrap();
        assert!(s.accept(&secret, 1003).is_none());
    }

    #[test]
    fn a_wrong_secret_is_refused_and_use_is_recorded() {
        let (mut s, secret) = store_with(Ttl::Days90, 1000);
        assert!(s.accept("secret-abd", 1001).is_none());
        assert!(s.accept(&secret, 1002).is_some());
        assert_eq!(s.list()[0]["last_used_at"].as_i64(), Some(1002));
    }

    /// The file is an audit record, not a credential store: nothing that can be
    /// replayed as a key may appear in it, nor in what a reader is shown.
    #[test]
    fn neither_the_file_nor_the_listing_carries_a_usable_secret() {
        let (s, secret) = store_with(Ttl::Days30, 1000);
        let file = serde_json::to_string(&s).unwrap();
        assert!(!file.contains(&secret), "the secret must not be persisted");
        let listing = serde_json::to_string(&s.list()).unwrap();
        assert!(!listing.contains(&secret));
        assert!(!listing.contains("hash"), "a hash is not a reader's business");
    }

    #[test]
    fn expiry_choices_are_the_three_offered() {
        assert_eq!(Ttl::parse("30").unwrap(), Ttl::Days30);
        assert_eq!(Ttl::parse("90d").unwrap(), Ttl::Days90);
        assert_eq!(Ttl::parse("never").unwrap(), Ttl::Never);
        assert!(Ttl::parse("45").is_err());
    }

    #[test]
    fn round_trips_through_disk() {
        let dir = std::env::temp_dir().join(format!("tappscan-keys-{}", std::process::id()));
        let path = dir.join("keys.json");
        let (s, secret) = store_with(Ttl::Days90, 1000);
        s.save(&path).unwrap();
        let mut back = KeyStore::load(&path);
        assert!(back.accept(&secret, 1001).is_some());
        std::fs::remove_dir_all(&dir).ok();
    }
}
