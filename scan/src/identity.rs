//! Typed identities committed to by report_data. These checks authenticate a
//! tapp declaration, not a ZK proof of the secret-to-public-key relation.

use std::collections::BTreeSet;

use anyhow::{anyhow, bail, ensure, Result};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::EncodePublicKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::attest::RuntimeEvent;

pub const COMMITMENT_SCHEME: &str = "poseidon-bn254-4-v1";
pub const SIGNER_MATERIAL: &str = "70726f7669646572";
pub const TLS_MATERIAL: &str = "746c73";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KeyCommitment {
    pub commitment: String,
    pub material: String,
    pub scheme: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub algorithm: String,
    pub derivation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_ref: Option<KeyCommitment>,
    pub key_source: String,
    pub public_key: String,
    pub public_key_encoding: String,
    pub role: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Identities {
    #[serde(default)]
    pub identities: Vec<Identity>,
    #[serde(default)]
    pub key_commitments: Vec<KeyCommitment>,
    #[serde(default)]
    pub app_signer: Option<String>,
    #[serde(default)]
    pub identities_error: Option<String>,
    #[serde(default)]
    pub identities_unchecked: usize,
}

/// Strictly canonical encodings avoid interpreting the same metadata two ways.
fn canonical_hex(value: &str, bytes: usize) -> Result<Vec<u8>> {
    ensure!(value.starts_with("0x"), "hex value needs 0x prefix");
    let raw = &value[2..];
    ensure!(raw.len() == bytes * 2, "wrong hex length");
    let decoded = hex::decode(raw)?;
    ensure!(
        hex::encode(&decoded) == raw,
        "hex must be lowercase canonical"
    );
    Ok(decoded)
}

fn check_commitment(key: &KeyCommitment) -> Result<()> {
    ensure!(
        key.scheme == COMMITMENT_SCHEME,
        "unsupported commitment scheme"
    );
    let c = canonical_hex(&key.commitment, 32)?;
    let modulus = hex::decode("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001")?;
    ensure!(
        c < modulus,
        "commitment is not a canonical BN254 field element"
    );
    ensure!(key.material.len() <= 512, "material exceeds KMS limit");
    let material = hex::decode(&key.material)?;
    ensure!(
        hex::encode(material) == key.material,
        "material must be lowercase hex without prefix"
    );
    Ok(())
}

pub fn secp256k1_address(public_key: &str) -> Result<String> {
    let bytes = canonical_hex(public_key, 33)?;
    ensure!(
        matches!(bytes[0], 2 | 3),
        "public key is not SEC1 compressed"
    );
    let public = k256::PublicKey::from_sec1_bytes(&bytes)?;
    ensure!(
        public.to_encoded_point(true).as_bytes() == bytes,
        "noncanonical public key"
    );
    let uncompressed = public.to_encoded_point(false);
    let hash = ethers::utils::keccak256(&uncompressed.as_bytes()[1..]);
    Ok(format!("0x{}", hex::encode(&hash[12..])))
}

pub fn tls_spki_sha256(public_key: &str) -> Result<String> {
    let bytes = canonical_hex(public_key, 33)?;
    ensure!(
        matches!(bytes[0], 2 | 3),
        "public key is not SEC1 compressed"
    );
    let public = p256::PublicKey::from_sec1_bytes(&bytes)?;
    ensure!(
        public.to_encoded_point(true).as_bytes() == bytes,
        "noncanonical public key"
    );
    let spki = public.to_public_key_der()?;
    Ok(format!(
        "0x{}",
        hex::encode(Sha256::digest(spki.as_bytes()))
    ))
}

/// Called only AFTER sha512(raw runtime_data) has matched the verified quote.
/// A malformed new schema never falls back to a synthesized app identity.
pub fn authenticate(
    runtime: &Value,
    app_id: &str,
    signer: Option<&str>,
    legacy_tls: Option<&str>,
    events: &[RuntimeEvent],
    fresh: Option<bool>,
) -> Identities {
    if runtime.get("identities").is_none() && runtime.get("key_commitments").is_none() {
        return Identities::default();
    }
    match authenticate_inner(runtime, app_id, signer, legacy_tls, events, fresh) {
        Ok(v) => v,
        Err(e) => Identities {
            identities_error: Some(e.to_string()),
            ..Default::default()
        },
    }
}

fn authenticate_inner(
    runtime: &Value,
    app_id: &str,
    signer: Option<&str>,
    legacy_tls: Option<&str>,
    events: &[RuntimeEvent],
    fresh: Option<bool>,
) -> Result<Identities> {
    ensure!(
        runtime.get("app_id").and_then(Value::as_str) == Some(app_id),
        "identity app_id does not match requested app"
    );
    ensure!(
        fresh == Some(true),
        "typed identities require a matching quote challenge"
    );
    ensure!(
        events.iter().all(|e| e.digest_matches),
        "runtime event log did not replay"
    );
    let identities: Vec<Identity> = serde_json::from_value(
        runtime
            .get("identities")
            .cloned()
            .ok_or_else(|| anyhow!("identities missing"))?,
    )?;
    ensure!(
        !identities.is_empty() && identities.len() <= 3,
        "invalid number of identities"
    );
    let keys: Vec<KeyCommitment> = serde_json::from_value(
        runtime
            .get("key_commitments")
            .cloned()
            .ok_or_else(|| anyhow!("key_commitments missing"))?,
    )?;
    let mut materials = BTreeSet::new();
    for key in &keys {
        check_commitment(key)?;
        ensure!(
            materials.insert(&key.material),
            "duplicate commitment material"
        );
        ensure!(
            events
                .iter()
                .any(|event| commitment_in_event(event, app_id, key)),
            "commitment lacks a measured event for this app and material"
        );
    }
    let mut roles = BTreeSet::new();
    let mut app_signer = None;
    let local_derivation = if app_id.is_empty() {
        "node-native-v1"
    } else {
        "tapp-app-signer-v1"
    };
    for identity in &identities {
        ensure!(roles.insert(&identity.role), "duplicate identity role");
        ensure!(
            identity.public_key_encoding == "sec1-compressed",
            "unsupported public key encoding"
        );
        match identity.role.as_str() {
            "node_signer" => {
                ensure!(
                    identity.algorithm == "ecdsa-secp256k1",
                    "wrong node signer algorithm"
                );
                ensure!(
                    identity.key_source == "local"
                        && identity.derivation == local_derivation
                        && identity.key_ref.is_none(),
                    "invalid node signer provenance"
                );
                let address = secp256k1_address(&identity.public_key)?;
                ensure!(
                    signer.is_some_and(|s| s.eq_ignore_ascii_case(&address)),
                    "node public key does not match quote signer"
                );
            }
            "app_signer" => {
                ensure!(
                    identity.algorithm == "ecdsa-secp256k1",
                    "wrong app signer algorithm"
                );
                ensure!(
                    identity.key_source == "kms",
                    "app_signer requires KMS provenance"
                );
                app_signer = Some(secp256k1_address(&identity.public_key)?);
                check_source(
                    identity,
                    SIGNER_MATERIAL,
                    local_derivation,
                    &keys,
                    events,
                    app_id,
                )?;
            }
            "tls" => {
                ensure!(identity.algorithm == "ecdsa-p256", "wrong TLS algorithm");
                let hash = tls_spki_sha256(&identity.public_key)?;
                ensure!(
                    legacy_tls.is_some_and(|h| h.eq_ignore_ascii_case(&hash)),
                    "TLS public key does not match legacy SPKI hash"
                );
                check_source(
                    identity,
                    TLS_MATERIAL,
                    "tapp-tls-v1-sha256",
                    &keys,
                    events,
                    app_id,
                )?;
            }
            _ => bail!("unsupported identity role"),
        }
    }
    ensure!(
        roles.contains(&"node_signer".to_string()),
        "node_signer identity missing"
    );
    ensure!(
        legacy_tls.is_none() || roles.contains(&"tls".to_string()),
        "TLS identity missing"
    );
    let identities_unchecked = keys
        .iter()
        .filter(|key| !acquisition_attested(events, app_id, key))
        .count();
    Ok(Identities {
        identities,
        key_commitments: keys,
        app_signer,
        identities_error: None,
        identities_unchecked,
    })
}

/// Whether the measured acquisition of `key` went over an attested KMS connection.
/// Without that, the key is whatever answered at the node's `kms_url` — not
/// necessarily the 0g KMS, and possibly one its operator knows.
fn acquisition_attested(events: &[RuntimeEvent], app_id: &str, key: &KeyCommitment) -> bool {
    events.iter().any(|event| {
        commitment_in_event(event, app_id, key)
            && event.payload.get("kms_attested").and_then(Value::as_bool) == Some(true)
    })
}

/// Whether the app signer's OWN key was acquired over an attested KMS connection.
/// `identities_unchecked` counts every commitment, TLS and generic secrets
/// included, so it cannot single the app signer out; this does. Recomputed on
/// read from the stored trace, like the rest of a verdict.
pub fn app_signer_checked(identity: &Identities, events: &[RuntimeEvent], app_id: &str) -> bool {
    identity.app_signer.is_some()
        && identity
            .identities
            .iter()
            .find(|i| i.role == "app_signer")
            .and_then(|i| i.key_ref.as_ref())
            .is_some_and(|key| acquisition_attested(events, app_id, key))
}

fn commitment_in_event(event: &RuntimeEvent, app_id: &str, key: &KeyCommitment) -> bool {
    event.digest_matches
        && event.operation == "get_secret_resource"
        && event.app_id() == Some(app_id)
        && event.result() == Some("success")
        && event.payload.get("material").and_then(Value::as_str) == Some(key.material.as_str())
        && event
            .payload
            .get("key_commitment")
            .and_then(|v| serde_json::from_value::<KeyCommitment>(v.clone()).ok())
            .as_ref()
            == Some(key)
}

fn check_source(
    identity: &Identity,
    material: &str,
    local_derivation: &str,
    keys: &[KeyCommitment],
    events: &[RuntimeEvent],
    app_id: &str,
) -> Result<()> {
    match identity.key_source.as_str() {
        "local" => ensure!(
            identity.key_ref.is_none() && identity.derivation == local_derivation,
            "invalid local key provenance"
        ),
        "kms" => {
            ensure!(
                identity.derivation == "raw-scalar-v1",
                "unsupported KMS derivation"
            );
            let key = identity
                .key_ref
                .as_ref()
                .ok_or_else(|| anyhow!("KMS identity has no key_ref"))?;
            check_commitment(key)?;
            ensure!(
                key.material == material && keys.contains(key),
                "KMS key_ref is not committed for this role"
            );
            ensure!(
                events.iter().any(|event| {
                    commitment_in_event(event, app_id, key)
                        && event
                            .payload
                            .get("identity")
                            .and_then(|v| serde_json::from_value::<Identity>(v.clone()).ok())
                            .as_ref()
                            == Some(identity)
                }),
                "KMS identity lacks its matching measured declaration"
            );
        }
        _ => bail!("unsupported key source"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn secp(n: u8) -> String {
        let public = k256::SecretKey::from_slice(&[n; 32]).unwrap().public_key();
        format!(
            "0x{}",
            hex::encode(public.to_encoded_point(true).as_bytes())
        )
    }

    fn p256(n: u8) -> String {
        let public = p256::SecretKey::from_slice(&[n; 32]).unwrap().public_key();
        format!(
            "0x{}",
            hex::encode(public.to_encoded_point(true).as_bytes())
        )
    }

    fn key(material: &str, n: u8) -> KeyCommitment {
        KeyCommitment {
            material: material.into(),
            scheme: COMMITMENT_SCHEME.into(),
            commitment: format!("0x{:064x}", n),
        }
    }

    fn fixture() -> (Value, Vec<RuntimeEvent>, String, String) {
        let node = Identity {
            role: "node_signer".into(),
            algorithm: "ecdsa-secp256k1".into(),
            public_key: secp(1),
            public_key_encoding: "sec1-compressed".into(),
            key_source: "local".into(),
            derivation: "tapp-app-signer-v1".into(),
            key_ref: None,
        };
        let app = Identity {
            role: "app_signer".into(),
            algorithm: "ecdsa-secp256k1".into(),
            public_key: secp(2),
            public_key_encoding: "sec1-compressed".into(),
            key_source: "kms".into(),
            derivation: "raw-scalar-v1".into(),
            key_ref: Some(key(SIGNER_MATERIAL, 1)),
        };
        let tls = Identity {
            role: "tls".into(),
            algorithm: "ecdsa-p256".into(),
            public_key: p256(3),
            public_key_encoding: "sec1-compressed".into(),
            key_source: "kms".into(),
            derivation: "raw-scalar-v1".into(),
            key_ref: Some(key(TLS_MATERIAL, 2)),
        };
        let events = [&app, &tls].iter().map(|identity| RuntimeEvent {
            operation: "get_secret_resource".into(),
            payload: json!({"app_id":"app", "material":identity.key_ref.as_ref().unwrap().material,
                "key_commitment":identity.key_ref,"identity":identity,"result":"success"}),
            digest: None, digest_matches: true,
        }).collect();
        let signer = secp256k1_address(&node.public_key).unwrap();
        let hash = tls_spki_sha256(&tls.public_key).unwrap();
        (
            json!({"app_id":"app","identities":[node,app,tls],
            "key_commitments":[key(SIGNER_MATERIAL,1),key(TLS_MATERIAL,2)]}),
            events,
            signer,
            hash,
        )
    }

    fn run(runtime: &Value, events: &[RuntimeEvent], signer: &str, tls: &str) -> Identities {
        authenticate(runtime, "app", Some(signer), Some(tls), events, Some(true))
    }

    #[test]
    fn authenticates_typed_identities_and_computes_addresses_and_spki() {
        let (runtime, events, signer, hash) = fixture();
        let out = run(&runtime, &events, &signer, &hash);
        assert!(out.identities_error.is_none(), "{:?}", out.identities_error);
        assert_eq!(out.identities.len(), 3);
        assert_eq!(out.app_signer, Some(secp256k1_address(&secp(2)).unwrap()));
        assert_eq!(out.key_commitments.len(), 2);
        // SPKI must use the uncompressed P-256 point and standard DER identifiers.
        let mut der = hex::decode("3059301306072a8648ce3d020106082a8648ce3d030107034200").unwrap();
        der.extend_from_slice(
            p256::SecretKey::from_slice(&[3; 32])
                .unwrap()
                .public_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        assert_eq!(hash, format!("0x{}", hex::encode(Sha256::digest(der))));
    }

    #[test]
    fn local_tls_has_no_kms_reference_but_still_matches_the_attested_spki() {
        let (mut runtime, mut events, signer, _) = fixture();
        let mut derive = Sha256::new();
        derive.update(b"tapp-tls-v1");
        derive.update([1; 32]);
        let local_public = p256::SecretKey::from_slice(&derive.finalize())
            .unwrap()
            .public_key();
        let local_public = format!(
            "0x{}",
            hex::encode(local_public.to_encoded_point(true).as_bytes())
        );
        runtime["identities"][2]["public_key"] = json!(local_public);
        runtime["identities"][2]["key_source"] = json!("local");
        runtime["identities"][2]["derivation"] = json!("tapp-tls-v1-sha256");
        runtime["identities"][2]
            .as_object_mut()
            .unwrap()
            .remove("key_ref");
        runtime["key_commitments"].as_array_mut().unwrap().pop();
        events.pop();
        let hash = tls_spki_sha256(&local_public).unwrap();
        let out = run(&runtime, &events, &signer, &hash);
        assert!(out.identities_error.is_none(), "{:?}", out.identities_error);
        assert_eq!(out.identities.len(), 3);
        assert_eq!(out.key_commitments.len(), 1);
    }

    #[test]
    fn consumes_the_tapp_poseidon_commitment_wire_known_answer() {
        // Generated by tapp's frozen Poseidon BN254 Circom-4 implementation for
        // app_id=sandbox, material=provider, secret=[0x01;32]. Scan authenticates
        // its declaration and bindings; it does not claim to recompute C from P.
        let app: Identity = serde_json::from_value(json!({
            "algorithm":"ecdsa-secp256k1", "derivation":"raw-scalar-v1",
            "key_ref":{"commitment":"0x0d2e61c0c36e0879b239181b05600f6e64fec76cc972c63198b0286533460ab3",
                "material":"70726f7669646572","scheme":"poseidon-bn254-4-v1"},
            "key_source":"kms",
            "public_key":"0x031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
            "public_key_encoding":"sec1-compressed", "role":"app_signer"
        })).unwrap();
        assert_eq!(app.public_key, secp(1));
        let node = Identity {
            role: "node_signer".into(),
            algorithm: "ecdsa-secp256k1".into(),
            public_key: secp(4),
            public_key_encoding: "sec1-compressed".into(),
            key_source: "local".into(),
            derivation: "tapp-app-signer-v1".into(),
            key_ref: None,
        };
        let signer = secp256k1_address(&node.public_key).unwrap();
        let event = RuntimeEvent {
            operation: "get_secret_resource".into(),
            digest: None,
            digest_matches: true,
            payload: json!({"app_id":"sandbox","material":SIGNER_MATERIAL,
                "key_commitment":app.key_ref,"identity":app,"result":"success"}),
        };
        let raw =
            json!({"app_id":"sandbox","identities":[node,app],"key_commitments":[app.key_ref]});
        let out = authenticate(&raw, "sandbox", Some(&signer), None, &[event], Some(true));
        assert!(out.identities_error.is_none(), "{:?}", out.identities_error);
        assert_eq!(
            out.app_signer.as_deref(),
            Some("0x1a642f0e3c3af545e7acbd38b07251b3990914f1")
        );
    }

    #[test]
    fn rejects_bad_encoding_curve_role_and_legacy_bindings() {
        let (runtime, events, signer, hash) = fixture();
        for (index, field, value) in [
            (0, "public_key", json!(format!("0x04{}", "00".repeat(64)))),
            (0, "public_key", json!(format!("0x02{}", "ff".repeat(32)))),
            (0, "algorithm", json!("ecdsa-p256")),
            (2, "algorithm", json!("ecdsa-secp256k1")),
            (2, "public_key_encoding", json!("spki-der")),
            (1, "key_source", json!("local")),
            (1, "role", json!("unrecognized")),
        ] {
            let mut bad = runtime.clone();
            bad["identities"][index][field] = value;
            let out = run(&bad, &events, &signer, &hash);
            assert!(out.identities_error.is_some(), "accepted {index}/{field}");
            assert!(out.identities.is_empty() && out.app_signer.is_none());
        }
        assert!(run(
            &runtime,
            &events,
            &secp256k1_address(&secp(4)).unwrap(),
            &hash
        )
        .identities_error
        .is_some());
        assert!(run(
            &runtime,
            &events,
            &signer,
            &format!("0x{}", "00".repeat(32))
        )
        .identities_error
        .is_some());
    }

    #[test]
    fn commitment_must_match_rd_and_replayed_event_same_app_and_material() {
        let (runtime, events, signer, hash) = fixture();
        let mut bad = runtime.clone();
        bad["identities"][1]["key_ref"]["commitment"] = json!(format!("0x{:064x}", 3));
        assert!(run(&bad, &events, &signer, &hash)
            .identities_error
            .is_some());
        for field in ["app_id", "material", "result"] {
            let mut bad_events = events.clone();
            bad_events[0].payload[field] = json!("other");
            assert!(run(&runtime, &bad_events, &signer, &hash)
                .identities_error
                .is_some());
        }
        let mut bad_events = events.clone();
        bad_events[0].digest_matches = false;
        assert!(run(&runtime, &bad_events, &signer, &hash)
            .identities_error
            .is_some());
        let mut bad_events = events.clone();
        bad_events[0].payload["identity"]["public_key"] = json!(secp(4));
        assert!(run(&runtime, &bad_events, &signer, &hash)
            .identities_error
            .is_some());
    }

    #[test]
    fn malformed_commitment_scope_freshness_and_conflicts_fail_closed() {
        let (runtime, events, signer, hash) = fixture();
        for value in [
            json!("0x01"),
            json!(format!("0x{}", "ff".repeat(32))),
            json!("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"),
        ] {
            let mut bad = runtime.clone();
            bad["key_commitments"][0]["commitment"] = value;
            assert!(run(&bad, &events, &signer, &hash)
                .identities_error
                .is_some());
        }
        let mut bad = runtime.clone();
        bad["app_id"] = json!("other");
        assert!(run(&bad, &events, &signer, &hash)
            .identities_error
            .is_some());
        let mut bad = runtime.clone();
        bad["identities"][1]["role"] = json!("node_signer");
        assert!(run(&bad, &events, &signer, &hash)
            .identities_error
            .is_some());
        for fresh in [None, Some(false)] {
            assert!(
                authenticate(&runtime, "app", Some(&signer), Some(&hash), &events, fresh)
                    .identities_error
                    .is_some()
            );
        }
    }

    #[test]
    fn legacy_and_public_extensions_do_not_create_app_identity() {
        let out = authenticate(
            &json!({"signer":"0x00","extensions":{"identities":[{}]}}),
            "app",
            None,
            None,
            &[],
            None,
        );
        assert!(
            out.identities.is_empty() && out.app_signer.is_none() && out.identities_error.is_none()
        );
        let (mut runtime, events, signer, hash) = fixture();
        runtime["extensions"] = json!({"proof":"not-a-proof","algorithm":"invented"});
        let out = run(&runtime, &events, &signer, &hash);
        assert!(out.identities_error.is_none());
        assert!(!serde_json::to_string(&out).unwrap().contains("not-a-proof"));
    }

    #[test]
    fn kms_provenance_counts_tls_and_signer_acquisitions_without_hiding_them() {
        let (runtime, mut events, signer, hash) = fixture();
        assert_eq!(
            run(&runtime, &events, &signer, &hash).identities_unchecked,
            2
        );
        for event in &mut events {
            event.payload["kms_attested"] = json!(true);
        }
        assert_eq!(
            run(&runtime, &events, &signer, &hash).identities_unchecked,
            0
        );
        events[1].payload["kms_attested"] = json!(false);
        let out = run(&runtime, &events, &signer, &hash);
        assert_eq!(out.identities_unchecked, 1);
        assert!(out.identities_error.is_none());
    }

    #[test]
    fn app_signer_checked_reads_the_app_signers_own_acquisition_only() {
        // events[0] acquires the app signer's key, events[1] the TLS key.
        let (runtime, mut events, signer, hash) = fixture();
        let out = run(&runtime, &events, &signer, &hash);
        assert!(!app_signer_checked(&out, &events, "app"), "nothing attested");
        // An attested TLS acquisition says nothing about the app signer's key.
        events[1].payload["kms_attested"] = json!(true);
        assert!(!app_signer_checked(&out, &events, "app"), "only TLS attested");
        events[0].payload["kms_attested"] = json!(true);
        assert!(app_signer_checked(&out, &events, "app"));
        // Bound to this app: the same acquisition under another app id does not count.
        assert!(!app_signer_checked(&out, &events, "other"));
        // No app signer, nothing to check.
        assert!(!app_signer_checked(&Identities::default(), &events, "app"));
    }
}
