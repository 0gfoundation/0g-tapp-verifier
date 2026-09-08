//! Attestation of one node: pull its evidence, have the Attestation Service
//! verify the quote, then read the boot chain and the runtime event log out of
//! the signed token.
//!
//! The AS is called with an EMPTY policy list on purpose (see
//! [`crate::refvalues`]): it does the parts only it can do — verify the quote's
//! signature chain, report platform TCB status, and replay each event-log entry
//! against the signed RTMRs — while the boot-chain comparison happens locally
//! against published reference values.
//!
//! Everything read below comes out of `ear.veraison.annotated-evidence`, i.e. out
//! of the AS's signed token, not from a second unauthenticated channel.

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Digest;

use crate::refvalues::{self, Measured, RefSet, SetMatch, ANY_BSA};

pub mod tapp {
    tonic::include_proto!("tapp_service");
}
pub mod as_proto {
    tonic::include_proto!("attestation");
}

use as_proto::attestation_service_client::AttestationServiceClient;
use as_proto::{AttestationRequest, IndividualAttestationRequest};
use tapp::{tapp_service_client::TappServiceClient, GetEvidenceRequest};

const B64URL: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// The event log can carry thousands of entries (one per measured operation, and
/// RTMR3 only ever grows), so an evidence blob of a few MB turns into a token of
/// several MB. gRPC's 4 MB default would reject those.
const MAX_MSG_BYTES: usize = 64 * 1024 * 1024;

/// Domain every measured tapp runtime operation is tagged with.
const TAPP_DOMAIN: &str = "tapp.0g.com";

// ─── Runtime event log ───────────────────────────────────────────────────────

/// One measured tapp operation (start_app, stop_app, get_app_secret_key, …) as
/// the AS parsed it out of the event log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeEvent {
    pub operation: String,
    /// The measured JSON payload, verbatim.
    pub payload: Value,
    /// SHA-384 extended into the RTMR for this event.
    pub digest: Option<String>,
    /// The AS's own replay result: does the event body hash to the digest that
    /// was extended? False here would mean the log does not reconstruct the
    /// signed RTMR value.
    pub digest_matches: bool,
}

impl RuntimeEvent {
    pub fn app_id(&self) -> Option<&str> {
        self.payload.get("app_id")?.as_str()
    }
    pub fn result(&self) -> Option<&str> {
        self.payload.get("result")?.as_str()
    }
    pub fn timestamp(&self) -> Option<i64> {
        self.payload.get("timestamp")?.as_i64()
    }
}

/// Extract the measured tapp operations, in event-log order.
fn runtime_events(logs: &[Value]) -> Vec<RuntimeEvent> {
    logs.iter()
        .filter_map(|e| {
            let data = e.pointer("/details/data")?;
            if data.get("domain")?.as_str()? != TAPP_DOMAIN {
                return None;
            }
            Some(RuntimeEvent {
                operation: data.get("operation")?.as_str()?.to_string(),
                payload: data.get("content").cloned().unwrap_or(Value::Null),
                digest: sha384_of(e).map(str::to_string),
                // Absent means the AS did not flag a mismatch.
                digest_matches: e
                    .get("digest_matches_event")
                    .and_then(Value::as_bool)
                    .unwrap_or(true),
            })
        })
        .collect()
}

fn sha384_of(event: &Value) -> Option<&str> {
    event
        .get("digests")?
        .as_array()?
        .iter()
        .find(|d| d.get("alg").and_then(Value::as_str) == Some("SHA-384"))?
        .get("digest")?
        .as_str()
}

// ─── Boot chain ──────────────────────────────────────────────────────────────

/// Pull the boot-chain digests out of the parsed event log.
///
/// Selection rules mirror `../tdx-boot-chain/policy.rego`:
///
/// | component        | event                            | matched on                    |
/// |------------------|----------------------------------|-------------------------------|
/// | `shim`           | EV_EFI_BOOT_SERVICES_APPLICATION | device path ~ `shimx64.efi`   |
/// | `grub`           | EV_EFI_BOOT_SERVICES_APPLICATION | device path ~ `grubx64.efi`   |
/// | `kernel`         | EV_IPL                           | string starts `/vmlinuz`      |
/// | `initrd`         | EV_IPL                           | string starts `/initrd`       |
/// | `kernel_cmdline` | EV_IPL                           | string starts `kernel_cmdline:` |
/// | (UKI)            | EV_EFI_BOOT_SERVICES_APPLICATION | any — collected under `ANY_BSA` |
fn boot_digests(logs: &[Value]) -> Measured {
    let mut measured = Measured::default();
    for e in logs {
        let Some(digest) = sha384_of(e) else { continue };
        match e.get("type_name").and_then(Value::as_str) {
            Some("EV_EFI_BOOT_SERVICES_APPLICATION") => {
                // A UKI is loaded as a boot-services application too, so every
                // such digest is a UKI candidate.
                measured.add(ANY_BSA, digest);
                let paths = e
                    .pointer("/details/device_paths")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(Value::as_str)
                            .collect::<Vec<_>>()
                            .join(" ")
                            .to_ascii_lowercase()
                    })
                    .unwrap_or_default();
                if paths.contains("shimx64.efi") {
                    measured.add("shim", digest);
                } else if paths.contains("grubx64.efi") {
                    measured.add("grub", digest);
                }
            }
            Some("EV_IPL") => {
                let s = e
                    .pointer("/details/string")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if s.starts_with("kernel_cmdline:") {
                    measured.add("kernel_cmdline", digest);
                } else if s.starts_with("/vmlinuz") {
                    measured.add("kernel", digest);
                } else if s.starts_with("/initrd") {
                    measured.add("initrd", digest);
                }
            }
            _ => {}
        }
    }
    measured
}

// ─── Quote ───────────────────────────────────────────────────────────────────

/// What the quote's `report_data` committed to. The on-chain node signer must
/// appear here — that binding is what ties a piece of hardware to an app's
/// on-chain registration.
struct ReportData {
    signer: Option<String>,
    /// sha256 of the app's TLS public key (hex), when the node attested one.
    tls_public_key: Option<String>,
    note: String,
}

/// Read the identity out of the quote, in whichever era's format applies.
///
/// Which era is decided by PRESENCE — a `runtime_data` field beside the quote in
/// the evidence — never guessed from the bytes:
///
/// - absent (tapp-server ≤0.3.x): `report_data` is the bare 20-byte signer
///   address, left-aligned and zero-padded.
/// - present (≥0.4.0): `report_data` is `sha512(runtime_data)`. Recompute over
///   the bytes AS RECEIVED — never re-serialise: both sides hash the transmitted
///   bytes, which is what removes any need for a canonical JSON form. Only a
///   match makes anything inside believable, the signer included — a structure
///   swapped for one naming a different address stops hashing correctly, and
///   reading the signer out of it anyway would defeat the point.
///
/// The wrinkle: `report_data` comes out of the AS token (whose quote signature
/// the AS verified), while `runtime_data` rides in the raw evidence this service
/// fetched from the node. The comparison spans both, which is why the raw
/// evidence is a parameter here.
fn read_report_data(tdx: &Value, evidence: &[u8]) -> ReportData {
    let mut out = ReportData {
        signer: None,
        tls_public_key: None,
        note: String::new(),
    };
    let Some(rd) = tdx
        .pointer("/quote/body/reportdata")
        .or_else(|| tdx.pointer("/quote/body/report_data"))
        .and_then(Value::as_str)
        .and_then(|h| hex::decode(h.trim_start_matches("0x")).ok())
        .filter(|b| b.len() >= 20)
    else {
        out.note = "could not read report_data from the token; ".into();
        return out;
    };

    let runtime_data_b64 = serde_json::from_slice::<Value>(evidence)
        .ok()
        .and_then(|e| e.get("runtime_data").and_then(Value::as_str).map(String::from));
    let Some(runtime_data_b64) = runtime_data_b64 else {
        out.signer = Some(format!("0x{}", hex::encode(&rd[..20])));
        return out;
    };

    let bytes = match base64::engine::general_purpose::STANDARD.decode(&runtime_data_b64) {
        Ok(b) => b,
        Err(e) => {
            out.note = format!("runtime_data base64: {e}; ");
            return out;
        }
    };
    if sha2::Sha512::digest(&bytes).as_slice() != rd.as_slice() {
        out.note =
            "runtime_data does not hash to the quote's report_data — nothing in it can be believed; "
                .into();
        return out;
    }
    match serde_json::from_slice::<Value>(&bytes) {
        Ok(v) => {
            out.signer = v
                .get("signer")
                .and_then(Value::as_str)
                .map(str::to_lowercase);
            out.tls_public_key = v
                .get("tls_public_key")
                .and_then(Value::as_str)
                .map(str::to_lowercase)
                .filter(|k| !k.is_empty());
            if out.signer.is_none() {
                out.note = "runtime_data verified but names no signer; ".into();
            }
        }
        Err(e) => out.note = format!("runtime_data parse: {e}; "),
    }
    out
}

// ─── Node status ─────────────────────────────────────────────────────────────

/// What tappscan knows about one node at one point in time.
#[derive(Debug, Clone, Serialize)]
pub struct NodeStatus {
    /// On-chain node signer (the hardware identity being checked).
    pub signer: String,
    pub tee_url: String,
    /// Unix seconds when this check ran. A cached status is only ever "as of"
    /// this moment — attestation is a snapshot, not a standing property.
    pub checked_at: i64,

    pub tcb_status: String,
    pub advisories: Vec<String>,
    /// Signer attested in the quote. Whether it EQUALS the registered one is derived
    /// where it is used — the registration can change.
    pub attested_signer: Option<String>,
    /// sha256 of the app's TLS public key (hex), when the node attested one
    /// (tapp-server ≥0.4.0 with a TLS certificate issued).
    pub tls_public_key: Option<String>,

    pub boot_format: &'static str,
    pub measured: Measured,
    /// How the measurements compared against each reference set at check time.
    /// Informational only: the verdict is re-derived wherever it is shown, since
    /// the published values move (see [`crate::status::Attested`]).
    pub matches: Vec<SetMatch>,

    pub runtime_events: Vec<RuntimeEvent>,
    /// Event-log entries whose digest the AS could not reproduce. Firmware
    /// events legitimately land here (the AS cannot recompute a TdxTable digest
    /// from the event body), so this is informational unless a tapp runtime
    /// event appears in it.
    pub replay_mismatches: usize,
    pub note: String,
}

impl NodeStatus {
    /// Whether any measured tapp runtime event failed the AS's replay check.
    /// Unlike firmware events, these must always reconstruct.
    pub fn runtime_replay_ok(&self) -> bool {
        self.runtime_events.iter().all(|e| e.digest_matches)
    }
}

/// Which side a failed check failed on.
///
/// Worth separating because conflating them lets our own outage look like a node
/// being down: a verifier error means the evidence arrived fine and nothing has been
/// established either way, which is not a statement about the node at all.
#[derive(Debug)]
pub enum CheckError {
    /// The node did not produce evidence — unreachable, no such app, malformed reply.
    Node(anyhow::Error),
    /// Evidence was in hand but verification could not be completed: the AS errored,
    /// its reference-value lookup timed out, its policy failed to evaluate.
    Verifier(anyhow::Error),
}

impl std::fmt::Display for CheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckError::Node(e) => write!(f, "{e}"),
            CheckError::Verifier(e) => write!(f, "{e}"),
        }
    }
}

impl CheckError {
    pub fn is_verifier(&self) -> bool {
        matches!(self, CheckError::Verifier(_))
    }
}

/// Fetch `app_id`'s evidence from a node.
async fn fetch_evidence(tee_url: &str, app_id: &str) -> Result<Vec<u8>> {
    // An https teeUrl (nodes ≥0g-tapp#110 register their baked :50052 front) is
    // encryption without authentication — the certificate is self-signed and
    // accepted unseen, which is sound here because evidence authenticates itself
    // (Intel-signed) and this fetch sends no secret. See tls.rs.
    let channel = if tee_url.starts_with("https://") {
        crate::tls::grpc_channel_any(tee_url).await?
    } else {
        tonic::transport::Endpoint::from_shared(tee_url.to_string())
            .with_context(|| format!("endpoint {tee_url}"))?
            .connect()
            .await
            .with_context(|| format!("connect {tee_url}"))?
    };
    let mut client = TappServiceClient::new(channel).max_decoding_message_size(MAX_MSG_BYTES);
    // GetEvidence (≥0.4.0) accepts a challenge that the node echoes into
    // runtime_data — that is how a caller tells a fresh quote from a replayed
    // one. NONE IS SENT HERE ON PURPOSE, not as an oversight: this service
    // fetches once and serves the result to many readers, and its whole
    // contract is "as of checked_at". A nonce would prove freshness only to
    // this service while making the answer un-cacheable for everyone else.
    let resp = client
        .get_evidence(tonic::Request::new(GetEvidenceRequest {
            app_id: app_id.to_string(),
        }))
        .await
        .map_err(|e| anyhow!("GetEvidence: {}", e.message()))?
        .into_inner();
    if resp.evidence.is_empty() {
        return Err(anyhow!("node returned empty evidence: {}", resp.message));
    }
    Ok(resp.evidence)
}

/// Submit evidence to the AS with no policy selected and return the token claims.
async fn evaluate(as_endpoint: &str, evidence: &[u8]) -> Result<Value> {
    let mut client = AttestationServiceClient::connect(format!("http://{as_endpoint}"))
        .await
        .with_context(|| format!("connect AS {as_endpoint}"))?
        .max_decoding_message_size(MAX_MSG_BYTES)
        .max_encoding_message_size(MAX_MSG_BYTES);

    let token = client
        .attestation_evaluate(AttestationRequest {
            verification_requests: vec![IndividualAttestationRequest {
                tee: "tdx".to_string(),
                evidence: B64URL.encode(evidence),
                // No nonce binding: the evidence is pre-generated and bound to
                // the node's signer via report_data, not to a challenge.
                runtime_data: None,
                init_data: None,
                runtime_data_hash_algorithm: String::new(),
            }],
            policy_ids: vec![],
        })
        .await
        .map_err(|e| anyhow!("AttestationEvaluate: {}", e.message()))?
        .into_inner()
        .attestation_token;

    // The AS signed this token; the payload is read without re-verifying the
    // signature here. Layer 3 is explicitly a cache — anyone who does not want
    // to trust it can run `tapp-cli verify-app` (layer 2) or a self-hosted
    // trustee (layer 1) and check the signature themselves.
    let payload = token
        .split('.')
        .nth(1)
        .ok_or_else(|| anyhow!("malformed attestation token"))?;
    let raw = B64URL
        .decode(payload)
        .context("decode attestation token payload")?;
    serde_json::from_slice(&raw).context("parse attestation token claims")
}

/// Check one node: fetch evidence, verify the quote via the AS, identify the
/// image, and collect the runtime event log.
pub async fn check_node(
    tee_url: &str,
    app_id: &str,
    signer: &str,
    as_endpoint: &str,
    ref_sets: &[RefSet],
    now: i64,
) -> Result<NodeStatus, CheckError> {
    let evidence = fetch_evidence(tee_url, app_id)
        .await
        .map_err(CheckError::Node)?;
    tracing::debug!("{tee_url}: {} bytes of evidence", evidence.len());
    // From here on the node has done its part; anything that goes wrong is ours.
    let claims = evaluate(as_endpoint, &evidence)
        .await
        .map_err(CheckError::Verifier)?;

    let cpu = claims
        .pointer("/submods/cpu0")
        .ok_or_else(|| CheckError::Verifier(anyhow!("token has no cpu0 submodule")))?;
    let tdx = cpu
        .pointer("/ear.veraison.annotated-evidence/tdx")
        .ok_or_else(|| CheckError::Verifier(anyhow!("token has no tdx evidence")))?;
    let logs: Vec<Value> = tdx
        .get("uefi_event_logs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let measured = boot_digests(&logs);
    let matches = refvalues::match_sets(&measured, ref_sets);
    let rd = read_report_data(tdx, &evidence);
    let note = rd.note;

    Ok(NodeStatus {
        signer: signer.to_lowercase(),
        tee_url: tee_url.to_string(),
        checked_at: now,
        tcb_status: tdx
            .get("tcb_status")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string(),
        advisories: tdx
            .get("advisory_ids")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default(),
        attested_signer: rd.signer,
        tls_public_key: rd.tls_public_key,
        boot_format: measured.boot_format(),
        matches,
        measured,
        replay_mismatches: logs
            .iter()
            .filter(|e| e.get("digest_matches_event").and_then(Value::as_bool) == Some(false))
            .count(),
        runtime_events: runtime_events(&logs),
        note,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn token(rd_hex: &str) -> Value {
        json!({"quote": {"body": {"reportdata": rd_hex}}})
    }

    #[test]
    fn report_data_without_runtime_data_is_the_bare_address() {
        let rd_hex = format!("2bb10b0a9994d2a34da9c5c75c433a5a882ec0df{}", "00".repeat(44));
        let out = read_report_data(&token(&rd_hex), br#"{"quote":"q","cc_eventlog":"e"}"#);
        assert_eq!(
            out.signer.as_deref(),
            Some("0x2bb10b0a9994d2a34da9c5c75c433a5a882ec0df")
        );
        assert!(out.tls_public_key.is_none());
        assert!(out.note.is_empty());
    }

    #[test]
    fn report_data_with_runtime_data_reads_signer_and_tls_key() {
        // Mixed case in, lowercase out; hash computed over the bytes as sent.
        let runtime = br#"{"signer":"0x4DECAFBB35ad669871bd8a4beb8b4f8dfd0d9ff1","tls_public_key":"0x70CF27808f9764c920f17da56aa88caefbe9baddb9c2fdb0de344dc5624bbaa7"}"#;
        let rd_hex = hex::encode(sha2::Sha512::digest(runtime.as_slice()));
        let evidence = serde_json::to_vec(&json!({
            "quote": "q",
            "runtime_data": base64::engine::general_purpose::STANDARD.encode(runtime),
        }))
        .unwrap();
        let out = read_report_data(&token(&rd_hex), &evidence);
        assert_eq!(
            out.signer.as_deref(),
            Some("0x4decafbb35ad669871bd8a4beb8b4f8dfd0d9ff1")
        );
        assert_eq!(
            out.tls_public_key.as_deref(),
            Some("0x70cf27808f9764c920f17da56aa88caefbe9baddb9c2fdb0de344dc5624bbaa7")
        );
        assert!(out.note.is_empty());
    }

    #[test]
    fn tampered_runtime_data_is_believed_nowhere() {
        // The structure names a signer, but report_data hashes something else.
        // Falling back to "read it anyway" (or to the leading 20 bytes, which
        // here are hash bytes) would be exactly the bug this format prevents.
        let runtime = br#"{"signer":"0x1111111111111111111111111111111111111111"}"#;
        let rd_hex = hex::encode(sha2::Sha512::digest(b"something else entirely"));
        let evidence = serde_json::to_vec(&json!({
            "quote": "q",
            "runtime_data": base64::engine::general_purpose::STANDARD.encode(runtime),
        }))
        .unwrap();
        let out = read_report_data(&token(&rd_hex), &evidence);
        assert!(out.signer.is_none());
        assert!(out.tls_public_key.is_none());
        assert!(out.note.contains("does not hash"));
    }

    fn bsa(digest: &str, path: &str) -> Value {
        json!({
            "type_name": "EV_EFI_BOOT_SERVICES_APPLICATION",
            "digests": [{"alg": "SHA-384", "digest": digest}],
            "details": {"device_paths": ["ACPI(PNP0A03,0)", path]}
        })
    }
    fn ipl(digest: &str, s: &str) -> Value {
        json!({
            "type_name": "EV_IPL",
            "digests": [{"alg": "SHA-384", "digest": digest}],
            "details": {"string": s}
        })
    }

    #[test]
    fn grub_boot_chain_is_extracted() {
        let logs = vec![
            bsa("d_shim", "File(\\EFI\\alinux\\shimx64.efi)"),
            bsa("d_grub", "File(\\EFI\\alinux\\grubx64.efi)"),
            ipl("d_cmdline", "kernel_cmdline: console=ttyS0"),
            ipl("d_kernel", "/vmlinuz-6.16"),
            ipl("d_initrd", "/initrd.img"),
            ipl("d_other", "grub_cmd set pager=1"),
        ];
        let m = boot_digests(&logs);
        assert_eq!(m.boot_format(), "grub");
        assert!(m.get("shim").unwrap().contains("d_shim"));
        assert!(m.get("grub").unwrap().contains("d_grub"));
        assert!(m.get("kernel").unwrap().contains("d_kernel"));
        assert!(m.get("initrd").unwrap().contains("d_initrd"));
        assert!(m.get("kernel_cmdline").unwrap().contains("d_cmdline"));
        // Both boot-services apps are UKI candidates; unrelated IPL is ignored.
        assert_eq!(m.get(ANY_BSA).unwrap().len(), 2);
        assert!(!m.0.values().any(|s| s.contains("d_other")));
    }

    #[test]
    fn uki_boot_has_no_shim_or_grub() {
        let m = boot_digests(&[bsa("d_uki", "File(\\EFI\\BOOT\\BOOTX64.EFI)")]);
        assert_eq!(m.boot_format(), "uki");
        assert!(m.get("shim").is_none());
        assert!(m.get(ANY_BSA).unwrap().contains("d_uki"));
    }

    /// Device paths are matched case-insensitively — real logs carry
    /// `SHIMX64.EFI` as often as the lower-case spelling.
    #[test]
    fn device_path_matching_ignores_case() {
        let m = boot_digests(&[bsa("d", "File(\\EFI\\alinux\\SHIMX64.EFI)")]);
        assert!(m.get("shim").unwrap().contains("d"));
    }

    #[test]
    fn runtime_events_are_extracted_in_order() {
        let logs = vec![
            json!({
                "type_name": "EV_EVENT_TAG",
                "digests": [{"alg": "SHA-384", "digest": "d1"}],
                "digest_matches_event": true,
                "details": {"data": {"domain": "tapp.0g.com", "operation": "start_app",
                                     "content": {"app_id": "a", "result": "success", "timestamp": 7}}}
            }),
            // A firmware event with no tapp domain must not appear.
            json!({
                "type_name": "EV_EFI_HANDOFF_TABLES2",
                "digests": [{"alg": "SHA-384", "digest": "d2"}],
                "digest_matches_event": false,
                "details": {"string": "TdxTable"}
            }),
            json!({
                "type_name": "EV_EVENT_TAG",
                "digests": [{"alg": "SHA-384", "digest": "d3"}],
                "digest_matches_event": true,
                "details": {"data": {"domain": "tapp.0g.com", "operation": "stop_app",
                                     "content": {"app_id": "a", "result": "success"}}}
            }),
        ];
        let events = runtime_events(&logs);
        let ops: Vec<&str> = events.iter().map(|e| e.operation.as_str()).collect();
        assert_eq!(ops, ["start_app", "stop_app"]);
        assert_eq!(events[0].app_id(), Some("a"));
        assert_eq!(events[0].result(), Some("success"));
        assert_eq!(events[0].timestamp(), Some(7));
        assert_eq!(events[0].digest.as_deref(), Some("d1"));
    }

    #[test]
    fn unreadable_report_data_yields_no_signer() {
        let out = read_report_data(&json!({}), b"{}");
        assert!(out.signer.is_none());
        assert!(out.note.contains("report_data"));
    }
}
