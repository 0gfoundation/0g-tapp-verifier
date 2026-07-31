//! On-chain history reconstruction for the TappRegistry.
//!
//! Rebuilds, for every app the registry has ever seen, the ordered list of
//! changes and splits it into **identity epochs**: a stretch of history served
//! by one set of node signers. A signer set change means the hardware identity
//! behind the app changed; everything else is a code/config update under the
//! same identity.
//!
//! Two things make this less trivial than "read the events":
//!
//! * `string indexed appId` stores only `keccak256(appId)` in the log topic, so
//!   the plaintext app id is not in the log. It is recovered from the calldata of
//!   the emitting transaction — every app-scoped registry method takes
//!   `string appId` as its first argument. One lookup per app, cached forever
//!   (keccak is deterministic, so a recovered name never needs re-checking).
//!
//! * `eth_getLogs` limits differ per RPC provider, and some providers silently
//!   TRUNCATE at a result cap instead of erroring. Ranges are therefore split
//!   recursively on both errors and suspiciously full responses.

use anyhow::{anyhow, Context, Result};
use ethers::{
    abi::{decode, ParamType},
    providers::{Http, Middleware, Provider},
    types::{Address, Filter, Log, H256, U64},
    utils::keccak256,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// A response at or above this many logs is assumed to be a provider-side cap
/// rather than the true result, and the range is split. Real caps are usually
/// 10_000; staying under it keeps us from silently missing history.
const TRUNCATION_SUSPECT: usize = 9_000;

/// Blocks re-scanned on each incremental sync, so a short reorg cannot leave a
/// stale event in the cache. Events are keyed by (block, log_index), so
/// re-scanning is idempotent.
const REORG_DEPTH: u64 = 32;

// ─── Event model ─────────────────────────────────────────────────────────────

/// A decoded app-scoped registry event. Non-app-scoped events (StakeWithdrawn,
/// MinStakeUpdated, AdminTransferred, …) are not represented: their topic[1] is
/// not an app id hash, so treating them as app events would invent apps.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "event")]
pub enum Event {
    AppRegistered {
        owner: String,
        compose: String,
        volumes: String,
        images: Vec<String>,
    },
    AppUpdated {
        ack_version: u64,
        compose: String,
        volumes: String,
        images: Vec<String>,
    },
    AppUnregistered {
        owner: String,
    },
    /// `oldSigner == 0` in NodeUpdated: a node joined.
    NodeAdded {
        signer: String,
        ack_version: u64,
    },
    /// Both signers non-zero: the node kept its slot but the hardware identity
    /// behind it changed (redeploy, restart, or a different machine — the chain
    /// cannot tell these apart, and does not need to).
    NodeReplaced {
        old_signer: String,
        new_signer: String,
        ack_version: u64,
    },
    /// `newSigner == 0` in NodeUpdated: a node left.
    NodeRemoved {
        signer: String,
        ack_version: u64,
    },
    /// Per-node compose/volumes override (empty = inherit the app-level value).
    NodeCode {
        signer: String,
        compose: String,
        volumes: String,
    },
    Acknowledged {
        user: String,
        ack_version: u64,
    },
    AckRevoked {
        user: String,
    },
    AcksInvalidated {
        invalidator: String,
        ack_version: u64,
    },
    InvalidatorAuthorized {
        invalidator: String,
    },
    InvalidatorRevoked {
        invalidator: String,
    },
}

impl Event {
    /// Human label for listings.
    pub fn label(&self) -> &'static str {
        match self {
            Event::AppRegistered { .. } => "AppRegistered",
            Event::AppUpdated { .. } => "AppUpdated",
            Event::AppUnregistered { .. } => "AppUnregistered",
            Event::NodeAdded { .. } => "NodeAdded",
            Event::NodeReplaced { .. } => "NodeReplaced",
            Event::NodeRemoved { .. } => "NodeRemoved",
            Event::NodeCode { .. } => "NodeCode",
            Event::Acknowledged { .. } => "Acknowledged",
            Event::AckRevoked { .. } => "AckRevoked",
            Event::AcksInvalidated { .. } => "AcksInvalidated",
            Event::InvalidatorAuthorized { .. } => "InvalidatorAuthorized",
            Event::InvalidatorRevoked { .. } => "InvalidatorRevoked",
        }
    }
}

/// One event, located in the chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppEvent {
    pub block: u64,
    pub log_index: u64,
    pub tx: String,
    /// keccak256(appId) — the log topic. The plaintext name lives in
    /// [`Registry::app_ids`] once recovered.
    pub app_hash: String,
    pub event: Event,
}

// ─── Event signatures ────────────────────────────────────────────────────────

/// Registry methods whose FIRST argument is `string appId` — the calldata shape
/// that lets us recover a plaintext app id from a log.
const METHOD_SIGS: &[&str] = &[
    "registerApp(string,bytes,bytes,bytes[],address,string)",
    "updateApp(string,bytes,bytes,bytes[])",
    "addNode(string,address,string,bytes,bytes)",
    "updateNode(string,address,address,string,bytes,bytes)",
    "removeNode(string,address)",
    "acknowledgeApp(string)",
    "revokeAcknowledgement(string)",
    "authorizeInvalidator(string,address)",
    "revokeInvalidator(string,address)",
    "invalidateAcks(string)",
];

/// Batch methods taking `string[] appIds`. Their logs are indistinguishable from
/// the single-app form, so recovery must also search the array — otherwise an app
/// whose events all come from batch acknowledgements can never be named.
const BATCH_METHOD_SIGS: &[&str] = &[
    "acknowledgeApps(string[])",
    "revokeAcknowledgements(string[])",
];

/// Transactions tried per unnamed app before giving up for this sync. Recovery
/// is retried on later syncs, so a cap only defers work, never loses it.
const MAX_RECOVERY_TRIES: usize = 20;

fn topic0(sig: &str) -> H256 {
    H256::from(keccak256(sig.as_bytes()))
}

fn selector(sig: &str) -> [u8; 4] {
    let h = keccak256(sig.as_bytes());
    [h[0], h[1], h[2], h[3]]
}

/// On-chain `bytes` rendered for display: as text when it is printable ASCII
/// (image digests are ASCII `sha256:…`), hex otherwise.
///
/// The test is deliberately ASCII-only, not "valid UTF-8": raw SHA-384 bytes are
/// sometimes accidentally valid UTF-8 (`de ad` decodes to U+07AD), which would
/// render a hash as mojibake. Compose/volumes hashes always contain bytes
/// outside printable ASCII, so they land in the hex branch.
fn bytes_display(b: &[u8]) -> String {
    if !b.is_empty() && b.iter().all(|c| (0x20..=0x7e).contains(c)) {
        String::from_utf8_lossy(b).into_owned()
    } else {
        hex::encode(b)
    }
}

fn addr_from_topic(t: &H256) -> String {
    format!("0x{}", hex::encode(&t.as_bytes()[12..]))
}

// ─── Log decoding ────────────────────────────────────────────────────────────

/// Decode one log into an [`AppEvent`], or `None` if it is not an app-scoped
/// event we model.
fn decode_log(log: &Log) -> Option<AppEvent> {
    let t0 = *log.topics.first()?;
    let app_hash = format!("0x{}", hex::encode(log.topics.get(1)?.as_bytes()));
    let data = log.data.as_ref();

    // Non-indexed argument decoding; a decode failure means the deployed
    // contract's event shape differs from ours, so skip rather than guess.
    let words = |types: &[ParamType]| decode(types, data).ok();
    let uint = |v: &ethers::abi::Token| -> u64 {
        v.clone().into_uint().map(|u| u.as_u64()).unwrap_or(0)
    };
    let bytes = |v: &ethers::abi::Token| -> String {
        v.clone().into_bytes().map(|b| bytes_display(&b)).unwrap_or_default()
    };
    let bytes_arr = |v: &ethers::abi::Token| -> Vec<String> {
        v.clone()
            .into_array()
            .map(|a| {
                a.into_iter()
                    .filter_map(|t| t.into_bytes())
                    .map(|b| bytes_display(&b))
                    .collect()
            })
            .unwrap_or_default()
    };

    let event = if t0 == topic0("AppRegistered(string,address,bytes,bytes,bytes[])") {
        let f = words(&[
            ParamType::Bytes,
            ParamType::Bytes,
            ParamType::Array(Box::new(ParamType::Bytes)),
        ])?;
        Event::AppRegistered {
            owner: addr_from_topic(log.topics.get(2)?),
            compose: bytes(&f[0]),
            volumes: bytes(&f[1]),
            images: bytes_arr(&f[2]),
        }
    } else if t0 == topic0("AppUpdated(string,uint256,bytes,bytes,bytes[])") {
        let f = words(&[
            ParamType::Uint(256),
            ParamType::Bytes,
            ParamType::Bytes,
            ParamType::Array(Box::new(ParamType::Bytes)),
        ])?;
        Event::AppUpdated {
            ack_version: uint(&f[0]),
            compose: bytes(&f[1]),
            volumes: bytes(&f[2]),
            images: bytes_arr(&f[3]),
        }
    } else if t0 == topic0("AppUnregistered(string,address)") {
        Event::AppUnregistered {
            owner: addr_from_topic(log.topics.get(2)?),
        }
    } else if t0 == topic0("NodeCode(string,address,bytes,bytes)") {
        let f = words(&[ParamType::Bytes, ParamType::Bytes])?;
        Event::NodeCode {
            signer: addr_from_topic(log.topics.get(2)?),
            compose: bytes(&f[0]),
            volumes: bytes(&f[1]),
        }
    } else if t0 == topic0("NodeUpdated(string,address,address,uint256,uint256,uint256)") {
        // stakeAmount, unlockAt, newAckVersion — only the ack version is kept;
        // stake/unlock belong to the withdrawal flow, not app history.
        let f = words(&[ParamType::Uint(256), ParamType::Uint(256), ParamType::Uint(256)])?;
        let ack_version = uint(&f[2]);
        let old = *log.topics.get(2)?;
        let new = *log.topics.get(3)?;
        let zero = H256::zero();
        match (old == zero, new == zero) {
            (true, false) => Event::NodeAdded {
                signer: addr_from_topic(&new),
                ack_version,
            },
            (false, true) => Event::NodeRemoved {
                signer: addr_from_topic(&old),
                ack_version,
            },
            (false, false) => Event::NodeReplaced {
                old_signer: addr_from_topic(&old),
                new_signer: addr_from_topic(&new),
                ack_version,
            },
            // Both zero is meaningless; the contract cannot emit it.
            (true, true) => return None,
        }
    } else if t0 == topic0("AppAcknowledged(string,address,uint256)") {
        let f = words(&[ParamType::Uint(256)])?;
        Event::Acknowledged {
            user: addr_from_topic(log.topics.get(2)?),
            ack_version: uint(&f[0]),
        }
    } else if t0 == topic0("AppAcknowledgementRevoked(string,address)") {
        Event::AckRevoked {
            user: addr_from_topic(log.topics.get(2)?),
        }
    } else if t0 == topic0("AcksInvalidated(string,address,uint256)") {
        let f = words(&[ParamType::Uint(256)])?;
        Event::AcksInvalidated {
            invalidator: addr_from_topic(log.topics.get(2)?),
            ack_version: uint(&f[0]),
        }
    } else if t0 == topic0("InvalidatorAuthorized(string,address)") {
        Event::InvalidatorAuthorized {
            invalidator: addr_from_topic(log.topics.get(2)?),
        }
    } else if t0 == topic0("InvalidatorRevoked(string,address)") {
        Event::InvalidatorRevoked {
            invalidator: addr_from_topic(log.topics.get(2)?),
        }
    } else {
        return None;
    };

    Some(AppEvent {
        block: log.block_number?.as_u64(),
        log_index: log.log_index?.as_u64(),
        tx: format!("0x{}", hex::encode(log.transaction_hash?.as_bytes())),
        app_hash,
        event,
    })
}

/// ABI-decode the leading `string` argument of calldata (after the 4-byte
/// selector). Returns `None` for anything that does not decode cleanly.
fn first_string_arg(input: &[u8]) -> Option<String> {
    if input.len() < 4 {
        return None;
    }
    let tokens = decode(&[ParamType::String], &input[4..]).ok()?;
    tokens.into_iter().next()?.into_string()
}

/// ABI-decode the leading `string[]` argument of calldata.
fn first_string_array_arg(input: &[u8]) -> Vec<String> {
    if input.len() < 4 {
        return vec![];
    }
    decode(&[ParamType::Array(Box::new(ParamType::String))], &input[4..])
        .ok()
        .and_then(|t| t.into_iter().next())
        .and_then(|t| t.into_array())
        .map(|a| a.into_iter().filter_map(|t| t.into_string()).collect())
        .unwrap_or_default()
}

/// Candidate app ids carried by one transaction's calldata.
fn app_ids_in_calldata(input: &[u8]) -> Vec<String> {
    let Some(sel) = input.get(..4) else {
        return vec![];
    };
    if METHOD_SIGS.iter().any(|m| selector(m) == sel) {
        first_string_arg(input).into_iter().collect()
    } else if BATCH_METHOD_SIGS.iter().any(|m| selector(m) == sel) {
        first_string_array_arg(input)
    } else {
        vec![]
    }
}

// ─── Registry ────────────────────────────────────────────────────────────────

/// Everything scanned from one registry contract, cached on disk between runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Registry {
    pub chain_id: u64,
    pub contract: String,
    /// Highest block included in `events`.
    pub scanned_to: u64,
    /// keccak256(appId) → plaintext appId, for every app we could recover.
    pub app_ids: BTreeMap<String, String>,
    /// All app-scoped events, ordered by (block, log_index).
    pub events: Vec<AppEvent>,
}

impl Registry {
    fn new(chain_id: u64, contract: &str) -> Self {
        Self {
            chain_id,
            contract: contract.to_lowercase(),
            scanned_to: 0,
            app_ids: BTreeMap::new(),
            events: Vec::new(),
        }
    }

    /// Load a cache, or start empty. A cache for a different chain/contract is
    /// ignored rather than merged.
    pub fn load(path: &Path, chain_id: u64, contract: &str) -> Self {
        let fresh = Self::new(chain_id, contract);
        let Ok(raw) = std::fs::read(path) else {
            return fresh;
        };
        match serde_json::from_slice::<Registry>(&raw) {
            Ok(r) if r.chain_id == chain_id && r.contract == contract.to_lowercase() => r,
            Ok(_) => {
                tracing::warn!("cache is for a different chain/contract — starting fresh");
                fresh
            }
            Err(e) => {
                tracing::warn!("cache unreadable ({e}) — starting fresh");
                fresh
            }
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

    /// Plaintext app ids, sorted. Apps whose name could not be recovered are
    /// reported as their hash so they are visible rather than silently dropped.
    pub fn apps(&self) -> Vec<String> {
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for e in &self.events {
            seen.insert(
                self.app_ids
                    .get(&e.app_hash)
                    .cloned()
                    .unwrap_or_else(|| e.app_hash.clone()),
            );
        }
        seen.into_iter().collect()
    }

    fn hash_of(&self, app_id: &str) -> String {
        format!("0x{}", hex::encode(keccak256(app_id.as_bytes())))
    }

    /// Rebuild one app's history. Accepts either a plaintext app id or, for
    /// apps whose name was never recovered, the `0x…` hash.
    pub fn timeline(&self, app_id: &str) -> Timeline {
        let hash = if app_id.starts_with("0x") && app_id.len() == 66 {
            app_id.to_lowercase()
        } else {
            self.hash_of(app_id)
        };
        Timeline::build(
            app_id.to_string(),
            self.events.iter().filter(|e| e.app_hash == hash),
        )
    }
}

// ─── Timeline ────────────────────────────────────────────────────────────────

/// One entry of an app's history, annotated with the identity in force after it.
#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    pub block: u64,
    pub tx: String,
    pub event: Event,
    /// Node signers active AFTER this event.
    pub signers: Vec<String>,
    /// Whether this event changed the signer set — i.e. the hardware identity
    /// behind the app changed here.
    pub identity_change: bool,
}

/// A continuous stretch of history served by one signer set. A stretch ends when
/// the set changes OR when the app is left with no nodes at all; the same node
/// coming back after such a gap starts a new stretch.
#[derive(Debug, Clone, Serialize)]
pub struct Epoch {
    pub signers: Vec<String>,
    pub from_block: u64,
    /// `None` while this is the current epoch.
    pub to_block: Option<u64>,
    /// Code/config updates that happened under this identity.
    pub code_updates: usize,
    /// Whether the hardware identity actually changed relative to the previous
    /// stretch. False when an app was unregistered and re-registered on the SAME
    /// signer — a new stretch, but not a new machine identity.
    pub identity_changed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Timeline {
    pub app_id: String,
    pub entries: Vec<Entry>,
    pub epochs: Vec<Epoch>,
}

impl Timeline {
    fn build<'a>(app_id: String, events: impl Iterator<Item = &'a AppEvent>) -> Self {
        let mut signers: BTreeSet<String> = BTreeSet::new();
        let mut entries: Vec<Entry> = Vec::new();
        let mut epochs: Vec<Epoch> = Vec::new();

        for e in events {
            let before = signers.clone();
            match &e.event {
                Event::NodeAdded { signer, .. } => {
                    signers.insert(signer.clone());
                }
                Event::NodeRemoved { signer, .. } => {
                    signers.remove(signer);
                }
                Event::NodeReplaced {
                    old_signer,
                    new_signer,
                    ..
                } => {
                    signers.remove(old_signer);
                    signers.insert(new_signer.clone());
                }
                // AppUnregistered leaves no nodes behind.
                Event::AppUnregistered { .. } => signers.clear(),
                _ => {}
            }
            let identity_change = signers != before;
            let is_code_update = matches!(
                e.event,
                Event::AppUpdated { .. } | Event::NodeCode { .. }
            );

            if identity_change {
                // Close only a still-open epoch. An app can sit with no nodes for
                // a while (unregistered, or its last node removed); the next add
                // must not retroactively extend the epoch that already ended.
                if let Some(last) = epochs.last_mut() {
                    if last.to_block.is_none() {
                        last.to_block = Some(e.block);
                    }
                }
                // An empty signer set is a gap (unregistered / last node
                // removed), not an epoch — the app is served by nobody.
                if !signers.is_empty() {
                    let now: Vec<String> = signers.iter().cloned().collect();
                    let identity_changed =
                        epochs.last().map(|p| p.signers != now).unwrap_or(true);
                    epochs.push(Epoch {
                        signers: now,
                        from_block: e.block,
                        to_block: None,
                        code_updates: 0,
                        identity_changed,
                    });
                }
            } else if is_code_update {
                if let Some(last) = epochs.last_mut() {
                    if last.to_block.is_none() {
                        last.code_updates += 1;
                    }
                }
            }

            entries.push(Entry {
                block: e.block,
                tx: e.tx.clone(),
                event: e.event.clone(),
                signers: signers.iter().cloned().collect(),
                identity_change,
            });
        }

        Timeline {
            app_id,
            entries,
            epochs,
        }
    }

    /// Signers currently serving the app (empty if unregistered / no nodes).
    pub fn current_signers(&self) -> Vec<String> {
        self.entries
            .last()
            .map(|e| e.signers.clone())
            .unwrap_or_default()
    }

    /// Block of the app's most recent registry event — the trigger for
    /// re-attesting a cached result.
    pub fn latest_block(&self) -> u64 {
        self.entries.last().map(|e| e.block).unwrap_or(0)
    }
}

// ─── Scanning ────────────────────────────────────────────────────────────────

pub struct Scanner {
    provider: Provider<Http>,
    contract: Address,
    contract_str: String,
    /// First block to scan on a cold start. The registry cannot have events
    /// before its deployment, so a caller that knows the deploy block saves a
    /// lot of splitting.
    pub from_block: u64,
    pub cache_path: PathBuf,
}

impl Scanner {
    pub fn new(rpc_url: &str, contract: &str, from_block: u64, cache_path: PathBuf) -> Result<Self> {
        let provider = Provider::<Http>::try_from(rpc_url)
            .with_context(|| format!("invalid RPC URL: {rpc_url}"))?;
        let addr: Address = contract
            .parse()
            .with_context(|| format!("invalid contract address: {contract}"))?;
        Ok(Self {
            provider,
            contract: addr,
            contract_str: contract.to_lowercase(),
            from_block,
            cache_path,
        })
    }

    /// The `teeUrl` a node was registered with, via `getNode`. This is an
    /// owner-supplied string, NOT an attested fact — it says where to ask for
    /// evidence, and nothing more.
    pub async fn node_tee_url(&self, app_id: &str, signer: &str) -> Result<String> {
        use ethers::abi::{encode, Token};
        use ethers::types::{Bytes, TransactionRequest};

        let addr: Address = signer
            .parse()
            .with_context(|| format!("invalid signer address: {signer}"))?;
        let mut data = selector("getNode(string,address)").to_vec();
        data.extend_from_slice(&encode(&[
            Token::String(app_id.to_string()),
            Token::Address(addr),
        ]));
        let tx = TransactionRequest::new()
            .to(self.contract)
            .data(Bytes::from(data));
        let out = self.provider.call(&tx.into(), None).await?;

        // NodeInfo = (teeUrl, addedAt, stakeAmount, composeHash, volumesHash).
        // Deployments predating the per-node code override return only the first
        // three fields, so fall back rather than failing on an older registry.
        let shapes = [
            vec![
                ParamType::String,
                ParamType::Uint(256),
                ParamType::Uint(256),
                ParamType::Bytes,
                ParamType::Bytes,
            ],
            vec![ParamType::String, ParamType::Uint(256), ParamType::Uint(256)],
        ];
        for shape in shapes {
            if let Ok(tokens) = decode(&[ParamType::Tuple(shape)], &out) {
                if let Some(url) = tokens
                    .into_iter()
                    .next()
                    .and_then(|t| t.into_tuple())
                    .and_then(|f| f.into_iter().next())
                    .and_then(|t| t.into_string())
                {
                    return Ok(url);
                }
            }
        }
        Err(anyhow!("could not decode getNode response for {signer}"))
    }

    /// Fetch logs over `[from, to]`, splitting the range on errors and on
    /// suspiciously full responses (providers that cap instead of erroring).
    async fn fetch_logs(&self, from: u64, to: u64) -> Result<Vec<Log>> {
        let mut out = Vec::new();
        let mut stack = vec![(from, to)];

        while let Some((a, b)) = stack.pop() {
            let filter = Filter::new()
                .address(self.contract)
                .from_block(U64::from(a))
                .to_block(U64::from(b));

            match self.provider.get_logs(&filter).await {
                Ok(logs) if logs.len() >= TRUNCATION_SUSPECT && a < b => {
                    tracing::debug!("blocks {a}-{b}: {} logs, possibly capped — splitting", logs.len());
                    let mid = a + (b - a) / 2;
                    stack.push((mid + 1, b));
                    stack.push((a, mid));
                }
                Ok(logs) => {
                    tracing::debug!("blocks {a}-{b}: {} logs", logs.len());
                    out.extend(logs);
                }
                Err(e) if a < b => {
                    tracing::debug!("blocks {a}-{b} failed ({e}) — splitting");
                    let mid = a + (b - a) / 2;
                    stack.push((mid + 1, b));
                    stack.push((a, mid));
                }
                // A single block that still fails is a real error.
                Err(e) => return Err(anyhow!("get_logs at block {a}: {e}")),
            }
        }
        Ok(out)
    }

    /// Recover the plaintext app id behind `app_hash` from the calldata of the
    /// transactions that emitted its events, trying them in order until one
    /// yields a name that hashes to `app_hash`.
    ///
    /// Several txs may need trying: a batch acknowledgement names many apps at
    /// once, and some methods do not carry the id in a recoverable position. The
    /// keccak check makes accepting a wrong name impossible.
    ///
    /// Transactions are read out of their BLOCK rather than by hash. The 0G
    /// public RPC answers `eth_getTransactionByHash` with null for transactions
    /// it will happily return inside `eth_getBlockByNumber(_, true)`, so a
    /// by-hash lookup loses history at random.
    async fn recover_app_id(&self, app_hash: &str, candidates: &[(u64, String)]) -> Option<String> {
        let mut blocks_tried = BTreeSet::new();
        for (block, tx) in candidates.iter().take(MAX_RECOVERY_TRIES) {
            if !blocks_tried.insert(*block) {
                continue;
            }
            let body = match self.provider.get_block_with_txs(*block).await {
                Ok(Some(b)) => b,
                Ok(None) => {
                    tracing::debug!("block {block} not returned by the RPC");
                    continue;
                }
                Err(e) => {
                    tracing::debug!("block {block} lookup failed: {e}");
                    continue;
                }
            };
            let Ok(want) = tx.parse::<H256>() else { continue };
            for transaction in body.transactions.iter().filter(|t| t.hash == want) {
                for candidate in app_ids_in_calldata(transaction.input.as_ref()) {
                    let computed = format!("0x{}", hex::encode(keccak256(candidate.as_bytes())));
                    if computed == app_hash {
                        return Some(candidate);
                    }
                }
            }
        }
        None
    }

    /// Bring the cached registry up to the current head. Returns the registry
    /// and how many new events were added.
    pub async fn sync(&self) -> Result<(Registry, usize)> {
        let chain_id = self.provider.get_chainid().await?.as_u64();
        let mut reg = Registry::load(&self.cache_path, chain_id, &self.contract_str);

        let head = self.provider.get_block_number().await?.as_u64();
        let from = if reg.scanned_to == 0 {
            self.from_block
        } else {
            // Re-scan the tail so a reorg cannot leave stale events behind.
            reg.scanned_to.saturating_sub(REORG_DEPTH).max(self.from_block)
        };
        if from > head {
            return Ok((reg, 0));
        }

        tracing::info!("scanning blocks {from}..{head}");
        let logs = self.fetch_logs(from, head).await?;
        let decoded: Vec<AppEvent> = logs.iter().filter_map(decode_log).collect();
        tracing::info!("{} logs, {} app events", logs.len(), decoded.len());

        // Merge: drop anything in the re-scanned range, then re-insert.
        reg.events.retain(|e| e.block < from);
        let before = reg.events.len();
        reg.events.extend(decoded);
        reg.events.sort_by_key(|e| (e.block, e.log_index));
        reg.events.dedup_by_key(|e| (e.block, e.log_index));
        let added = reg.events.len().saturating_sub(before);

        // Recover names for app hashes we have never resolved, collecting every
        // candidate tx per app so one unhelpful calldata shape is not fatal.
        let mut unknown: BTreeMap<String, Vec<(u64, String)>> = BTreeMap::new();
        for e in &reg.events {
            if reg.app_ids.contains_key(&e.app_hash) {
                continue;
            }
            let txs = unknown.entry(e.app_hash.clone()).or_default();
            if !txs.iter().any(|(_, tx)| tx == &e.tx) {
                txs.push((e.block, e.tx.clone()));
            }
        }
        for (hash, candidates) in unknown {
            match self.recover_app_id(&hash, &candidates).await {
                Some(name) => {
                    tracing::debug!("recovered app id {name} for {hash}");
                    reg.app_ids.insert(hash, name);
                }
                None => tracing::warn!(
                    "could not recover app id for {hash} ({} tx tried)",
                    candidates.len().min(MAX_RECOVERY_TRIES)
                ),
            }
        }

        reg.scanned_to = head;
        reg.save(&self.cache_path)?;
        Ok((reg, added))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_display_prefers_printable_ascii() {
        assert_eq!(bytes_display(b"sha256:abc"), "sha256:abc");
        // Valid UTF-8 but not ASCII — must stay hex, or hashes render as mojibake.
        assert_eq!(bytes_display(&[0xde, 0xad]), "dead");
        // Printable ASCII prefix followed by raw digest bytes (volumesHash shape).
        assert_eq!(bytes_display(b"kms.toml:\x60\x9c\n"), "6b6d732e746f6d6c3a609c0a");
        assert_eq!(bytes_display(b""), "");
    }

    #[test]
    fn first_string_arg_decodes_app_id() {
        // registerApp("0g-kms", …) — offset(0x20) then the string, trailing args
        // are ignored by the decoder.
        let mut input = selector("registerApp(string,bytes,bytes,bytes[],address,string)").to_vec();
        input.extend_from_slice(&[0u8; 31]);
        input.push(0x20); // offset to the string
        input.extend_from_slice(&[0u8; 31]);
        input.push(6); // length
        let mut word = b"0g-kms".to_vec();
        word.resize(32, 0);
        input.extend_from_slice(&word);
        assert_eq!(first_string_arg(&input).as_deref(), Some("0g-kms"));
    }

    /// Build a timeline from bare (block, event) pairs.
    fn timeline(events: Vec<(u64, Event)>) -> Timeline {
        let app_events: Vec<AppEvent> = events
            .into_iter()
            .enumerate()
            .map(|(i, (block, event))| AppEvent {
                block,
                log_index: i as u64,
                tx: format!("0x{i:064x}"),
                app_hash: "0xdead".to_string(),
                event,
            })
            .collect();
        Timeline::build("app".to_string(), app_events.iter())
    }

    #[test]
    fn signer_replacement_starts_a_new_epoch() {
        let t = timeline(vec![
            (
                100,
                Event::NodeAdded {
                    signer: "0xaaa".into(),
                    ack_version: 1,
                },
            ),
            (
                110,
                Event::AppUpdated {
                    ack_version: 2,
                    compose: "c1".into(),
                    volumes: String::new(),
                    images: vec![],
                },
            ),
            (
                120,
                Event::NodeReplaced {
                    old_signer: "0xaaa".into(),
                    new_signer: "0xbbb".into(),
                    ack_version: 3,
                },
            ),
            (
                130,
                Event::AppUpdated {
                    ack_version: 4,
                    compose: "c2".into(),
                    volumes: String::new(),
                    images: vec![],
                },
            ),
        ]);

        // Two identities, split at the replacement.
        assert_eq!(t.epochs.len(), 2);
        assert_eq!(t.epochs[0].signers, vec!["0xaaa"]);
        assert_eq!(t.epochs[0].from_block, 100);
        assert_eq!(t.epochs[0].to_block, Some(120));
        assert_eq!(t.epochs[0].code_updates, 1);
        assert_eq!(t.epochs[1].signers, vec!["0xbbb"]);
        assert_eq!(t.epochs[1].to_block, None);
        assert_eq!(t.epochs[1].code_updates, 1);

        // Only the replacement is an identity change.
        let changes: Vec<u64> = t
            .entries
            .iter()
            .filter(|e| e.identity_change)
            .map(|e| e.block)
            .collect();
        assert_eq!(changes, vec![100, 120]);
        assert_eq!(t.current_signers(), vec!["0xbbb"]);
    }

    #[test]
    fn multi_node_app_tracks_the_whole_set() {
        let t = timeline(vec![
            (10, Event::NodeAdded { signer: "0xaaa".into(), ack_version: 1 }),
            (20, Event::NodeAdded { signer: "0xbbb".into(), ack_version: 2 }),
            (30, Event::NodeRemoved { signer: "0xaaa".into(), ack_version: 3 }),
        ]);
        assert_eq!(t.current_signers(), vec!["0xbbb"]);
        // Each add/remove changes the set, so each opens an epoch.
        assert_eq!(t.epochs.len(), 3);
        assert_eq!(t.epochs[1].signers, vec!["0xaaa", "0xbbb"]);
        assert_eq!(t.epochs[2].signers, vec!["0xbbb"]);
    }

    #[test]
    fn unregister_ends_the_current_epoch_without_opening_one() {
        let t = timeline(vec![
            (10, Event::NodeAdded { signer: "0xaaa".into(), ack_version: 1 }),
            (20, Event::AppUnregistered { owner: "0xowner".into() }),
        ]);
        assert_eq!(t.epochs.len(), 1);
        assert_eq!(t.epochs[0].to_block, Some(20));
        assert!(t.current_signers().is_empty());
    }

    /// register → unregister → re-register much later (seen on 0g-sandbox-provider).
    /// The gap must not be absorbed into the first epoch.
    #[test]
    fn reregistration_after_a_gap_does_not_extend_the_closed_epoch() {
        let t = timeline(vec![
            (100, Event::NodeAdded { signer: "0xaaa".into(), ack_version: 1 }),
            (200, Event::NodeRemoved { signer: "0xaaa".into(), ack_version: 2 }),
            (200, Event::AppUnregistered { owner: "0xowner".into() }),
            (900, Event::NodeAdded { signer: "0xbbb".into(), ack_version: 3 }),
        ]);
        assert_eq!(t.epochs.len(), 2);
        // First epoch ended when its node left, NOT when the next one arrived.
        assert_eq!(t.epochs[0].to_block, Some(200));
        assert_eq!(t.epochs[1].from_block, 900);
        assert_eq!(t.epochs[1].to_block, None);
    }

    #[test]
    fn acks_are_not_code_updates() {
        let t = timeline(vec![
            (10, Event::NodeAdded { signer: "0xaaa".into(), ack_version: 1 }),
            (20, Event::Acknowledged { user: "0xu".into(), ack_version: 1 }),
            (30, Event::AckRevoked { user: "0xu".into() }),
        ]);
        assert_eq!(t.epochs[0].code_updates, 0);
        assert!(!t.entries[1].identity_change);
    }
}
