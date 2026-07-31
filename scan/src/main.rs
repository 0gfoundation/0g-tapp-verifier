//! tappscan — TappRegistry explorer (trust layer 3).
//!
//! Layer 3 of the verification stack: a cache in front of the chain and the
//! Attestation Service, so reading an app's history and status does not require
//! every viewer to re-scan the chain and re-fetch multi-megabyte evidence.
//! Anyone who does not want to trust this cache can verify directly —
//! `tapp-cli verify-app` (layer 2) or a self-hosted trustee (layer 1).

mod attest;
mod chain;
mod refvalues;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// 0G testnet defaults. Mainnet is a config change, not a code change.
const DEFAULT_RPC: &str = "https://evmrpc-testnet.0g.ai";
const DEFAULT_CONTRACT: &str = "0x2Ce80374318B1d7Fb3345724457a182E0ad165c9";
const DEFAULT_AS: &str = "47.237.201.184:50004";

#[derive(Parser)]
#[command(name = "tappscan", version, about = "TappRegistry explorer")]
struct Cli {
    /// EVM RPC URL
    #[arg(long, env = "TAPPSCAN_RPC", default_value = DEFAULT_RPC)]
    rpc_url: String,

    /// TappRegistry contract address
    #[arg(long, env = "TAPPSCAN_CONTRACT", default_value = DEFAULT_CONTRACT)]
    contract: String,

    /// First block to scan on a cold start
    #[arg(long, env = "TAPPSCAN_FROM_BLOCK", default_value_t = 0)]
    from_block: u64,

    /// Where the scanned history is cached between runs
    #[arg(long, env = "TAPPSCAN_CACHE", default_value = "tappscan-cache.json")]
    cache: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List every app the registry has seen, with its current node signers
    Apps,
    /// Show one app's update history, split by hardware identity
    History {
        /// App id (or its 0x… hash, for apps whose name could not be recovered)
        app_id: String,
        /// Show every event, not just identity changes and code updates
        #[arg(long)]
        all: bool,
    },
    /// Attest the app's current hardware identities: verify each node's quote via
    /// the AS, identify its CVM image, and show the measured runtime event log
    Check {
        /// App id
        app_id: String,

        /// CoCo-AS gRPC endpoint (host:port)
        #[arg(long, env = "TAPPSCAN_AS", default_value = DEFAULT_AS)]
        as_endpoint: String,

        /// Directory of published reference values, scanned recursively
        #[arg(long, env = "TAPPSCAN_REFERENCE_VALUES")]
        reference_values: PathBuf,

        /// How many runtime event-log entries to print (newest last); 0 for all
        #[arg(long, default_value_t = 20)]
        events: usize,

        /// Only show runtime events for this app id (the log covers the whole node)
        #[arg(long)]
        events_this_app_only: bool,
    },
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "tappscan=info".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let scanner = chain::Scanner::new(&cli.rpc_url, &cli.contract, cli.from_block, cli.cache)?;
    let (registry, added) = scanner.sync().await?;
    tracing::info!(
        "{} events for {} apps (+{added} new), scanned to block {}",
        registry.events.len(),
        registry.apps().len(),
        registry.scanned_to
    );

    match cli.command {
        Command::Apps => {
            let apps = registry.apps();
            println!("{} app(s) on {}\n", apps.len(), registry.contract);
            for app in apps {
                let t = registry.timeline(&app);
                let signers = t.current_signers();
                let status = if signers.is_empty() {
                    "— no active node".to_string()
                } else {
                    signers.join(", ")
                };
                println!(
                    "  {:<34} {:>3} events  {:>2} identity epoch(s)  {}",
                    app,
                    t.entries.len(),
                    t.epochs.len(),
                    status
                );
            }
        }

        Command::History { app_id, all } => {
            let t = registry.timeline(&app_id);
            if t.entries.is_empty() {
                println!("no on-chain history for '{app_id}'");
                return Ok(());
            }
            println!("{}  —  {} event(s)\n", t.app_id, t.entries.len());

            println!("hardware identities:");
            for (i, ep) in t.epochs.iter().enumerate() {
                let until = match ep.to_block {
                    Some(b) => b.to_string(),
                    None => "now".to_string(),
                };
                // Only flag a real identity change; an app re-registered on the
                // same node starts a new stretch without changing machines.
                let note = if i == 0 {
                    ""
                } else if ep.identity_changed {
                    "  ⇄ 身份变更"
                } else {
                    "  (同一身份重新注册)"
                };
                println!(
                    "  #{}  blocks {}..{:<9}  {} code update(s)  signers: {}{}",
                    i + 1,
                    ep.from_block,
                    until,
                    ep.code_updates,
                    ep.signers.join(", "),
                    note
                );
            }

            println!("\nhistory:");
            for e in &t.entries {
                let interesting = e.identity_change
                    || matches!(
                        e.event,
                        chain::Event::AppUpdated { .. }
                            | chain::Event::AppRegistered { .. }
                            | chain::Event::AppUnregistered { .. }
                            | chain::Event::NodeCode { .. }
                    );
                if !all && !interesting {
                    continue;
                }
                let mark = if e.identity_change { "⇄" } else { " " };
                print!("  {} {:<9} {:<22}", mark, e.block, e.event.label());
                match &e.event {
                    chain::Event::NodeReplaced {
                        old_signer,
                        new_signer,
                        ..
                    } => print!(" {old_signer} → {new_signer}   硬件身份变更"),
                    chain::Event::NodeAdded { signer, .. }
                    | chain::Event::NodeRemoved { signer, .. } => print!(" {signer}"),
                    chain::Event::AppRegistered { owner, compose, .. } => {
                        print!(" owner={owner} compose={}", short(compose))
                    }
                    chain::Event::AppUpdated {
                        compose,
                        ack_version,
                        ..
                    } => print!(" compose={} ack_version={ack_version}", short(compose)),
                    chain::Event::AppUnregistered { owner } => print!(" owner={owner}"),
                    chain::Event::NodeCode { signer, compose, .. } => {
                        print!(" {signer} compose={}", short(compose))
                    }
                    chain::Event::Acknowledged { user, .. } | chain::Event::AckRevoked { user } => {
                        print!(" {user}")
                    }
                    chain::Event::AcksInvalidated { invalidator, .. }
                    | chain::Event::InvalidatorAuthorized { invalidator }
                    | chain::Event::InvalidatorRevoked { invalidator } => print!(" {invalidator}"),
                }
                println!();
            }
            if !all {
                println!("\n(acknowledgements hidden — pass --all to see every event)");
            }
        }

        Command::Check {
            app_id,
            as_endpoint,
            reference_values,
            events,
            events_this_app_only,
        } => {
            let ref_sets = refvalues::load_dir(&reference_values)?;
            if ref_sets.is_empty() {
                println!(
                    "warning: no reference values under {} — the boot chain cannot be identified",
                    reference_values.display()
                );
            }
            tracing::info!("{} reference set(s) loaded", ref_sets.len());

            let timeline = registry.timeline(&app_id);
            let signers = timeline.current_signers();
            if signers.is_empty() {
                println!("{app_id}: no active node on chain — nothing to attest");
                return Ok(());
            }
            println!("{app_id}  —  {} active node(s)\n", signers.len());

            for signer in signers {
                let tee_url = match scanner.node_tee_url(&app_id, &signer).await {
                    Ok(u) => u,
                    Err(e) => {
                        println!("  {signer}\n    ✗ could not read teeUrl from chain: {e}\n");
                        continue;
                    }
                };
                let status = match attest::check_node(
                    &tee_url,
                    &app_id,
                    &signer,
                    &as_endpoint,
                    &ref_sets,
                    unix_now(),
                )
                .await
                {
                    Ok(s) => s,
                    Err(e) => {
                        println!("  {signer}\n    teeUrl : {tee_url}\n    ✗ {e}\n");
                        continue;
                    }
                };
                print_status(&status, events, events_this_app_only, &app_id);
            }
        }
    }
    Ok(())
}

fn print_status(
    s: &attest::NodeStatus,
    event_limit: usize,
    this_app_only: bool,
    app_id: &str,
) {
    let yn = |b: bool| if b { "✓" } else { "✗" };
    println!("  {}", s.signer);
    println!("    teeUrl     : {}", s.tee_url);
    println!(
        "    signer     : {} attested {}",
        yn(s.signer_ok),
        s.attested_signer.as_deref().unwrap_or("—")
    );
    println!(
        "    quote      : ear.status={} tcb={} advisories={}",
        s.ear_status,
        s.tcb_status,
        s.advisories.len()
    );

    // Boot chain: report per component, since a partial match ("this image
    // except its initrd") is the useful diagnostic.
    match &s.image {
        Some(label) => println!("    image      : ✓ {label}  ({} boot)", s.boot_format),
        None => println!(
            "    image      : ✗ unknown ({} boot — no reference set fully matched)",
            s.boot_format
        ),
    }
    for m in s.matches.iter().take(if s.image.is_some() { 1 } else { 3 }) {
        let detail: Vec<String> = m
            .components
            .iter()
            .map(|(c, ok)| format!("{c}{}", yn(*ok)))
            .collect();
        println!(
            "      {:<52} {}",
            m.label,
            detail.join(" ")
        );
    }
    if s.image.is_none() {
        for (component, digests) in &s.measured.0 {
            if component.starts_with('_') {
                continue;
            }
            for d in digests {
                println!("      measured {component:<15} {d}");
            }
        }
    }

    // The AS replays every event against the signed RTMRs. Firmware events it
    // cannot recompute are expected; a tapp runtime event that fails is not.
    println!(
        "    event log  : {} tapp event(s), replay {}{}",
        s.runtime_events.len(),
        if s.runtime_replay_ok() { "✓" } else { "✗ MISMATCH" },
        if s.replay_mismatches > 0 {
            format!(" ({} firmware event(s) not reproducible — normal)", s.replay_mismatches)
        } else {
            String::new()
        }
    );

    let shown: Vec<&attest::RuntimeEvent> = s
        .runtime_events
        .iter()
        .filter(|e| !this_app_only || e.app_id() == Some(app_id))
        .collect();
    let skip = if event_limit == 0 {
        0
    } else {
        shown.len().saturating_sub(event_limit)
    };
    if skip > 0 {
        println!("      … {skip} earlier event(s) hidden");
    }
    for e in shown.iter().skip(skip) {
        println!(
            "      {:<10} {:<22} {:<26} {:<8} {}",
            e.timestamp().map(|t| t.to_string()).unwrap_or_default(),
            e.operation,
            e.app_id().unwrap_or("-"),
            e.result().unwrap_or("-"),
            e.digest
                .as_deref()
                .map(|d| &d[..16.min(d.len())])
                .unwrap_or("")
        );
    }

    if !s.note.is_empty() {
        println!("    note       : {}", s.note);
    }
    println!("    checked at : {} (unix)", s.checked_at);
    println!();
}

/// Abbreviate a long hash for one-line output.
fn short(s: &str) -> String {
    if s.len() > 18 {
        format!("{}…", &s[..16])
    } else {
        s.to_string()
    }
}
