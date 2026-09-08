//! tappscan — TappRegistry explorer (trust layer 3).
//!
//! Layer 3 of the verification stack: a cache in front of the chain and the
//! Attestation Service, so reading an app's history and status does not require
//! every viewer to re-scan the chain and re-fetch multi-megabyte evidence.
//! Anyone who does not want to trust this cache can verify directly —
//! `tapp-cli verify-app` (layer 2) or a self-hosted trustee (layer 1).

mod api;
mod attest;
mod tls;
mod keys;
mod chain;
mod refsource;
mod refvalues;
mod status;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::time::Duration;

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

    /// First block to scan on a cold start. Set this to the registry's deployment
    /// block to avoid splitting tens of millions of empty blocks — but set it
    /// together with --contract, because a value later than a registry's first
    /// event silently loses history. It cannot be derived automatically: the 0G
    /// public RPC is pruned, so eth_getCode at a historical block answers "state
    /// is not available" and a deployment-block search converges on the head.
    #[arg(long, env = "TAPPSCAN_FROM_BLOCK", default_value_t = 0)]
    from_block: u64,

    /// Where the scanned history is cached between runs
    #[arg(long, env = "TAPPSCAN_CACHE", default_value = "tappscan-cache.json")]
    cache: PathBuf,

    /// Where attestation results are cached between runs
    #[arg(long, env = "TAPPSCAN_STATUS", default_value = "tappscan-status.json")]
    status: PathBuf,

    #[command(subcommand)]
    command: Command,
}

/// Options shared by everything that attests a node.
#[derive(clap::Args, Clone)]
struct AttestOpts {
    /// CoCo-AS gRPC endpoint (host:port)
    #[arg(long, env = "TAPPSCAN_AS", default_value = DEFAULT_AS)]
    as_endpoint: String,

    /// A directory of published reference values, scanned recursively. Pins them:
    /// nothing changes underneath a verdict, and nothing is fetched. Without it the
    /// values are tracked from the repository below, which is the default because a
    /// mount left behind reports every node running a newer image as "unknown".
    #[arg(long, env = "TAPPSCAN_REFERENCE_VALUES")]
    reference_values: Option<PathBuf>,

    /// Repository to track reference values from when no directory is given.
    #[arg(long, env = "TAPPSCAN_REFS_REPO", default_value = "0gfoundation/0g-tapp")]
    refs_repo: String,

    /// Ref to track. Whoever can merge here decides what counts as verified, which
    /// is why every verdict is reported with the tree it was reached against.
    #[arg(long, env = "TAPPSCAN_REFS_REF", default_value = "dev")]
    refs_ref: String,

    /// Path within the repository.
    #[arg(long, env = "TAPPSCAN_REFS_PATH", default_value = "verifier/reference-values")]
    refs_path: String,

    /// Optional GitHub token. Only raises the rate limit; the values are public.
    #[arg(long, env = "TAPPSCAN_REFS_TOKEN")]
    refs_token: Option<String>,

    /// Backstop for re-attesting when the chain shows no change, in seconds.
    /// A new registry event always forces a re-check regardless of this.
    #[arg(long, env = "TAPPSCAN_MAX_AGE", default_value_t = 3600)]
    max_age: i64,

    /// Nodes attested at once. Each one moves megabytes (evidence in, token
    /// out), so this trades round-trip latency against bandwidth and AS load.
    #[arg(long, env = "TAPPSCAN_CONCURRENCY", default_value_t = 4)]
    concurrency: usize,
}

#[derive(Subcommand)]
enum Command {
    /// List every app the registry has seen, with its current node signers
    Apps {
        #[command(flatten)]
        attest: AttestOpts,
    },
    /// Show one app's update history, split by hardware identity
    History {
        /// App id (or its 0x… hash, for apps whose name could not be recovered)
        app_id: String,
        /// Show every event, not just identity changes and code updates
        #[arg(long)]
        all: bool,
    },
    /// Attest the app's current hardware identities: verify each node's quote via
    /// the AS, identify its CVM image, and show the measured runtime event log.
    /// A cached result is served while it is fresh.
    Check {
        /// App id
        app_id: String,

        #[command(flatten)]
        attest: AttestOpts,

        /// Re-attest even if the cached result is fresh
        #[arg(long)]
        force: bool,

        /// How many runtime event-log entries to print (newest last); 0 for all
        #[arg(long, default_value_t = 20)]
        events: usize,

        /// Which slice of the machine's trace to print. The trace belongs to the
        /// CVM, not the app: every app on a machine measures into the same RTMR3,
        /// and operations like docker_login carry no app id at all.
        ///   app    — this app plus the unattributable machine-scoped events
        ///   others — what the machine's other apps did
        ///   all    — the whole trace
        #[arg(long, default_value = "app")]
        scope: EventScope,
    },
    /// Keep the cache warm: sync the chain, re-attest whatever the chain says has
    /// changed, and repeat. This is what makes reads cheap for everyone else.
    Watch {
        #[command(flatten)]
        attest: AttestOpts,

        /// Seconds between chain syncs
        #[arg(long, default_value_t = 60)]
        interval: u64,

        /// Stop after this many rounds (0 = run forever)
        #[arg(long, default_value_t = 0)]
        rounds: u64,
    },
    /// Run the refresh loop and serve the read-only HTTP interface. This is the
    /// deployable form of tappscan.
    Serve {
        #[command(flatten)]
        attest: AttestOpts,

        /// Address to listen on
        #[arg(long, env = "TAPPSCAN_BIND", default_value = "0.0.0.0:9090")]
        bind: String,

        /// Seconds between chain syncs
        #[arg(long, default_value_t = 60)]
        interval: u64,

        /// Where API keys for policy writes are kept. Only hashes are stored.
        #[arg(long, env = "TAPPSCAN_KEYS", default_value = "tappscan-keys.json")]
        keys: PathBuf,

        /// Shared with the AS proxy so its authorisation subrequest can be told
        /// apart from a stranger probing the endpoint. Unset disables the check,
        /// which is fine when nothing but the proxy can reach this port.
        #[arg(long, env = "TAPPSCAN_AUTHZ_SECRET")]
        authz_secret: Option<String>,
    },
}

/// Which slice of a machine's trace to show for one app.
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum EventScope {
    App,
    Others,
    All,
}

impl EventScope {
    /// Operations carrying no app id belong to the machine rather than to any one
    /// app, so they are shown under every scope rather than hidden or assigned.
    fn admits(self, event_app: Option<&str>, app_id: &str) -> bool {
        match (self, event_app) {
            (EventScope::All, _) | (_, None) => true,
            (EventScope::Others, Some(a)) => a != app_id,
            (EventScope::App, Some(a)) => a == app_id,
        }
    }
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
    let scanner = std::sync::Arc::new(chain::Scanner::new(
        &cli.rpc_url,
        &cli.contract,
        cli.from_block,
        cli.cache,
    )?);
    let (registry, added) = scanner.sync().await?;
    tracing::info!(
        "{} events for {} apps (+{added} new), scanned to block {}",
        registry.events.len(),
        registry.apps().len(),
        registry.scanned_to
    );

    match cli.command {
        Command::Apps { attest: opts } => {
            let apps = registry.apps();
            let store = status::Store::load(&cli.status);
            let now = unix_now();
            let tracker = load_ref_sets(&opts).await?;
            let ref_sets = tracker.sets();
            println!("{} app(s) on {}\n", apps.len(), registry.contract);
            for app in apps {
                let t = registry.timeline(&app);
                let signers = t.current_signers();
                println!(
                    "  {:<34} {:>3} events  {:>2} signer(s) ever  {:>2} node(s)  {}",
                    app,
                    t.entries.len(),
                    t.signers.len(),
                    signers.len(),
                    attestation_summary(&store, &app, &signers, ref_sets, now)
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

            println!("signers:");
            for h in &t.signers {
                // Several intervals means the address was removed and registered
                // again — the same instance, re-recorded on chain.
                let spans: Vec<String> = h
                    .intervals
                    .iter()
                    .map(|i| {
                        format!(
                            "{}..{}",
                            i.from_block,
                            i.to_block.map(|b| b.to_string()).unwrap_or("now".into())
                        )
                    })
                    .collect();
                println!(
                    "  {}  {}  {} code update(s){}",
                    h.signer,
                    spans.join(", "),
                    h.code_updates,
                    if h.is_current() {
                        "  ← current, attestable"
                    } else {
                        "  (retired — cannot be re-attested)"
                    }
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
            attest: opts,
            force,
            events,
            scope,
        } => {
            let tracker = load_ref_sets(&opts).await?;
            let ref_sets = std::sync::Arc::new(tracker.sets().to_vec());
            let mut store = status::Store::load(&cli.status);

            let signers = registry.timeline(&app_id).current_signers();
            if signers.is_empty() {
                println!("{app_id}: no active node on chain — nothing to attest");
                return Ok(());
            }
            let jobs = plan(
                &registry,
                &store,
                std::slice::from_ref(&app_id),
                &opts,
                force,
                unix_now(),
            );
            run_jobs(scanner.clone(), &mut store, jobs, &opts, ref_sets.clone()).await;
            store.save(&cli.status)?;

            println!("{app_id}  —  {} active node(s)\n", signers.len());
            let now = unix_now();
            for signer in &signers {
                match store.get(&app_id, signer) {
                    Some(entry) => print_entry(entry, now, events, scope, &app_id, &ref_sets),
                    None => println!("  {signer}\n    ✗ never attested (see log above)\n"),
                }
            }
        }

        Command::Watch {
            attest: opts,
            interval,
            rounds,
        } => {
            let mut tracker = refsource::Tracker::new(opts.source());
            tracker.refresh(unix_now()).await?;
            let mut ref_sets = std::sync::Arc::new(tracker.sets().to_vec());
            let mut store = status::Store::load(&cli.status);
            let mut registry = registry;
            let mut round: u64 = 0;

            loop {
                round += 1;
                let apps = registry.apps();
                let jobs = plan(&registry, &store, &apps, &opts, false, unix_now());
                tracing::info!("round {round}: {} node(s) to attest", jobs.len());
                let rechecked =
                    run_jobs(scanner.clone(), &mut store, jobs, &opts, ref_sets.clone()).await;
                store.save(&cli.status)?;
                tracing::info!(
                    "round {round}: {rechecked} node(s) attested, chain at block {}",
                    registry.scanned_to
                );

                if rounds != 0 && round >= rounds {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_secs(interval)).await;
                if tracker.refresh(unix_now()).await.is_ok() {
                    ref_sets = std::sync::Arc::new(tracker.sets().to_vec());
                }
                match scanner.sync().await {
                    Ok((r, added)) => {
                        if added > 0 {
                            tracing::info!("{added} new chain event(s)");
                        }
                        registry = r;
                    }
                    // A transient RPC failure must not end the watch; the next
                    // round retries against the cache we already have.
                    Err(e) => tracing::warn!("chain sync failed: {e}"),
                }
            }
        }

        Command::Serve {
            attest: opts,
            bind,
            interval,
            keys: keys_path,
            authz_secret,
        } => {
            let mut tracker = refsource::Tracker::new(opts.source());
            tracker.refresh(unix_now()).await?;
            // Read once at startup: keys are issued against whoever the chain says
            // is admin, so that authority is not re-invented here.
            let admin = match scanner.admin().await {
                Ok(a) => {
                    tracing::info!("registry admin is {a} — the only signer that may issue keys");
                    Some(a)
                }
                Err(e) => {
                    tracing::warn!("could not read admin() ({e}) — key issuing disabled");
                    None
                }
            };
            let shared: api::AppState = std::sync::Arc::new(tokio::sync::RwLock::new(api::Shared {
                registry,
                store: status::Store::load(&cli.status),
                api_keys: keys::KeyStore::load(&keys_path),
                keys_path,
                admin,
                spent: Default::default(),
                authz_secret,
                balances: Default::default(),
                rpc_url: cli.rpc_url.clone(),
                ref_sets: std::sync::Arc::new(tracker.sets().to_vec()),
                refs_from: tracker.provenance().clone(),
                refreshed_at: unix_now(),
            }));

            // The refresh loop is the ONLY thing that touches nodes or the AS;
            // serving is pure reads of what it has already established.
            let refresher = {
                let shared = shared.clone();
                let scanner = scanner.clone();
                let status_path = cli.status.clone();
                tokio::spawn(async move {
                    loop {
                        // Pick up anything written by an operator's one-off check.
                        {
                            let mut s = shared.write().await;
                            let taken = s.store.merge_from_disk(&status_path);
                            if taken > 0 {
                                tracing::info!("took {taken} externally written result(s)");
                            }
                        }
                        let (apps, jobs) = {
                            let s = shared.read().await;
                            let apps = s.registry.apps();
                            let jobs = plan(&s.registry, &s.store, &apps, &opts, false, unix_now());
                            (apps.len(), jobs)
                        };
                        if !jobs.is_empty() {
                            tracing::info!("{apps} apps: attesting {} node(s)", jobs.len());
                            // Work on a copy so readers are never blocked while
                            // megabytes move over the network.
                            let mut store = shared.read().await.store.clone();
                            let sets = shared.read().await.ref_sets.clone();
                            let done =
                                run_jobs(scanner.clone(), &mut store, jobs, &opts, sets).await;
                            if let Err(e) = store.save(&status_path) {
                                tracing::warn!("could not save status cache: {e}");
                            }
                            let mut s = shared.write().await;
                            s.store = store;
                            s.refreshed_at = unix_now();
                            tracing::info!("{done} node(s) attested");
                        } else {
                            shared.write().await.refreshed_at = unix_now();
                        }

                        // Reference values are re-read every round, so a set
                        // published upstream takes effect without an ops step — and
                        // a failed read keeps the last good one rather than turning
                        // every node "unknown".
                        match tracker.refresh(unix_now()).await {
                            Ok(_) => {
                                let mut s = shared.write().await;
                                s.ref_sets = std::sync::Arc::new(tracker.sets().to_vec());
                                s.refs_from = tracker.provenance().clone();
                            }
                            Err(e) => tracing::warn!("reference values unavailable: {e}"),
                        }

                        // Balances are a plain chain read and change on their own
                        // schedule, so they refresh every round regardless of
                        // whether anything needed re-attesting.
                        let addresses = {
                            let s = shared.read().await;
                            let mut all: Vec<String> = s
                                .registry
                                .apps()
                                .iter()
                                .flat_map(|app| {
                                    s.registry
                                        .timeline(app)
                                        .signers
                                        .iter()
                                        .map(|h| h.signer.clone())
                                        .collect::<Vec<_>>()
                                })
                                .collect();
                            all.sort();
                            all.dedup();
                            all
                        };
                        let balances = scanner.balances(&addresses).await;
                        if !balances.is_empty() {
                            shared.write().await.balances = balances;
                        }

                        tokio::time::sleep(Duration::from_secs(interval)).await;
                        match scanner.sync().await {
                            Ok((r, added)) => {
                                if added > 0 {
                                    tracing::info!("{added} new chain event(s)");
                                }
                                shared.write().await.registry = r;
                            }
                            Err(e) => tracing::warn!("chain sync failed: {e}"),
                        }
                    }
                })
            };

            let listener = tokio::net::TcpListener::bind(&bind).await?;
            tracing::info!("serving on http://{bind}");
            axum::serve(listener, api::router(shared)).await?;
            refresher.abort();
        }
    }
    Ok(())
}

/// One-line attestation state for the app listing, from the cache only — listing
/// apps must never trigger megabytes of evidence fetching.
fn attestation_summary(
    store: &status::Store,
    app_id: &str,
    signers: &[String],
    ref_sets: &[refvalues::RefSet],
    now: i64,
) -> String {
    if signers.is_empty() {
        return "— no active node".to_string();
    }
    let cached = store.for_app(app_id);
    if cached.is_empty() {
        return "not attested yet".to_string();
    }
    let failed = cached.iter().filter(|e| e.error.is_some()).count();
    // Identity is a comparison against today's reference values, so it is derived
    // here rather than read back from the cache.
    let named: Vec<Option<String>> = cached.iter().map(|e| e.image(ref_sets)).collect();
    let identified = named.iter().flatten().count();
    let oldest = cached.iter().map(|e| e.age_secs(now)).max().unwrap_or(0);
    // No image is named at the app level: the boot chain belongs to one machine,
    // and an app's nodes may run on different machines with different images.
    // `attest <app>` names each node's image next to its signer.
    let state = match (failed, identified) {
        (f, _) if f == cached.len() => "✗ all attempts failed".to_string(),
        (0, 0) => "image unknown".to_string(),
        (0, i) if i == cached.len() => format!("✓ {i}/{i} boot chains identified"),
        (f, i) => format!("{i}/{} identified, {f} failed", signers.len()),
    };
    format!("{state}  (as of {} ago)", human_age(oldest))
}

impl AttestOpts {
    fn source(&self) -> refsource::Source {
        match &self.reference_values {
            Some(dir) => refsource::Source::Dir(dir.clone()),
            None => refsource::Source::Git {
                repo: self.refs_repo.clone(),
                git_ref: self.refs_ref.clone(),
                path: self.refs_path.clone(),
                token: self.refs_token.clone(),
            },
        }
    }
}

/// Read the reference values once, for the commands that do not run a loop.
async fn load_ref_sets(opts: &AttestOpts) -> Result<refsource::Tracker> {
    let mut tracker = refsource::Tracker::new(opts.source());
    let count = tracker.refresh(unix_now()).await?;
    let p = tracker.provenance();
    tracing::info!(
        "{count} reference set(s) from {}{}",
        p.source,
        p.tree.as_deref().map(|t| format!(" (tree {})", &t[..12.min(t.len())])).unwrap_or_default()
    );
    Ok(tracker)
}

/// One node that needs attesting.
struct Job {
    app_id: String,
    signer: String,
    latest_block: u64,
    reason: &'static str,
}

/// Nodes across `apps` whose cached result is missing, superseded by a chain
/// event, or past the age backstop.
fn plan(
    registry: &chain::Registry,
    store: &status::Store,
    apps: &[String],
    opts: &AttestOpts,
    force: bool,
    now: i64,
) -> Vec<Job> {
    let mut jobs = Vec::new();
    for app_id in apps {
        let timeline = registry.timeline(app_id);
        let latest_block = timeline.latest_block();
        for signer in timeline.current_signers() {
            let freshness = store.freshness(app_id, &signer, latest_block, opts.max_age, now);
            if force || freshness.needs_check() {
                jobs.push(Job {
                    app_id: app_id.clone(),
                    signer,
                    latest_block,
                    reason: if force { "forced" } else { freshness.reason() },
                });
            }
        }
    }
    jobs
}

/// Attest every job, up to `opts.concurrency` at a time, and store each outcome.
///
/// Serial execution would make a round take time proportional to the number of
/// apps — fine at 25 apps, useless at 500 — so jobs run concurrently under a
/// semaphore. Results are applied afterwards, keeping the store single-writer.
async fn run_jobs(
    scanner: std::sync::Arc<chain::Scanner>,
    store: &mut status::Store,
    jobs: Vec<Job>,
    opts: &AttestOpts,
    ref_sets: std::sync::Arc<Vec<refvalues::RefSet>>,
) -> usize {
    if jobs.is_empty() {
        return 0;
    }
    let limit = std::sync::Arc::new(tokio::sync::Semaphore::new(opts.concurrency.max(1)));
    let mut tasks = tokio::task::JoinSet::new();

    for job in jobs {
        let scanner = scanner.clone();
        let ref_sets = ref_sets.clone();
        let limit = limit.clone();
        let as_endpoint = opts.as_endpoint.clone();
        tasks.spawn(async move {
            let _permit = limit.acquire().await;
            let now = unix_now();
            tracing::info!("{}/{}: attesting ({})", job.app_id, job.signer, job.reason);

            let tee_url = match scanner.node_tee_url(&job.app_id, &job.signer).await {
                Ok(u) => u,
                Err(e) => {
                    tracing::warn!(
                        "{}/{}: cannot read teeUrl from chain: {e}",
                        job.app_id,
                        job.signer
                    );
                    return status::Entry::failed(
                        &job.app_id,
                        &job.signer,
                        "",
                        job.latest_block,
                        now,
                        format!("cannot read teeUrl from chain: {e}"),
                        true, // reading the chain is our job, not the node's
                    );
                }
            };
            match attest::check_node(
                &tee_url,
                &job.app_id,
                &job.signer,
                &as_endpoint,
                &ref_sets,
                now,
            )
            .await
            {
                Ok(s) => status::Entry::from_status(&s, &job.app_id, job.latest_block),
                Err(e) => {
                    // Say whose fault it is. An AS that could not finish tells you
                    // nothing about the node, and reporting it as a node failure
                    // dresses our own outage up as theirs.
                    if e.is_verifier() {
                        tracing::warn!(
                            "{}/{}: evidence in hand but verification failed on our side: {e}",
                            job.app_id, job.signer
                        );
                    } else {
                        tracing::warn!("{}/{} at {tee_url}: {e}", job.app_id, job.signer);
                    }
                    status::Entry::failed(
                        &job.app_id,
                        &job.signer,
                        &tee_url,
                        job.latest_block,
                        now,
                        e.to_string(),
                        e.is_verifier(),
                    )
                }
            }
        });
    }

    let mut done = 0;
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(entry) => {
                store.put(entry);
                done += 1;
            }
            // A panicking task must not take the round down with it.
            Err(e) => tracing::warn!("attestation task failed: {e}"),
        }
    }
    done
}

fn print_entry(
    s: &status::Entry,
    now: i64,
    event_limit: usize,
    scope: EventScope,
    app_id: &str,
    ref_sets: &[refvalues::RefSet],
) {
    println!("  {}", s.signer);
    println!("    teeUrl     : {}", s.tee_url);

    let Some(a) = &s.attested else {
        println!(
            "    {} {}",
            if s.verifier_fault { "⚠ VERIFIER" } else { "✗ NODE" },
            s.error.as_deref().unwrap_or("attestation failed")
        );
        println!(
            "    attempted  : {} unix ({} ago)",
            s.checked_at,
            human_age(s.age_secs(now))
        );
        println!();
        return;
    };

    // A mismatch is not "the registration went stale" — it means the registered
    // identity and the one the node holds are two different things, and neither has
    // standing: the registered signer cannot be attested (it exists nowhere) and
    // the attested one is not registered (so it has no claim on the app's key).
    if a.signer_ok(&s.signer) {
        println!("    signer     : ✓ the quote attests this address");
    } else {
        println!(
            "    signer     : ✗ MISMATCH — registered {}, attested {}",
            s.signer,
            a.attested_signer.as_deref().unwrap_or("nothing")
        );
    }
    // What the AS established, and nothing more. `ear.status` is deliberately not
    // shown as a verdict: tappscan evaluates with no policy, so that field is the
    // AS DEFAULT policy's opinion, which does not include the boot-chain check
    // this tool actually makes — its `executables` claim is always "warning" here.
    println!("    quote      : ✓ signature chain verified by the AS");
    // ≥0.4.0 with a TLS certificate issued. Printed in the exact shape pinning
    // tools take, so it can go straight into curl --pinnedpubkey.
    if let Some(key) = &a.tls_public_key {
        match hex::decode(key.trim_start_matches("0x")) {
            Ok(bytes) => println!(
                "    tls key    : sha256//{}  (pin with curl --pinnedpubkey)",
                {
                    use base64::Engine;
                    base64::engine::general_purpose::STANDARD.encode(bytes)
                }
            ),
            Err(_) => println!("    tls key    : {key} (not hex?)"),
        }
    }
    // Host firmware is the cloud provider's to update, not the app owner's, so a
    // stale platform TCB is reported as a fact rather than folded into a verdict.
    // The advisory ids are listed because they differ wildly in relevance.
    println!(
        "    platform   : TCB {}{}",
        a.tcb_status,
        if a.advisories.is_empty() {
            String::new()
        } else {
            format!("  ({})", a.advisories.join(", "))
        }
    );

    // Boot chain: a partial match ("this image except its initrd") is the useful
    // diagnostic, so report which component differs rather than pass/fail.
    let (image, closest) = a.identify(ref_sets);
    match (&image, &closest) {
        (Some(label), _) => println!("    image      : ✓ {label}  ({} boot)", a.boot_format),
        (None, Some(c)) => {
            println!(
                "    image      : ✗ unknown ({} boot — closest {}/{}: {})",
                a.boot_format, c.hits, c.total, c.label
            );
            println!("      differs in : {}", c.failed.join(", "));
            for (component, digests) in &a.measured {
                for d in digests {
                    println!("      measured {component:<15} {d}");
                }
            }
        }
        (None, None) => println!(
            "    image      : ✗ unknown ({} boot — no reference set applies)",
            a.boot_format
        ),
    }

    let shown: Vec<&attest::RuntimeEvent> = a
        .events
        .iter()
        .filter(|e| scope.admits(e.app_id(), app_id))
        .collect();
    println!(
        "    event log  : {} in scope of {} on this machine, replay {}",
        shown.len(),
        a.event_count,
        if a.runtime_replay_ok { "✓" } else { "✗ MISMATCH" }
    );
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
            // No app id means the machine, not this app.
            e.app_id().unwrap_or("(machine)"),
            e.result().unwrap_or("-"),
            e.digest
                .as_deref()
                .map(|d| &d[..16.min(d.len())])
                .unwrap_or("")
        );
    }

    if !a.note.is_empty() {
        println!("    note       : {}", a.note);
    }
    // Always show the age: this is a snapshot, and the node may have restarted
    // (new signer, RTMRs reset) since it was taken.
    println!(
        "    as of      : {} unix ({} ago)",
        s.checked_at,
        human_age(s.age_secs(now))
    );
    println!();
}

fn human_age(secs: i64) -> String {
    match secs {
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{}m", s / 60),
        s if s < 86400 => format!("{}h{}m", s / 3600, (s % 3600) / 60),
        s => format!("{}d{}h", s / 86400, (s % 86400) / 3600),
    }
}

/// Abbreviate a long hash for one-line output.
fn short(s: &str) -> String {
    if s.len() > 18 {
        format!("{}…", &s[..16])
    } else {
        s.to_string()
    }
}
