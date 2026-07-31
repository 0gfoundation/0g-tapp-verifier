# tappscan — TappRegistry explorer (trust layer 3)

Enumerates every app in the on-chain TappRegistry, reconstructs each one's update
history, and shows the attestation state of the hardware identities currently
serving it.

## Where this sits

The three layers differ in **who tells you a node is trustworthy**, not in what
gets checked:

| Layer | You verify with | You additionally trust |
|---|---|---|
| 1 | your own trustee ([`../tdx-boot-chain`](../tdx-boot-chain)) | Intel, and the reference values you loaded |
| 2 | someone else's AS — `tapp-cli verify-app` | that AS and its policy registry |
| 3 | **this** — read a cached result | whoever runs this instance |

A separate question, on its own axis, is *what a reference digest means* — that
is what image auditing ([`../verify`](../verify), [`../audit`](../audit)) and
reproducible builds answer. Neither axis substitutes for the other: you can run
your own trustee and still have no idea what is inside the image it approves.

Layer 3 exists because attestation is expensive to read. A node's evidence is
several megabytes and grows with every measured operation — RTMR3 only ever
appends — so having every viewer re-fetch and re-submit it does not scale. This
service does it once and serves the result, with the time it was taken.

## What it establishes

For each node signer an app has on chain:

- **signer binding** — the on-chain signer appears in the quote's report_data,
  which is what ties a piece of hardware to the app's registration
- **quote validity and platform state** — from the AS: signature chain to Intel,
  `ear.status`, TCB status, advisories
- **which CVM image booted** — measured boot-chain digests compared against the
  published reference values, reported per component
- **the measured runtime log** — every `start_app`, `stop_app`,
  `get_app_secret_key`, `claim_config`, … extended into RTMR3, with the AS's own
  replay result for each

The AS is deliberately called with **no policy**. It does what only it can do —
verify the quote and replay the event log against the signed RTMRs — while the
boot-chain comparison happens here. That means:

- no policy to register per image × cloud × environment, and no guessing which
  policy id to evaluate against;
- the verdict is a pure function of the signed token plus public files in git, so
  anyone can recompute it rather than trusting that a policy on our AS returned
  `executables=3`;
- **per-component results.** A policy answers pass/fail; this reports "this image
  except its initrd", which is what you actually need. That distinction found a
  wrong published `initrd` digest on first contact with real nodes.

## Reading the output honestly

- Every result is **as of** a timestamp. A node may have restarted since, which
  derives a new signer and resets its RTMRs.
- `teeUrl` is supplied by whoever registered the node and is **not attested**. Some
  registered nodes carry placeholder URLs (`http://probe:0`) or point at hosts
  that no longer answer; one is registered as `http://127.0.0.1:50051`, which
  resolves to the verifier's own machine.
- A failed check is a **state**, not an absence: "the chain says this node serves
  the app, the node says it has no such app" is worth showing.
- `ear.status` aggregates several claims. A stale platform TCB alone makes it
  non-affirming even when the boot chain matches, so boot chain and platform state
  are reported separately.
- Only a recent window of each event log is cached. Responses say how many entries
  exist on the node versus how many are shown.

## Running

```bash
# One app's history, from the chain only
tappscan history 0g-kms-dev

# Attest an app's current nodes (serves a cached result while it is fresh)
tappscan check 0g-kms-dev --reference-values ../../0g-tapp/verifier/reference-values

# The deployable form: refresh loop + read-only HTTP on :8088
tappscan serve --reference-values ../../0g-tapp/verifier/reference-values
```

Re-attestation is triggered by the **chain**: a new registry event for an app is
the signal that something may have changed. `--max-age` (default 1h) is only a
backstop for what the chain cannot see, such as a node restarting on its own.

### Deployment

```bash
docker compose -f scan/docker-compose.yml up -d --build    # from the repo root
```

Brings up `rvps` + `as` on an internal network only, an nginx front that allows
`AttestationEvaluate` and refuses `SetAttestationPolicy`, and tappscan on `:8088`.
The AS is not published directly because it has **no authentication**: anyone who
can reach it can overwrite any policy id, and an EAR token records only which
policy id was used — never a hash of it — so a client cannot detect a swap.

Point `TAPPSCAN_REFVALUES_HOST` at a checkout of
[`0g-tapp`](https://github.com/0gfoundation/0g-tapp)'s `verifier/reference-values`.

## HTTP interface

All reads are served from memory; nothing here can trigger evidence fetching.

| Endpoint | |
|---|---|
| `GET /` | single-page view |
| `GET /api/health` | contract, chain, scanned block, last refresh |
| `GET /api/apps` | every app with its cached attestation state |
| `GET /api/apps/:app_id` | identity epochs, full history, per-node status |
| `GET /api/apps/:app_id/events` | measured runtime log · `signer`, `operation`, `this_app_only`, `limit` |

## Notes on the chain scan

Two things are not obvious:

- `string indexed appId` stores only `keccak256(appId)` in the log topic, so app
  names are not in the logs. They are recovered from the calldata of an emitting
  transaction and accepted only when the keccak matches.
- Transactions are read out of their **block**, not by hash: the 0G public RPC
  answers `eth_getTransactionByHash` with null for transactions it returns
  happily inside `eth_getBlockByNumber(_, true)`. Going via blocks took app-name
  recovery from 13/25 to 25/25.

`eth_getLogs` ranges split recursively on errors *and* on suspiciously full
responses, because some providers cap results silently instead of erroring.

## Keeping the boot-chain rules in step

Which event is the kernel, which is the shim, and so on is decided in
[`attest.rs`](src/attest.rs) using the same rules as
[`../tdx-boot-chain/policy.rego`](../tdx-boot-chain/policy.rego). Here those rules
*are* the security check rather than a routing hint, so the two must not drift.
