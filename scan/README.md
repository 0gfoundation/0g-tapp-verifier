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

- **signer binding** — the on-chain signer appears in the quote's report_data.
  This is the load-bearing check: the signer is derived inside the TEE, and only
  the signer registered on chain can obtain the app's KMS key, so everything else
  is a statement about that identity.
- **quote validity** — the AS verified the signature chain to Intel. (Getting a
  token back is the proof; an unverifiable quote is refused, not annotated.)
- **platform TCB** — reported, never used to fail a node. See below.
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

- Every result is **as of** a timestamp — and only that. Evidence carries no
  challenge ([0g-tapp#76](https://github.com/0gfoundation/0g-tapp/issues/76)), so
  it is replayable: "as of" means "when we received a blob claiming this", not
  "when the node was in this state". A node may also have restarted since, which
  re-derives its signer and resets its RTMRs.
- **Platform TCB is reported, never a reason to fail.** Host firmware belongs to
  the cloud provider, not the app's owner, and providers take Intel's updates on
  their own schedule — every node measured so far reports `OutOfDate`, so failing
  on it would paint everything red and carry no signal. It is not nothing either:
  the advisory ids differ widely in how much they bear on TDX isolation, so they
  are listed rather than reduced to a colour.
- **`ear.status` is not shown.** Evaluating with no policy means that field is the
  AS *default* policy's opinion, which does not include the boot-chain check made
  here — its `executables` claim is always "warning" regardless. Beside a real
  verdict it would read as a summary of a check it never performed.
- `teeUrl` is how a verifier finds a node at all — the registry's only pointer to
  where evidence can be fetched. It does not need to be attested, because getting
  it wrong cannot pass silently: a dead or mistyped address yields no evidence, and
  an address serving another instance yields evidence whose signer does not match
  the registration. Several nodes are registered with placeholders (`http://probe:0`)
  or point at hosts that no longer answer, and one at `http://127.0.0.1:50051`.
- A failed check is a **state**, not an absence: "the chain says this node serves
  the app, the node says it has no such app" is worth showing, and is cached so
  every reader does not re-trigger the same failing fetch.
- **Registered and verified are separate columns.** Registration is what actually
  authorises a node — it is how a node obtains the KMS key, and that path carries
  no attestation material at all. Verification is an observation made afterwards.
  Merging them would hide the gap, which is currently wide.

## Running

```bash
# One app's history, from the chain only
tappscan history 0g-kms-dev

# Attest an app's current nodes (serves a cached result while it is fresh)
tappscan check 0g-kms-dev --reference-values ../../0g-tapp/verifier/reference-values

# The deployable form: refresh loop + read-only HTTP on :9090
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
`AttestationEvaluate` and refuses `SetAttestationPolicy`, and tappscan on `:9090`.
The AS is not published directly because it has **no authentication**: anyone who
can reach it can overwrite any policy id, and an EAR token records only which
policy id was used — never a hash of it — so a client cannot detect a swap.

Point `TAPPSCAN_REFVALUES_HOST` at a checkout of
[`0g-tapp`](https://github.com/0gfoundation/0g-tapp)'s `verifier/reference-values`,
and set `TAPPSCAN_AUTHZ_SECRET` to any long random string — the proxy and this
service share it so the authorisation check cannot be probed from outside.

### Writing a policy

Policy writes are the one privileged operation here, and they need a key. Keys are
issued against the registry's **on-chain `admin`** — the authority the chain already
records, rather than a second one invented here — and only a hash of each key is
kept, so `keys.json` is an audit record and not a credential store.

Signed requests follow the convention tapp-server already uses — the message is
`method:args…:unix_timestamp`, signed with personal_sign and accepted inside a
±120s window — so there is no challenge to fetch first.

```bash
MSG="issue_key:ci:90:$(date +%s)"                       # expiry: 30 | 90 | never
SIG=$(cast wallet sign --private-key 0x<admin> "$MSG")

curl -sX POST http://<host>:9090/api/keys \
  -H 'content-type: application/json' \
  -d "{\"message\":\"$MSG\",\"signature\":\"$SIG\"}"     # the key is shown once

# then, wherever a policy is registered:
AS_WRITE_KEY=tsk_… verifier/register-shared-as.sh <cloud> <format> <version> <env>
```

`GET /api/keys` lists every key's metadata (never a hash). Revoking is the same
shape — `revoke_key:<id>:<timestamp>` to `POST /api/keys/revoke` — and bites on the
next request.

A window alone would leave a signature replayable until it expired, which for issuing
would mint duplicate keys, so spent signatures are remembered for the width of the
window. Each signature is therefore good for exactly one key.

## HTTP interface

All reads are served from memory; nothing here can trigger evidence fetching.

| Endpoint | |
|---|---|
| `GET /` | single-page view |
| `GET /api/health` | contract, chain, scanned block, last refresh |
| `GET /api/apps` | every app with its cached attestation state |
| `GET /api/apps/:app_id` | per-signer registration, status and trace size; full event history |
| `GET /api/apps/:app_id/events` | measured runtime log · `signer`, `operation`, `scope`, `limit` |

`scope` selects a slice of the machine's trace: `app` (this app plus the
machine-scoped operations, the default), `others`, or `all`. The trace belongs to
the CVM, not to one app — every app on a machine measures into the same RTMR3, and
operations like `docker_login` or `claim_config` carry no app id, so they are shown
under every app on that machine rather than hidden or arbitrarily assigned.

## The signer is the unit

A signer is re-derived on every tapp restart, so the same address reappearing means
the same running instance — one row, several registration intervals, rather than
several identities. Different signers are never chained into a longer-lived "node":
only `updateNode` records such a link (9 of 63 node events on the live registry),
elsewhere a change is a remove plus an add with nothing tying them together, and
even the explicit link is just the owner asserting one replaces the other. A signer
says nothing about hardware.

Each signer carries a verification status and a trace, whether current or retired.
The one difference is `reverifiable`: a retired signer's RTMRs are gone with its
instance, so whatever was cached while it was live is the only record that will ever
exist. Traces are therefore kept whole, never windowed.

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
