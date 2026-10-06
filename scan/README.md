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

One tappscan process watches one chain (`TAPPSCAN_RPC` / `TAPPSCAN_CONTRACT` /
`TAPPSCAN_FROM_BLOCK`, with their own cache files). The UI's testnet/mainnet
switch expects a second instance for the other network proxied under `/mainnet`
on the same host; the choice travels in `?net=mainnet` so links stay shareable.
The proxy must STRIP the prefix (the server's routes are `/` and `/api/*`) —
nginx does that with a trailing slash on `proxy_pass`:

```nginx
location /mainnet/ { proxy_pass http://tappscan-mainnet:9090/; }
```

Two misconfigurations to avoid: a proxy that does not strip (everything under
`/mainnet` 404s), and publishing the second instance's own port directly — the
page still works there (the network pill follows `/api/health`'s `chain_id`,
not the URL), but prefer one front so links mean one thing.

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

[`as-key.sh`](as-key.sh) does the signing:

```bash
export TAPPSCAN=<host>:9090 ADMIN_KEY=0x<admin>   # or CAST_WALLET_ARGS='--account admin'

scan/as-key.sh issue ci never > /root/as-write-key   # expiry: 30 | 90 | never
scan/as-key.sh list
scan/as-key.sh revoke <key-id>                       # bites on the next request
```

An issued key goes to **stdout and nothing else does**, so it can be moved without
being displayed:

```bash
gh secret set AS_WRITE_KEY -R 0gfoundation/0g-tapp < /root/as-write-key
```

That split is not fastidiousness. A key shown once and then pasted into a terminal
lives on in scrollback, and the copy someone reaches for later is whichever one they
can still see — which is how a revoked key ends up in CI while the live one sits in
a file. Keep the metadata (`issue`'s id and expiry, `list`'s table) and the secret on
separate channels and that cannot happen.

For the same reason a refused write says only 403: `list` shows metadata but never a
hash, and `last_used` records successes only, so a rejected key leaves no trace to
correlate. When CI is refused, reissue rather than guess — and keep exactly one key
active per consumer, so "which key was that" has no answer to get wrong.

A window alone would leave a signature replayable until it expired, which for issuing
would mint duplicate keys, so spent signatures are remembered for the width of the
window. Each signature is therefore good for exactly one key.

## HTTP interface

All reads are served from memory; no read can trigger evidence fetching. The
endpoints that do work on demand are `POST /api/verify` and the two relay
endpoints, bounded as described in their own sections below.

| Endpoint | |
|---|---|
| `GET /` | single-page view |
| `GET /api/health` | contract, chain, scanned block, last refresh |
| `GET /api/apps` | every app with its cached attestation state |
| `GET /api/apps/:app_id` | per-signer registration, status and trace size; full event history |
| `GET /api/apps/:app_id/cert` | the app's attested TLS key as `sha256//<base64>`, text/plain |
| `GET /api/apps/:app_id/events` | measured runtime log · `signer`, `operation`, `scope`, `limit` |
| `POST /api/verify` | attest one `{app_id, signer}` now and return the verdict |
| `GET /api/apps/:app_id/nodes/:signer/evidence` | the node's evidence, fetched now · `nonce` (hex, ≤ 64 bytes) |
| `GET /api/apps/:app_id/nodes/:signer/info` | the node's `GetTappInfo`, fetched now; not attested |

`/cert` is the publish half of the TLS story (tapp-server ≥0.4.0): the quote
commits to sha256 of a TLS public key derived inside the CVM, tappscan does the
expensive attestation once, and any client can then reach a TEE serving the app
with no CA and no verifier of its own:

```bash
curl --pinnedpubkey "$(curl -s https://scan/api/apps/X/cert)" https://node:8443/
```

It answers 404 while no current node attests a key, and 409 — refusing to pick —
if the app's nodes attest different keys, which is an anomaly, not a choice.

`scope` selects a slice of the machine's trace: `app` (this app plus the
machine-scoped operations, the default), `others`, or `all`. The trace belongs to
the CVM, not to one app — every app on a machine measures into the same RTMR3, and
operations like `docker_login` or `claim_config` carry no app id, so they are shown
under every app on that machine rather than hidden or arbitrarily assigned.

## On-demand verification: `POST /api/verify`

The polling loop makes conclusions up to `--interval` + `--max-age` old, and a
tapp node re-derives its signer on **every restart** — so a consumer that gates on
"this signer is verified" (the KMS admitting a freshly rebooted node before
serving its keys) would stall until the next round. `POST /api/verify` moves one
target to the front: fetch its evidence now, verify, answer.

```bash
curl -s -X POST https://scan/api/verify \
  -H 'content-type: application/json' \
  -d '{"app_id": "0g-kms", "signer": "0x…"}'
```

(`/verify` is mounted too, so a consumer configured with a base URL of the bare
host works the same as one ending in `/api`.)

An admission gate needs exactly three things, and they are top-level:
the **HTTP status** (200 = a verdict about the node; **503** = *this service*
could not establish anything — chain RPC or AS trouble — which a consumer must
treat as "verifier unavailable", never as a negative), **`verified`**, and
**`reason`** (empty when verified). `verified` means all of: quote verified and
the registered signer attested, runtime event log replays, the TD runs **without
DEBUG** (a DEBUG TD's memory is open to its host — on bare metal the operator
launches it), the platform TCB is **not revoked**, and the boot chain matches a
**published reference set** — running an image nobody published values for was not
declared, so it does not pass. On **mainnet** a dev set does not count (dev images
can carry an SSH key into the TD); `--accept-dev` / `TAPPSCAN_ACCEPT_DEV` overrides,
and testnet accepts them by default. A node-side failure (unreachable, no such app)
is a 200 with `verified: false` and the error as the reason.

`warnings` lists what passed with a caveat — a TCB trailing Intel's latest
(`OutOfDate`, `SWHardeningNeeded`, …) and its advisories, common on clouds that roll
firmware out behind Intel. `image_env` says whether the matched set is `dev` or
`prod`.

Beside those: `cached` (a fresh attestation, or one inside the cooldown),
`status` — the full per-signer shape `GET /api/apps/:app_id` serves (verdicts,
measurements, TCB, errors, all of it) minus the runtime trace, which stays on
the events endpoint — and `reference_values`, the provenance of the set the
verdict was reached against.

The endpoint is **public**. What keeps that safe is structural, not caller
identity:

1. **Per-target cooldown + single-flight.** A result younger than 60s answers
   repeats as-is, and concurrent requests for one target collapse into one
   attestation. The forcing scenario: a node reboots with a new signer, all five
   KMS nodes notice at once — one quote generation must serve all five, not five
   concurrent ones hitting a node that just came up.
2. **Targets come from the chain, never from the request.** The signer must be a
   CURRENT node of the app on chain, and its teeUrl is read via `getNode` — a
   URL parameter would be an SSRF primitive, so there is none, and unregistered
   targets are refused before any fetch (which also keeps stored negatives
   bounded). A target the cached registry does not know yet forces one chain
   sync (globally rate-limited) before it is refused, because "this signer just
   changed" is exactly when this endpoint gets called.
3. **A global concurrency cap** (`--concurrency`, shared with the refresh loop's
   own fan-out) protects this service, the AS and the nodes. Over capacity is
   `429` + `Retry-After`, not an unbounded queue.

An API key (`Authorization: Bearer` or `x-api-key`, the same keys
[`as-key.sh`](as-key.sh) issues) only selects a bigger request quota — anonymous
callers are metered per IP at 6/min, key holders at 60/min (a KMS node warming
its cache after a restart may need to verify tens of signers quickly). The key
is **not a security boundary**: all authorisation lives in the three limits
above, a stolen key yields nothing but quota, so it may sit in plaintext config
and be rotated freely.

On the per-IP metering: the IP is the **last** hop of `X-Forwarded-For` (what a
standard appending proxy actually saw; everything before it is client-supplied),
falling back to the socket peer. That is honest behind the deployment's nginx
front; a caller who can reach the port directly can still write the header, so
treat the anonymous quota as best-effort — the structural limits above are the
safety story either way.

## Relay: evidence for callers who cannot reach the node

A node's tapp port (`:50052`) is meant to be open only to this service and the
node's operators (0g-tapp#141). Everyone else gets the node's evidence through
here, and verifies it themselves:

```bash
NONCE=0x$(openssl rand -hex 32)
curl -s "https://scan/api/apps/$APP/nodes/$SIGNER/evidence?nonce=$NONCE"
```

The answer carries `evidence` (base64 of the bytes the node sent, untouched),
`tee_type`, the node's `timestamp`, the `nonce` it was fetched with, the
`tee_url` from the chain, and `relayed_at`. Responses are `no-store`.

**Relaying costs no trust; the nonce is what makes that true.** Evidence verifies
itself — the quote is Intel-signed and its `report_data` is `sha512` of the
`runtime_data` beside it, which names the signer. What a relay could still do is
hand back an *old* quote as a new one. With a nonce, the node writes it into
`runtime_data`, so a quote that does not echo yours was not produced for your
request. This service forwards the nonce as given and never answers a relay
request from a cache. Without a nonce the evidence is still genuine, only undated.

`/info` relays `GetTappInfo` — version, owner, KMS cluster, trust anchors. Nothing
in it is attested (`"attested": false`); the facts that matter are also in the
event log, where they are.

Both are bounded like `POST /api/verify`: only a CURRENT node of the app on chain,
its teeUrl read via `getNode` (no URL in the request), the same per-IP / per-key
quota — plus a concurrency cap of their own (half of `--concurrency`), since relay
calls cannot share results and must not starve `/api/verify`. Node calls time out
(8s to connect, 30s per call), and a target that did not answer is answered for
without trying for the next 30s. A node that cannot be reached is `502 node
unreachable`, one that answers with an error `502 node answered with an error`;
the detail goes to this service's log only, because a teeUrl is its registrant's
choice and raw connection errors would let them probe what is reachable from
here. Failing to read the chain is `503`.

## Verifying tappscan itself

Everything above has this instance vouching for other apps. Who vouches for it?
Not itself — a scan consuming its own conclusions would be circular — and not
the chain either. The trust model, explicitly:

```
human review           ← the only step that makes content trustworthy
                         (code → reproducible build → reference hash)
declarations (chain,   ← publication channels; they add no trustworthiness
 this repo)              of their own
TEE + verification     ← proves "what runs == what was declared",
                         never that what was declared is good
```

tappscan's job is to make "runs == declared" machine-checkable for every app, so
that the object a human must review shrinks to one: **this service**. Verify it
the way it verifies others, with your own client and the reference values in
this repository:

```bash
tapp-cli verify-app --app-id <this instance's app_id> --server <its teeUrl> \
  --reference-values ./verifier/reference-values
```

(or fetch the evidence yourself and follow
[`0g-tapp/docs/EVIDENCE_AND_AS_VERIFICATION.md`](https://github.com/0gfoundation/0g-tapp/blob/main/docs/EVIDENCE_AND_AS_VERIFICATION.md)).
A passing check proves this instance runs the measured image and compose this
repository declares — and nothing more. Whether the declared code deserves the
trust is exactly the part no machine can add: it comes from the people who have
reviewed it, which is why every consumer doing this check once is not a
formality but the audit itself. Consumers that pin this instance's attested TLS
key (the KMS does) re-run this verification whenever the instance's identity
rotates, and update their pin only after it passes.

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
