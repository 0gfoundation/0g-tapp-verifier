# GCP TDX boot-chain verifier (gRPC CoCo-AS)

Self-hosted, automated verification that a GCP confidential VM (Intel TDX) node's
boot chain matches a known-good image. Brings up a local trustee (the same
`coco-as-grpc` + `rvps` stack as the shared AS), registers the reference values and the
policy, and evaluates a node's evidence.

> This is the GCP/gRPC flow. The original Aliyun/cryptpilot RESTful flow under `verify/`
> is unchanged.

## What it checks

Five boot-chain measurements from the TDX evidence's `uefi_event_logs` (RTMR0-2):
shim, grub, kernel, initrd, kernel_cmdline. rootfs integrity is folded into the initrd,
so it is not checked separately. See `policy.rego` for field formats and matching.

## Files

| File | Purpose |
|---|---|
| `docker-compose.yml` | local trustee: `coco-as-grpc` :50004 + `rvps` :50003 |
| `as-config.json` / `rvps.json` | AS / RVPS config (AS → RVPS at `http://rvps:50003`) |
| `policy.rego` | boot-chain policy; reads reference values via `query_reference_value()` (RVPS), embedded fallback |
| `reference-values.json` | the 5 reference digests for the target image (edit per release) |
| `attestation.proto` / `reference.proto` | gRPC protos for AS / RVPS |
| `run.sh` | one-shot: keys → compose up → register RVPS + policy → evaluate |

## Usage

Prereqs (host): docker + docker compose, grpcurl, openssl, python3.

```bash
# 1. Set the reference values for your target image
$EDITOR reference-values.json     # the 5 measurement.* digests

# 2. Get a node's evidence (hex)
tapp-cli -s http://<node>:50051 get-evidence --app-id <id> \
  | grep -o 'Evidence (hex): [0-9a-f]*' | sed 's/Evidence (hex): //' > evidence.hex

# 3. Run
./run.sh evidence.hex
```

Output:

```
  ear.status   : affirming | warning | contraindicated
  tcb_status   : UpToDate | OutOfDate | ...
  boot-chain   : PASS (executables=3)   # the 5 measurements matched the reference values
```

`boot-chain PASS` means the node's shim/grub/kernel/initrd/kernel_cmdline matched the
reference values. `ear.status` also reflects platform TCB — `OutOfDate` keeps the overall
status non-affirming even when the boot chain passes (update the platform TCB to clear it).

## Notes

- Policy is registered as `<POLICY_ID>_cpu` — the AS appends the `_cpu` device-class suffix
  (evaluate with `policy_ids=[<POLICY_ID>]`). Default `POLICY_ID=0g-tapp`.
- `keys/`, `*-data/`, `evidence.*` are generated at runtime and gitignored.
- Same `policy.rego` is used against the shared remote AS; there RVPS isn't writable, so
  the policy's embedded fallback values are used instead of `query_reference_value()`.
- The AS token signing key is self-signed locally; this flow decodes the EAR payload and
  does not verify the token signature (the AS already verified the quote).
