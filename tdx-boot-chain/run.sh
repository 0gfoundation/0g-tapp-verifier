#!/usr/bin/env bash
# =============================================================================
# TDX confidential VM boot-chain verifier (gRPC CoCo-AS) — one-shot automation
# =============================================================================
# Brings up a local trustee (coco-as-grpc :50004 + rvps :50003), registers the
# reference values + policy, and evaluates a node's TDX evidence against them.
#
# Usage:
#   ./run.sh <evidence.hex>
#     <evidence.hex>: file containing the hex evidence string, e.g. from
#       tapp-cli -s http://<node>:50051 get-evidence --app-id <id> \
#         | grep -o 'Evidence (hex): [0-9a-f]*' | sed 's/Evidence (hex): //'
#
# Env:
#   POLICY_ID   policy id (default: 0g-tapp)   — registered as <POLICY_ID>_cpu
#
# Prereqs (host): docker + docker compose, grpcurl, openssl, python3
# Reference values: edit reference-values.json for the target release image.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

POLICY_ID="${POLICY_ID:-0g-tapp}"
AS=127.0.0.1:50004
RVPS=127.0.0.1:50003
EVIDENCE_HEX="${1:-evidence.hex}"

[ -f "$EVIDENCE_HEX" ] || { echo "error: evidence hex file not found: $EVIDENCE_HEX"; exit 1; }

# 1. token signing key for the AS (self-signed; EAR payload is decoded, not signature-verified here)
if [ ! -f keys/token.key ]; then
  mkdir -p keys
  openssl ecparam -name prime256v1 -genkey -noout -out keys/token.key
  openssl req -new -x509 -key keys/token.key -out keys/token-cert-chain.pem -days 3650 -subj "/CN=local-as"
  echo "[keys] generated token signing key"
fi

# 2. bring up the local trustee (coco-as-grpc + rvps)
echo "[up] starting local trustee (coco-as-grpc :50004 + rvps :50003)..."
docker compose up -d
# wait for both ports
for p in 50003 50004; do
  for _ in $(seq 1 30); do
    (echo > "/dev/tcp/127.0.0.1/$p") 2>/dev/null && break
    sleep 1
  done
done
sleep 2

# 3. register reference values to RVPS (sample provenance)
echo "[rvps] registering reference-values.json..."
PAYLOAD=$(base64 -w0 reference-values.json)
MSG=$(python3 -c 'import json,sys; print(json.dumps({"message": json.dumps({"version":"0.1.0","type":"sample","payload":sys.argv[1]})}))' "$PAYLOAD")
grpcurl -plaintext -import-path . -proto reference.proto -d "$MSG" \
  "$RVPS" reference.ReferenceValueProviderService/RegisterReferenceValue >/dev/null
echo "[rvps] done"

# 4. register policy as <POLICY_ID>_cpu (AS appends the _cpu device-class suffix)
echo "[policy] registering ${POLICY_ID}_cpu..."
POLICY_B64=$(base64 -w0 policy.rego | tr '+/' '-_' | tr -d '=')
python3 -c 'import json,sys; print(json.dumps({"policy_id":sys.argv[1],"policy":sys.argv[2]}))' \
  "${POLICY_ID}_cpu" "$POLICY_B64" > /tmp/setp.$$.json
grpcurl -plaintext -import-path . -proto attestation.proto -d @ \
  "$AS" attestation.AttestationService/SetAttestationPolicy < /tmp/setp.$$.json >/dev/null
rm -f /tmp/setp.$$.json
echo "[policy] done"

# 5. evaluate evidence and report
echo "[verify] evaluating evidence with policy_ids=[${POLICY_ID}]..."
python3 - "$EVIDENCE_HEX" "$POLICY_ID" "$AS" <<'PY'
import sys, json, base64, binascii, subprocess, re
hexfile, policy_id, as_ep = sys.argv[1], sys.argv[2], sys.argv[3]
raw = binascii.unhexlify(open(hexfile).read().strip())
req = {"verification_requests": [{"tee": "tdx", "evidence": base64.urlsafe_b64encode(raw).rstrip(b'=').decode()}],
       "policy_ids": [policy_id]}
out = subprocess.run(
    f"grpcurl -plaintext -import-path . -proto attestation.proto -d @ {as_ep} "
    "attestation.AttestationService/AttestationEvaluate",
    shell=True, input=json.dumps(req), capture_output=True, text=True)
m = re.search(r'"attestationToken":\s*"([^"]+)"', out.stdout)
if not m:
    print("FAILED:", (out.stdout + out.stderr)[:400]); sys.exit(1)
tok = m.group(1).split('.')[1]; tok += '=' * (-len(tok) % 4)
sm = json.loads(base64.urlsafe_b64decode(tok))["submods"]["cpu0"]
tv = sm.get("ear.trustworthiness-vector", {})
ex = tv.get("executables")
tdx = sm.get("ear.veraison.annotated-evidence", {}).get("tdx", {})
print(f"  ear.status   : {sm.get('ear.status')}")
print(f"  tcb_status   : {tdx.get('tcb_status')}")
print(f"  boot-chain   : {'PASS (executables=3)' if ex == 3 else f'FAIL (executables={ex})'}")
PY
