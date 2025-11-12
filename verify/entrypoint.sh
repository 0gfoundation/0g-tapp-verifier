#!/bin/bash
set -e

echo "========================================="
echo "  Verifier 镜像验证流程"
echo "========================================="

# check input file
QCOW2_IMAGE="${QCOW2_IMAGE:-/opt/verifier/input/confidential.qcow2}"
POLICY_FILE="${POLICY_FILE:-/opt/verifier/input/policy.rego}"
EVIDENCE_FILE="${EVIDENCE_FILE:-/opt/verifier/input/evidence.json}"
POLICY_ID="${POLICY_ID:-tapp}"

# output directory
OUTPUT_DIR="/opt/verifier/output"

echo ""
echo "configuration:"
echo "  - QCOW2 image: $QCOW2_IMAGE"
echo "  - Policy file: $POLICY_FILE"
echo "  - Evidence file: $EVIDENCE_FILE"
echo "  - Policy ID: $POLICY_ID"
echo "  - Output directory: $OUTPUT_DIR"
echo ""

# check file exists
if [ ! -f "$QCOW2_IMAGE" ]; then
    echo "error: QCOW2 image file not found: $QCOW2_IMAGE"
    exit 1
fi

if [ ! -f "$EVIDENCE_FILE" ]; then
    echo "error: Evidence file not found: $EVIDENCE_FILE"
    exit 1
fi

# 1. start trustee service
echo "[1/5] start trustee service..."

# check if the service is running
if systemctl is-active --quiet trustee; then
    echo "✓ trustee service is running"
else
    systemctl start trustee  # use start instead of restart
    sleep 5
    
    if systemctl is-active --quiet trustee; then
        echo "✓ trustee service is started"
    else
        echo "✗ trustee service start failed, check status:"
        systemctl status trustee
        journalctl -xe -u trustee.service | tail -20
        exit 1
    fi
fi

# 2. generate reference value
echo ""
echo "[2/5] generate reference value of confidential image..."
cryptpilot fde show-reference-value \
    --hash-algo sha384 \
    --disk "$QCOW2_IMAGE" \
    > /tmp/reference-value.json

if [ ! -s /tmp/reference-value.json ]; then
    echo "error: failed to generate reference-value.json or it is empty"
    exit 1
fi
echo "✓ Reference value is generated"

# 3. register reference value
echo ""
echo "[3/5] register reference value..."
provenance=$(cat /tmp/reference-value.json | base64 --wrap=0)

inner_json=$(cat << EOF
{ "version" : "0.1.0", "type": "sample", "payload": "$provenance" }
EOF
)

echo "$inner_json" | jq -R -s '{"message": .}' > /tmp/rvps.json

response=$(curl -s -w "\n%{http_code}" -X POST http://localhost:8081/api/rvps/register \
    -H 'Content-Type: application/json' \
    -d @/tmp/rvps.json)

http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | sed '$d')

if [ "$http_code" != "200" ]; then
    echo "error: failed to register reference value (HTTP $http_code)"
    echo "$body"
    exit 1
fi
echo "✓ Reference value is registered"

# 4. register policy
echo ""
echo "[4/5] register policy..."

if [ -f "$POLICY_FILE" ]; then
    echo "use custom policy file: $POLICY_FILE"
    POLICY_BASENAME=$(basename "$POLICY_FILE" .rego)
    TARGET_POLICY="/opt/trustee/attestation-service/policies/opa/${POLICY_ID}.rego"
    cp "$POLICY_FILE" "$TARGET_POLICY"
    echo "✓ Policy is registered (ID: ${POLICY_ID})"
else
    echo "warning: policy file not found: $POLICY_FILE"
    echo "⚠ skip policy registration"
fi

# 5. verify evidence
echo ""
echo "[5/5] verify evidence..."

# check if the script exists
VERIFY_SCRIPT="/opt/verifier/input/verify_evidence.py"
if [ ! -f "$VERIFY_SCRIPT" ]; then
    echo "error: verify script not found: $VERIFY_SCRIPT"
    echo "please ensure the script is mapped to the container's /opt/verifier/input/ directory"
    exit 1
fi

cd /opt/verifier
cp "$EVIDENCE_FILE" evidence.json

# run the verify script
if [ "$FULL_AUDIT_REPORT" = "true" ]; then
    python3 "$VERIFY_SCRIPT" -v | tee "$OUTPUT_DIR/verification_result.txt"
else
    python3 "$VERIFY_SCRIPT" | tee "$OUTPUT_DIR/verification_result.txt"
fi
verification_exit_code=${PIPESTATUS[0]}

# copy output files
if [ -f "jwt_token.txt" ]; then
    cp jwt_token.txt "$OUTPUT_DIR/"
fi

if [ -f "jwt_payload.json" ]; then
    cp jwt_payload.json "$OUTPUT_DIR/"
fi

echo ""
echo "========================================="
if [ $verification_exit_code -eq 0 ]; then
    echo "✓ verification completed, results are saved to: $OUTPUT_DIR"
    echo "  - verification_result.txt"
    echo "  - jwt_token.txt"
    echo "  - jwt_payload.json"
    echo "========================================="
    exit 0
else
    echo "✗ verification failed"
    echo "========================================="
    exit 1
fi