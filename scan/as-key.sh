#!/usr/bin/env bash
# =============================================================================
# Issue / list / revoke tappscan API keys.
# =============================================================================
# These are the bearer keys for the one privileged operation on a hosted AS:
# SetAttestationPolicy. Everything else there is public — evidence and tokens are
# verifiable by anyone, so only the write needs gating.
#
# The authority is the registry's ON-CHAIN admin, not a second credential invented
# for this service: a request is a personal_sign over `<method>:<args…>:<unix_ts>`,
# accepted inside a ±120s window and remembered as spent, so each signature is
# good for exactly one call. Nothing to fetch first, nothing to keep in sync.
#
# Usage:
#   ./as-key.sh issue  <label> <30|90|never>
#   ./as-key.sh list
#   ./as-key.sh revoke <key-id>
#
# An issued key goes to STDOUT and NOTHING else does, so it can be captured
# without ever landing in a log or a terminal scrollback:
#
#   AS_WRITE_KEY=$(scan/as-key.sh issue ci 90) \
#     ../0g-tapp/verifier/register-shared-as.sh gcp uki v0.3.0-r2 dev <as-host>:50004
#
# Only a hash of the key is kept server-side, so a lost key is reissued, never
# recovered — and `list` can show metadata but never the secret.
#
# Env:
#   ADMIN_KEY  admin private key (0x + 64 hex). Omit to sign with a keystore or a
#              hardware wallet instead, through CAST_WALLET_ARGS (e.g.
#              CAST_WALLET_ARGS='--account admin', or '--ledger').
#   TAPPSCAN   host:port of the scan service (default 34.171.164.181:9090)
#
# Prereqs: cast (foundry), curl, python3.
# =============================================================================
set -euo pipefail

TAPPSCAN="${TAPPSCAN:-34.171.164.181:9090}"
U="usage: as-key.sh issue <label> <30|90|never> | list | revoke <key-id>"

# Human-readable output goes to stderr throughout, so stdout carries only the
# thing a caller wants to capture.
say() { printf '%s\n' "$*" >&2; }

sign() {
	if [ -n "${ADMIN_KEY:-}" ]; then
		cast wallet sign --private-key "$ADMIN_KEY" "$1"
	elif [ -n "${CAST_WALLET_ARGS:-}" ]; then
		# Unquoted on purpose: this is a caller-supplied argument list.
		cast wallet sign ${CAST_WALLET_ARGS} "$1"
	else
		say "error: set ADMIN_KEY=0x… , or CAST_WALLET_ARGS='--account <name>' to use a keystore"
		exit 1
	fi
}

# req <path> [message] → "<status>\n<body>" on stdout. With a message, signs it and
# POSTs {message, signature}; without, GETs.
#
# The status leads rather than follows because callers run this in a command
# substitution — a subshell, so it cannot hand anything back in a variable.
req() {
	local out
	if [ -n "${2:-}" ]; then
		local sig
		sig=$(sign "$2")
		out=$(python3 -c 'import json,sys; print(json.dumps({"message":sys.argv[1],"signature":sys.argv[2]}))' "$2" "$sig" |
			curl -sS --max-time 30 -X POST "http://${TAPPSCAN}$1" \
				-H 'content-type: application/json' -d @- -w '\n%{http_code}')
	else
		out=$(curl -sS --max-time 30 "http://${TAPPSCAN}$1" -w '\n%{http_code}')
	fi
	printf '%s\n%s' "${out##*$'\n'}" "${out%$'\n'*}"
}

# body <response> → the body alone. A response with no newline is a bodiless
# status, not a body that happens to look like "200".
body() {
	case "$1" in
	*$'\n'*) printf '%s' "${1#*$'\n'}" ;;
	*) printf '' ;;
	esac
}

# Fail loudly on anything but 2xx — a refused write must never look like a no-op.
# Revoking answers 204, so matching 200 exactly would report a success as an error.
check() {
	case "${1%%$'\n'*}" in 2??) return 0 ;; esac
	say "error: HTTP ${1%%$'\n'*} from ${TAPPSCAN}"
	printf '%s\n' "$(body "$1")" >&2
	exit 1
}

case "${1:-}" in
issue)
	LABEL="${2:?$U}"
	TTL="${3:?$U}"
	case "$TTL" in 30 | 90 | never) ;; *)
		say "error: expiry must be 30, 90 or never (got '$TTL')"
		exit 1
		;;
	esac
	# The server splits the signed message on ':', so a colon in the label would
	# shift every later field — it would parse a different request than was signed.
	case "$LABEL" in *:*)
		say "error: label must not contain ':'"
		exit 1
		;;
	esac

	RESP=$(req /api/keys "issue_key:${LABEL}:${TTL}:$(date +%s)")
	check "$RESP"
	# Split deliberately: metadata to stderr, secret to stdout, never both together.
	body "$RESP" | python3 -c '
import json, sys, time
d = json.load(sys.stdin)
exp = d.get("expires_at")
when = time.strftime("%Y-%m-%d", time.localtime(exp)) if exp else "never"
print(f'"'"'issued {d["id"]}  label={d.get("label")}  expires={when}'"'"', file=sys.stderr)
print("the key is on stdout only — capture it; it is stored here as a hash and cannot be shown again", file=sys.stderr)
print(d["key"])
'
	;;

list)
	RESP=$(req /api/keys)
	check "$RESP"
	body "$RESP" | python3 -c '
import json, sys, time
d = json.load(sys.stdin)
print("keys issued against admin", d.get("admin"), file=sys.stderr)
ks = d.get("keys") or []
if not ks:
    print("none yet"); sys.exit()
now = time.time()
for k in ks:
    exp = k.get("expires_at")
    state = "revoked" if k.get("revoked_at") else \
            "EXPIRED" if exp and exp < now else "active"
    when = time.strftime("%Y-%m-%d", time.localtime(exp)) if exp else "never"
    used = time.strftime("%m-%d %H:%M", time.localtime(k["last_used_at"])) if k.get("last_used_at") else "never used"
    print(f'"'"'{k["id"]:12} {state:8} expires {when:11} {used:12} {k.get("label","")}'"'"')
'
	;;

revoke)
	ID="${2:?$U}"
	RESP=$(req /api/keys/revoke "revoke_key:${ID}:$(date +%s)")
	check "$RESP"
	say "revoked ${ID} — it stops working on the next request"
	;;

*)
	say "$U"
	exit 1
	;;
esac
