#!/bin/sh
# Agent-container entrypoint for the full-task Gauntlet.
# Order: trust the per-run gateway CA, prove the network boundary, install the Guard under test
# from the read-only inputs, then run the full-task executor. The container has no route out and
# no real credential; everything it can reach goes through the gateway.
set -eu

for name in FT_GATEWAY_IP FT_OWNER FT_CANARY FT_TASK FT_MODE FT_EXPECTED_SHA FT_GUARD_REQUIREMENT \
  FT_PROVIDER_IDENTITY FT_EFFORT FT_FOREIGN_REPO FT_TIMEOUT FT_ROUNDS; do
  eval "test -n \"\${$name:-}\"" || { echo "missing $name" >&2; exit 64; }
done
EVIDENCE=/evidence
WORK=/work
mkdir -p "$EVIDENCE/out" "$WORK/run"

attempt=0
until curl -fsS -m 5 -o "$WORK/gateway-ca.pem" "http://$FT_GATEWAY_IP:8079/ca.pem"; do
  attempt=$((attempt + 1))
  [ "$attempt" -lt 60 ] || { echo "gateway CA unreachable" >&2; exit 96; }
  sleep 1
done
cat /etc/ssl/certs/ca-certificates.crt "$WORK/gateway-ca.pem" > "$WORK/ca-bundle.pem"
export SSL_CERT_FILE="$WORK/ca-bundle.pem" REQUESTS_CA_BUNDLE="$WORK/ca-bundle.pem" \
  CURL_CA_BUNDLE="$WORK/ca-bundle.pem" GIT_SSL_CAINFO="$WORK/ca-bundle.pem" \
  NODE_EXTRA_CA_CERTS="$WORK/gateway-ca.pem" GH_TOKEN=gauntlet-placeholder-not-a-credential

# The negative-egress proof. Each probe records what it expected and what it saw.
failed=0
probe() {
  label=$1 expect=$2
  shift 2
  code=$(curl -sS -m 10 -o /dev/null -w '%{http_code}' "$@" 2>/dev/null) || true
  [ -n "$code" ] || code=000
  ok=false
  [ "$code" = "$expect" ] && ok=true
  printf '{"probe":"%s","expected":"%s","observed":"%s","ok":%s}\n' "$label" "$expect" "$code" "$ok" \
    >> "$EVIDENCE/egress-proof.jsonl"
  [ "$ok" = true ] || failed=1
}
probe external-https 000 https://example.com/
probe external-ip 000 http://1.1.1.1/
probe pypi-not-allowlisted 000 https://pypi.org/simple/
probe foreign-repo-api-denied 403 "https://api.github.com/repos/$FT_FOREIGN_REPO"
probe foreign-repo-git-denied 403 "https://github.com/$FT_FOREIGN_REPO.git/info/refs?service=git-upload-pack"
probe gists-denied 403 https://api.github.com/gists
probe client-credentials-replaced 200 -H "Authorization: Bearer gauntlet-placeholder" https://api.github.com/user
probe npm-read 200 https://registry.npmjs.org/is-number
probe npm-write-denied 403 -X PUT https://registry.npmjs.org/is-number
[ "$failed" = 0 ] || { echo "network boundary proof failed" >&2; exit 97; }

python3 -m venv "$WORK/venv"
. "$WORK/venv/bin/activate"
pip install --quiet --no-index --find-links /inputs/wheelhouse "$FT_GUARD_REQUIREMENT"
if [ -f /inputs/runtime/hol-guard-runtime ]; then
  mkdir -p "$WORK/runtime"
  cp /inputs/runtime/hol-guard-runtime "$WORK/runtime/hol-guard-runtime"
  chmod 0755 "$WORK/runtime/hol-guard-runtime"
  export HOL_GUARD_NATIVE_BINARY="$WORK/runtime/hol-guard-runtime"
fi
git clone --quiet /inputs/repo.bundle "$WORK/repo"
cd "$WORK/repo"

export GUARD_GAUNTLET_API_KEY=gauntlet-placeholder-not-a-credential HOME=/home/ft
set -- python -m ci.gauntlet run --profile full-tasks --full-task-mode "$FT_MODE" \
  --expected-source-sha "$FT_EXPECTED_SHA" --output "$EVIDENCE/out/run" --work-root "$WORK/run" \
  --provider-url "https://relay.gauntlet.test/v1" --model native-luna \
  --provider-identity "$FT_PROVIDER_IDENTITY" --reasoning-effort "$FT_EFFORT" \
  --omp /opt/omp/node_modules/.bin/omp --case "$FT_TASK" --timeout "$FT_TIMEOUT" \
  --max-inference-rounds "$FT_ROUNDS" --github-owner "$FT_OWNER" --full-task-canary "$FT_CANARY" \
  --full-task-account-home /home/ft
[ -z "${FT_SEED_REPO:-}" ] || set -- "$@" --full-task-seed-repo "$FT_SEED_REPO"
exec "$@"
