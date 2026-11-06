#!/usr/bin/env bash
# Run one gh command, retrying it only when GitHub answers with a rate limit.
#
# gh does not surface response headers on failure, so a primary limit waits
# for the reset that /rate_limit reports (the x-ratelimit-reset value; that
# endpoint costs no quota). A secondary limit, which carries no reset, backs off
# exponentially from one minute as GitHub documents. Every other failure, and
# the last rate-limited attempt, returns gh's own output and exit status.
# Standard input is not replayed, so callers must not pipe a request body in.
set -uo pipefail

real_gh=${GH_RETRY_REAL_GH:-gh}
max_attempts=${GH_RETRY_MAX_ATTEMPTS:-6}
max_wait=${GH_RETRY_MAX_WAIT_SECONDS:-3900}
base_delay=${GH_RETRY_BASE_DELAY_SECONDS:-60}
max_backoff=${GH_RETRY_MAX_BACKOFF_SECONDS:-900}
rate_limited='rate limit (already )?exceeded|exceeded a secondary rate limit|HTTP 429'

out=$(mktemp)
err=$(mktemp)
trap 'rm -f "$out" "$err"' EXIT

finish() {
  cat "$out"
  cat "$err" >&2
  exit "$1"
}

seconds_until_reset() {
  local reset
  reset=$("$real_gh" api rate_limit \
    --jq '[.resources.core, .resources.graphql] | map(select(.remaining == 0) | .reset) | max // empty' \
    2>/dev/null) || return 1
  [[ "$reset" =~ ^[0-9]+$ ]] || return 1
  echo $((reset - $(date +%s) + 1))
}

attempt=1
waited=0
while :; do
  "$real_gh" "$@" >"$out" 2>"$err"
  status=$?
  if [[ "$status" -eq 0 ]] || ! grep -Eqi "$rate_limited" "$err"; then
    finish "$status"
  fi
  if [[ "$attempt" -ge "$max_attempts" ]]; then
    echo "gh-retry: still rate limited after ${attempt} attempts" >&2
    finish "$status"
  fi
  if delay=$(seconds_until_reset); then
    kind=primary
  else
    kind=secondary
    delay=$((base_delay * (1 << (attempt - 1))))
    if [[ "$delay" -gt "$max_backoff" ]]; then
      delay=$max_backoff
    fi
  fi
  if [[ "$delay" -lt 1 ]]; then
    delay=1
  fi
  if [[ $((waited + delay)) -gt "$max_wait" ]]; then
    echo "gh-retry: ${kind} rate limit needs ${delay}s, beyond the ${max_wait}s retry budget" >&2
    finish "$status"
  fi
  echo "gh-retry: ${kind} rate limit on attempt ${attempt}/${max_attempts}; retrying in ${delay}s" >&2
  sleep "$delay"
  waited=$((waited + delay))
  attempt=$((attempt + 1))
done
