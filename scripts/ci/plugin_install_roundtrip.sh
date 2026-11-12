#!/usr/bin/env bash
# Install a HOL listing into Claude Code and Codex with
# `hol-guard plugin install --apply`, check that each runtime lists it, then
# uninstall and check that both runtimes and Guard's install list are clean.
#
# Usage: plugin_install_roundtrip.sh <runtime-bin-dir> <work-dir> [live]
#   runtime-bin-dir  folder holding the claude and codex executables
#   work-dir         empty scratch folder; it becomes HOME for the runtimes
#   live             read the install spec from hol.org instead of the fixture
#
# HOL_GUARD names the hol-guard executable under test (default: hol-guard).
set -euo pipefail

bin="$(cd "$1" && pwd)"
mkdir -p "$2"
work="$(cd "$2" && pwd)"
mode="${3:-fixture}"
guard="${HOL_GUARD:-hol-guard}"
slug="hashgraph-online/hol-guard-plugin"
plugin="hol-guard@hol-guard"

fail() {
  echo "::error::$1" >&2
  exit 1
}

# Runtimes read and write their own config; keep them off the real home.
export HOME="$work/home"
export CODEX_HOME="$work/codex-home"
export NO_COLOR=1
export PATH="$bin:$PATH"
mkdir -p "$HOME" "$CODEX_HOME"
ledger="$HOME/.hol-guard/plugin-kit/installs.json"

source_args=()
risk_args=()
if [ "$mode" != "live" ]; then
  # The fixture is what hol.org serves for a scanned listing: a passing scan
  # tied to the commit both runtimes are pinned to.
  ref="$(git ls-remote "https://github.com/$slug" HEAD | cut -f1)"
  [[ "$ref" =~ ^[0-9a-f]{40}$ ]] || fail "could not read the head commit of $slug"
  listing="https://hol.org/registry/plugins/hashgraph-online%2Fhol-guard-plugin"
  spec="$work/install-spec.json"
  cat >"$spec" <<EOF
{"schema":"hol.plugin-install-spec.v2","slug":"$slug","name":"hol-guard-plugin","version":null,
 "repository":"$slug","listingUrl":"$listing","trustScore":null,"installable":true,
 "security":{"verdict":"pass","scannedAt":"$(date -u +%Y-%m-%dT00:00:00Z)","scannedRef":"$ref",
  "findings":{"critical":0,"high":0,"medium":0,"low":0},"reasons":[],"reportUrl":"$listing"},
 "targets":[
  {"runtime":"claude-code","marketplace":{"repository":"$slug","name":"hol-guard","ref":"$ref"},"plugin":"hol-guard"},
  {"runtime":"codex","marketplace":{"repository":"$slug","name":"hol-guard","ref":"$ref"},"plugin":"hol-guard"},
  {"runtime":"agent-skills","repository":"$slug"}],"manual":[]}
EOF
  source_args=(--spec-file "$spec")
else
  # The canary checks install mechanics against whatever HOL's scan says today,
  # so it accepts a warning. A blocked listing still stops it.
  risk_args=(--accept-risk)
fi

echo "== Plan only: nothing changes"
"$guard" plugin install "$slug" ${source_args[@]+"${source_args[@]}"} --runtime claude-code,codex
[ ! -e "$ledger" ] || fail "a plan wrote Guard's install list"

echo "== Install into Claude Code and Codex"
"$guard" plugin install "$slug" ${source_args[@]+"${source_args[@]}"} --runtime claude-code,codex --apply --yes ${risk_args[@]+"${risk_args[@]}"}

output="$(claude plugin list 2>&1)"
echo "$output"
grep -q "$plugin" <<<"$output" || fail "claude does not list $plugin after install"
output="$(codex plugin list 2>&1)"
echo "$output"
grep -Eq "$plugin +installed, enabled" <<<"$output" || fail "codex does not list $plugin as installed"
grep -q '"claude-code"' "$ledger" && grep -q '"codex"' "$ledger" || fail "Guard's install list misses a runtime"

echo "== Uninstall"
# Uninstall plans from Guard's install list, never from HOL.
"$guard" plugin uninstall "$slug" --apply --yes

output="$(claude plugin list 2>&1)"
echo "$output"
if grep -q "$plugin" <<<"$output"; then
  fail "claude still lists $plugin after uninstall"
fi
output="$(codex plugin list 2>&1)"
echo "$output"
if grep -Eq "$plugin +installed" <<<"$output"; then
  fail "codex still lists $plugin as installed"
fi
jq -e '.schema == "hol.plugin-kit.installs.v1" and .installs == {}' "$ledger" >/dev/null ||
  fail "Guard's install list is not empty after uninstall"

echo "hol-guard plugin install and uninstall round-trip in Claude Code and Codex."
