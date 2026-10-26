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
if [ "$mode" != "live" ]; then
  spec="$work/install-spec.json"
  cat >"$spec" <<EOF
{"schema":"hol.plugin-install-spec.v1","slug":"$slug","name":"hol-guard-plugin","version":null,
 "repository":"$slug","listingUrl":"https://hol.org/registry/plugins/hashgraph-online%2Fhol-guard-plugin",
 "trustScore":null,"targets":[
  {"runtime":"claude-code","marketplace":{"repository":"$slug","name":"hol-guard"},"plugin":"hol-guard"},
  {"runtime":"codex","marketplace":{"repository":"$slug","name":"hol-guard"},"plugin":"hol-guard"},
  {"runtime":"agent-skills","repository":"$slug"}],"manual":[]}
EOF
  source_args=(--spec-file "$spec")
fi

echo "== Plan only: nothing changes"
"$guard" plugin install "$slug" ${source_args[@]+"${source_args[@]}"} --runtime claude-code,codex
[ ! -e "$ledger" ] || fail "a plan wrote Guard's install list"

echo "== Install into Claude Code and Codex"
"$guard" plugin install "$slug" ${source_args[@]+"${source_args[@]}"} --runtime claude-code,codex --apply --yes

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
