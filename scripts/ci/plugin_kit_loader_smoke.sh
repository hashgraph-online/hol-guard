#!/usr/bin/env bash
# Package the Plugin Kit's Claude Code fixture for every runtime, then load
# each runtime's output with that runtime's own CLI. A deliberately broken copy
# must be rejected, so a validator that silently accepts everything fails here.
#
# Usage: plugin_kit_loader_smoke.sh <validator-bin-dir> <work-dir>
#   validator-bin-dir  folder holding the claude, gemini and codex executables
#   work-dir           empty scratch folder; it becomes HOME for the validators
set -euo pipefail

bin="$(cd "$1" && pwd)"
mkdir -p "$2"
work="$(cd "$2" && pwd)"
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixture="$repo/rust/crates/guard-plugin-kit/tests/fixtures/claude-plugin/input"
package="$work/package"

fail() {
  echo "::error::$1" >&2
  exit 1
}

# Run from rust/ so rust-toolchain.toml picks the pinned toolchain.
(cd "$repo/rust" && cargo run --locked --quiet \
  -p guard-plugin-kit --example package -- "$fixture" "$package" >/dev/null)

# Validators read and write their own config; keep them off the real home.
export HOME="$work/home"
export CODEX_HOME="$work/codex-home"
export NO_COLOR=1
mkdir -p "$HOME" "$CODEX_HOME"

echo "== Claude Code: claude plugin validate"
output="$("$bin/claude" plugin validate "$package/claude-code" 2>&1)" || fail "claude rejected the package: $output"
echo "$output"
if grep -qi "warning" <<<"$output"; then
  fail "claude reported warnings for the package"
fi

echo "== Gemini CLI: gemini extensions validate"
output="$("$bin/gemini" extensions validate "$package/gemini-cli" 2>&1)" || fail "gemini rejected the package: $output"
echo "$output"
grep -q "successfully validated" <<<"$output" || fail "gemini did not confirm the package"

echo "== Codex: install from a local marketplace"
marketplace="$work/codex-marketplace"
mkdir -p "$marketplace/.agents/plugins" "$marketplace/plugins"
cp -R "$package/codex" "$marketplace/plugins/pdf-tools"
cat >"$marketplace/.agents/plugins/marketplace.json" <<'EOF'
{"name":"kit-smoke","plugins":[{"name":"pdf-tools","source":{"source":"local","path":"./plugins/pdf-tools"}}]}
EOF
"$bin/codex" plugin marketplace add "$marketplace"
"$bin/codex" plugin add pdf-tools@kit-smoke
output="$("$bin/codex" plugin list 2>&1)"
echo "$output"
grep -Eq "pdf-tools@kit-smoke +installed, enabled" <<<"$output" || fail "codex did not install the package"

echo "== Broken packages must be rejected"
broken="$work/broken"
cp -R "$package" "$broken"
printf '{"name": "Not A Valid Name", "version": 7}\n' >"$broken/claude-code/.claude-plugin/plugin.json"
if "$bin/claude" plugin validate "$broken/claude-code" >/dev/null 2>&1; then
  fail "claude accepted a broken plugin manifest"
fi
printf '{"version": "1.0.0"}\n' >"$broken/gemini-cli/gemini-extension.json"
if "$bin/gemini" extensions validate "$broken/gemini-cli" >/dev/null 2>&1; then
  fail "gemini accepted a broken extension manifest"
fi

echo "Plugin Kit packages load in Claude Code, Gemini CLI and Codex."
