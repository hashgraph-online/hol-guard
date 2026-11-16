#!/bin/bash
# lang_setup.sh: fetch and pin the language set's repos under $CIGAR_GAUNTLET_WORK/lang (Go, Rust, TypeScript).
# Needs go, cargo (rustup) and node/npm on PATH. Each repo gets a <repo>-bin/bin folder with python
# (a venv; the rig's shell check looks for it) and links to the language's tools.
set -euo pipefail
W=${CIGAR_GAUNTLET_WORK:-/tmp/cigar-gauntlet}
L="$W/lang"; mkdir -p "$L" "$L/sbx"
PATH=$(echo "$PATH" | tr ':' '\n' | grep -v package-shims | paste -sd: -)
# The same identity run.py writes, so setup can commit on a fresh rig.
[ -f "$W/gitconfig" ] || printf '[user]\n\tname = dev\n\temail = dev@example.test\n' > "$W/gitconfig"
rig_git() { GIT_CONFIG_GLOBAL="$W/gitconfig" git -c commit.gpgsign=false -c core.hooksPath=/dev/null "$@"; }
fetch() { # name url tag
  [ -d "$L/$1" ] || git clone -q --depth 1 --branch "$3" "$2" "$L/$1"
  printf 'target/\n.gocache/\npackage-lock.json\n' >> "$L/$1/.git/info/exclude"
}
tools() { # name tool...
  local name=$1; shift
  [ -x "$L/$name-bin/bin/python" ] || python3 -m venv "$L/$name-bin"
  for t in "$@"; do ln -sf "$(command -v "$t")" "$L/$name-bin/bin/$t"; done
}
fetch mux https://github.com/gorilla/mux.git v1.8.1
# The agent's sandbox cannot open a listening socket; this file's tests start an HTTP server.
if [ -f "$L/mux/mux_httpserver_test.go" ]; then
  rig_git -C "$L/mux" rm -q mux_httpserver_test.go
  rig_git -C "$L/mux" commit -qm "rig: drop test that needs a listening socket"
fi
tools mux go gofmt
fetch semver https://github.com/dtolnay/semver.git 1.0.23
tools semver cargo rustc rustfmt
fetch ufo https://github.com/unjs/ufo.git v1.6.1
(cd "$L/ufo" && npm install --ignore-scripts --no-audit --no-fund -q)
tools ufo node
# npm and npx from the same install as node, not a package manager's shim earlier on PATH.
node_dir=$(dirname "$(command -v node)")
ln -sf "$node_dir/npm" "$L/ufo-bin/bin/npm"; ln -sf "$node_dir/npx" "$L/ufo-bin/bin/npx"
echo "language repos ready in $L"
