#!/bin/bash
# linux_p95.sh <hol-guard Linux wheel> <base.json from mixed.py --save> <out dir> [platform]
# Note build time on Linux: builds a small rig inside a throwaway container (the given Guard
# wheel, the four repos the mixed set uses), then replays the mixed prompts one at a time with
# load.py (no model calls, no busy cores). Use the wheel that matches the host: the GitHub release
# ships manylinux aarch64 and x86_64 wheels (PyPI has x86_64 only). Guard under x86_64 emulation on
# Apple Silicon is too slow to start its resident, so the default platform is linux/arm64.
# Writes load-linux.json and load-linux.log to <out dir>.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
WHEEL=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
BASE=$(cd "$(dirname "$2")" && pwd)/$(basename "$2"); OUT=$(mkdir -p "$3" && cd "$3" && pwd)
PLATFORM=${4:-linux/arm64}
docker run --rm --platform "$PLATFORM" --memory 6g --cpus 4 \
  -v "$HERE:/bench:ro" -v "$BASE:/in/base.json:ro" -v "$OUT:/out" -v "$WHEEL:/whl/$(basename "$WHEEL"):ro" \
  python:3.14-slim bash -euo pipefail -c "
    apt-get update -qq >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq git >/dev/null
    export CIGAR_GAUNTLET_WORK=/rig HOME=/root
    cp -r /bench /work && cd /work/scripts
    bash setup.sh /whl/$(basename "$WHEEL")
    python3 load.py --base /in/base.json --jobs 1 --burn 0 --save /out/load-linux.json | tee /out/load-linux.log
  "
