# ADR 0007: Native runtime packaging

Status: selected direction, release proof pending.

## Decision

Keep `hol-guard` as the only required user-facing distribution. Supported platform wheels for `hol-guard` bundle one version-matched `hol-guard-runtime` executable under `codex_plugin_scanner/_native/`; the existing pure-Python universal wheel remains the compatibility fallback for unsupported platforms. `plugin-scanner` remains pure Python and does not carry the Guard runtime.

This avoids a second PyPI project, cross-project trusted-publisher bootstrapping, dependency-resolution races between two prerelease projects, and runtime/Python skew caused by independent package installation. It also preserves the current `pip install hol-guard` and `pipx install hol-guard` surface while allowing pip to prefer a compatible platform wheel when one exists.

The Python facade locates the bundled executable from the installed package first, validates the file before execution, negotiates protocol/version/rule metadata, and never searches PATH. An explicit absolute binary override remains permitted only for development/shadow verification; a separately installed `hol-guard-runtime` distribution may remain a development compatibility source but is not the primary release contract.

## Why not PyO3-only

A Python extension improves CPU-heavy in-process calls but cannot remove Python startup from hook cold paths. It also adds CPython ABI concerns that the standalone executable avoids. PyO3 remains available later for a measured in-process hotspot.

## Release requirements

Tier 1 artifacts are macOS arm64/x86_64, Windows x86_64, and the approved Linux x86_64 manylinux target. The embedded runtime capability version must exactly match the containing `hol-guard` wheel version. Partial target publication may not replace the universal fallback; mismatched versions, duplicate platform artifacts, missing provenance, or digest mismatch block the affected native wheel. Unsupported platforms retain the Python backend.

The native wheel builder must start from the already verified pure-Python `hol-guard` wheel, inject only the native executable plus a non-secret runtime manifest, recompute `RECORD`, mark the wheel non-pure, and emit a platform-specific tag. It must never mutate or retag the `plugin-scanner` wheel.
