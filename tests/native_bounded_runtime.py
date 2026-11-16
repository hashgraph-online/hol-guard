"""Name a fixture file as the runtime that carries the bounded hook bridge.

The native ``harness_adapter`` kind reads the bridge from the caller stamp's
``native_runtime``. Python's own ``bounded_cli_hook_bridge`` still looks it up
for the harnesses that have not moved, so a fixture names both.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import bounded_cli_hook_bridge, bounded_cli_hook_native

from .native_runtime_stamp import stamp_native_runtime

BOUNDED_FEATURES = ("bounded-hook-bridge-v1", "bounded-hook-bridge-muse-v1")


def use_bounded_runtime(monkeypatch: pytest.MonkeyPatch, runtime: Path, *, python_side: bool = True) -> str:
    """Stamp ``runtime`` as the bounded bridge and return its SHA-256."""

    runtime.parent.mkdir(parents=True, exist_ok=True)
    if not runtime.exists():
        runtime.write_bytes(b"native runtime")
    digest = stamp_native_runtime(monkeypatch, runtime, BOUNDED_FEATURES)
    if python_side:
        for module in (bounded_cli_hook_bridge, bounded_cli_hook_native):
            monkeypatch.setattr(module, "native_bridge_executable", lambda *_args, **_kwargs: runtime)
    return digest


def durable_copy(guard_home: Path, runtime: Path, digest: str) -> Path:
    """Where a frozen Guard names the verified copy of ``runtime``."""

    return guard_home / "native-runtime" / digest / runtime.name
