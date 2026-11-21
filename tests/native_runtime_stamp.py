"""Name a fixture file as the native runtime in this process's caller stamp.

The native side reads the hook bridge and MCP relay from the stamp's
``native_runtime``, so tests that need a particular runtime stamp it here.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_caller

CODEX_HOOK_FEATURE = "codex-hook-bridge-v1"


def stamp_native_runtime(
    monkeypatch: pytest.MonkeyPatch,
    runtime: Path,
    features: Iterable[str] = (CODEX_HOOK_FEATURE,),
) -> str:
    """Stamp ``runtime`` and return its SHA-256, which names a frozen
    Guard's durable copy under ``<guard home>/native-runtime/``."""

    data = runtime.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    identity = {"path": str(runtime), "size": len(data), "sha256": digest, "features": sorted(features)}
    monkeypatch.setattr(native_caller, "_native_runtime", lambda: identity)
    return digest
