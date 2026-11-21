"""Name a fixture file as the runtime that carries the bounded hook bridge.

The native ``harness_adapter`` kind reads the bridge from the caller stamp's
``native_runtime``, so stamping the fixture is all a test needs.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_hook_bridge
from codex_plugin_scanner.guard.harness_context import HarnessContext
from codex_plugin_scanner.guard.native_harness_client import raise_failure, wire_context
from codex_plugin_scanner.guard.native_runner_authority import native_runner_authority

from .native_runtime_stamp import stamp_native_runtime

BOUNDED_FEATURES = ("bounded-hook-bridge-v1", "bounded-hook-bridge-muse-v1")


def use_bounded_runtime(monkeypatch: pytest.MonkeyPatch, runtime: Path, guard_home: Path | None = None) -> str:
    """Stamp ``runtime`` as the bounded bridge and return its SHA-256.

    ``guard_home`` is the Guard home a frozen lookup without one falls back to.
    """

    runtime.parent.mkdir(parents=True, exist_ok=True)
    if not runtime.exists():
        runtime.write_bytes(b"native runtime")
    digest = stamp_native_runtime(monkeypatch, runtime, BOUNDED_FEATURES)

    default_home = guard_home

    def bridge(feature: str, *, guard_home: Path | None = None, **_kwargs: object) -> Path | None:
        # Validation looks the bridge up the way install named it: the stamped
        # runtime, or a frozen Guard's durable copy of it under ``guard_home``.
        if feature not in BOUNDED_FEATURES:
            return None
        if not getattr(sys, "frozen", False):
            return runtime
        home = guard_home or default_home
        return None if home is None else durable_copy(home, runtime, digest)

    monkeypatch.setattr(native_hook_bridge, "native_hook_bridge_executable", bridge)
    return digest


def durable_copy(guard_home: Path, runtime: Path, digest: str) -> Path:
    """Where a frozen Guard names the verified copy of ``runtime``."""

    return guard_home / "native-runtime" / digest / runtime.name


def hook_config_argv(
    context: HarnessContext, harness: str, cli_args: list[str], timeout_seconds: int = 20
) -> tuple[str, ...]:
    """The hook argv the native kind names for a bounded ``guard hook`` of ``harness``.

    Raises the error an install raises when the runtime refuses it.
    """

    request: dict[str, object] = {
        "op": "hook_config",
        "harness": harness,
        "context": wire_context(context),
        "cli_args": cli_args,
        "timeout_seconds": timeout_seconds,
    }
    answer = native_runner_authority("harness_adapter", request)
    raise_failure(answer)
    return tuple(str(part) for part in answer["hook_argv"])
