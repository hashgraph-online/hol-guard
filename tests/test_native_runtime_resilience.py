from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.native_runtime_resilience import (
    native_record_overload,
    native_runtime_health_snapshot,
)


def _identity(prefix: str) -> str:
    return (prefix * 64)[:64]


def test_overload_does_not_trip_crash_circuit(tmp_path: Path) -> None:
    identity = _identity("d")
    native_record_overload(identity, tmp_path)
    snapshot = native_runtime_health_snapshot(identity, tmp_path)
    assert snapshot.state == "overloaded"
    assert snapshot.overloads == 1
    assert snapshot.consecutive_failures == 0
    assert snapshot.circuit_open is False


def test_compatibility_mismatches_are_recoverable() -> None:
    from codex_plugin_scanner.guard.native_runtime import _INTEGRITY_FAILURE_REASONS

    assert "native_protocol_mismatch" not in _INTEGRITY_FAILURE_REASONS
    assert "native_version_mismatch" not in _INTEGRITY_FAILURE_REASONS
    assert "native_manifest_protocol_mismatch" in _INTEGRITY_FAILURE_REASONS
    assert "native_manifest_version_mismatch" in _INTEGRITY_FAILURE_REASONS
