from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.native_runtime_resilience import (
    native_record_integrity_failure,
    native_record_overload,
    native_record_resident_success,
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


def test_integrity_failure_quarantines_without_exposing_arbitrary_text(tmp_path: Path) -> None:
    identity = _identity("e")
    native_record_integrity_failure(
        identity,
        tmp_path,
        reason="unsafe reason with /private/path and spaces",
    )
    snapshot = native_runtime_health_snapshot(identity, tmp_path)
    assert snapshot.state == "quarantined"
    assert snapshot.reason == "native_integrity_failed"
    assert snapshot.circuit_open is True

    native_record_resident_success(identity, tmp_path)
    still_quarantined = native_runtime_health_snapshot(identity, tmp_path)
    assert still_quarantined.state == "quarantined"
    assert still_quarantined.circuit_open is True


def test_compatibility_mismatches_are_recoverable() -> None:
    from codex_plugin_scanner.guard.native_runtime import _INTEGRITY_FAILURE_REASONS

    assert "native_protocol_mismatch" not in _INTEGRITY_FAILURE_REASONS
    assert "native_version_mismatch" not in _INTEGRITY_FAILURE_REASONS
    assert "native_manifest_protocol_mismatch" in _INTEGRITY_FAILURE_REASONS
    assert "native_manifest_version_mismatch" in _INTEGRITY_FAILURE_REASONS
