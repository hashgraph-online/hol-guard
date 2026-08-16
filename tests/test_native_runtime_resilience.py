from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.native_runtime_resilience import (
    native_oneshot_lease,
    native_record_integrity_failure,
    native_record_oneshot_success,
    native_record_overload,
    native_record_resident_failure,
    native_record_resident_success,
    native_record_restart,
    native_record_starting,
    native_runtime_health_snapshot,
)


def _identity(prefix: str) -> str:
    return (prefix * 64)[:64]


def test_native_health_tracks_start_recovery_and_success(tmp_path: Path) -> None:
    identity = _identity("a")
    native_record_starting(identity, tmp_path)
    starting = native_runtime_health_snapshot(identity, tmp_path)
    assert starting.state == "starting"
    assert starting.starts == 1
    assert starting.circuit_open is False

    native_record_restart(identity, tmp_path)
    recovering = native_runtime_health_snapshot(identity, tmp_path)
    assert recovering.state == "recovering"
    assert recovering.restarts == 1

    native_record_resident_success(identity, tmp_path)
    healthy = native_runtime_health_snapshot(identity, tmp_path)
    assert healthy.state == "healthy"
    assert healthy.reason == "native_ready"
    assert healthy.consecutive_failures == 0


def test_native_circuit_opens_after_bounded_failures(tmp_path: Path) -> None:
    identity = _identity("b")
    for index in range(3):
        native_record_resident_failure(
            identity,
            tmp_path,
            reason=f"native_resident_failed_{index}",
        )

    snapshot = native_runtime_health_snapshot(identity, tmp_path)
    assert snapshot.state == "circuit_open"
    assert snapshot.reason == "native_circuit_open"
    assert snapshot.circuit_open is True
    assert snapshot.resident_failures == 3
    with native_oneshot_lease(identity, tmp_path) as acquired:
        assert acquired is False


def test_native_oneshot_lease_is_single_flight_per_runtime(tmp_path: Path) -> None:
    identity = _identity("c")
    with native_oneshot_lease(identity, tmp_path) as first:
        assert first is True
        with native_oneshot_lease(identity, tmp_path) as second:
            assert second is False
    native_record_oneshot_success(identity, tmp_path)
    snapshot = native_runtime_health_snapshot(identity, tmp_path)
    assert snapshot.state == "degraded"
    assert snapshot.reason == "native_oneshot_fallback"


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
