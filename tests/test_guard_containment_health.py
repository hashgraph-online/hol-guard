from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.runtime.containment_contract import (
    ContainmentBackend,
    ContainmentPolicy,
    ContainmentRequest,
)
from codex_plugin_scanner.guard.runtime.containment_executor import file_sha256
from codex_plugin_scanner.guard.runtime.containment_health import (
    CONTAINMENT_POLICY_CONTRACT_DIGEST,
    ContainmentHealthEvidence,
    containment_health_signals,
    containment_health_uncertainties,
)
from codex_plugin_scanner.guard.runtime.effect_contract import UncertaintyKind
from codex_plugin_scanner.guard.runtime.protection_health_runtime import build_runtime_protection_health

_NOW = datetime(2026, 7, 19, 15, 0, tzinfo=timezone.utc)


class _Health:
    dropped_event_count: int = 0
    persistence_error_count: int = 0


class _Store:
    def count_command_activities(self) -> int:
        return 1

    def get_command_activity_persistence_health(self) -> _Health:
        return _Health()


def _evidence(**overrides: object) -> ContainmentHealthEvidence:
    digest = hashlib.sha256(b"stable").hexdigest()
    values: dict[str, object] = {
        "backend": ContainmentBackend.MACOS_SANDBOX,
        "backend_digest": hashlib.sha256(b"backend").hexdigest(),
        "policy_contract_digest": CONTAINMENT_POLICY_CONTRACT_DIGEST,
        "daemon_fingerprint": digest,
        "runtime_fingerprint": digest,
        "probe_at": _NOW.isoformat(),
        "probe_enforced": True,
    }
    values.update(overrides)
    return ContainmentHealthEvidence(
        backend=cast(ContainmentBackend, values["backend"]),
        backend_digest=cast(str, values["backend_digest"]),
        policy_contract_digest=cast(str, values["policy_contract_digest"]),
        daemon_fingerprint=cast(str, values["daemon_fingerprint"]),
        runtime_fingerprint=cast(str, values["runtime_fingerprint"]),
        probe_at=cast(str, values["probe_at"]),
        probe_enforced=cast(bool, values["probe_enforced"]),
    )


def _runtime_payload(evidence: object) -> dict[str, object]:
    return build_runtime_protection_health(
        store=_Store(),
        runtime_state={"last_heartbeat_at": _NOW.isoformat(), "containment_health": evidence},
        managed_installs=[{"harness": "codex", "active": True}],
        trust_status={},
        now=_NOW,
    )


def test_compatible_health_proves_only_the_containment_owned_checks() -> None:
    evidence = _evidence()
    signals = containment_health_signals(evidence.to_dict(), now=_NOW)

    assert set(signals) == {
        "policy_engine",
        "decision_plane_compatibility",
        "containment_compatibility",
        "sandbox",
    }
    assert all(signal.status.value == "pass" for signal in signals.values())
    assert containment_health_uncertainties(evidence.to_dict(), now=_NOW) == ()

    payload = _runtime_payload(evidence.to_dict())
    checks = cast(list[dict[str, str]], payload["checks"])
    by_id = {item["check_id"]: item for item in checks}
    assert by_id["daemon"]["status"] == "pass"
    assert by_id["containment_compatibility"]["status"] == "pass"
    assert by_id["sandbox"]["reason_code"] == "containment_backend_enforced"
    assert payload["state"] == "degraded"


@pytest.mark.parametrize(
    ("overrides", "reason", "uncertainty"),
    (
        ({"backend": ContainmentBackend.UNSUPPORTED}, "unsupported_platform", UncertaintyKind.DEGRADED_CONTAINMENT),
        ({"probe_enforced": False}, "containment_probe_failed", UncertaintyKind.DEGRADED_CONTAINMENT),
        (
            {"probe_at": (_NOW - timedelta(minutes=6)).isoformat()},
            "containment_probe_stale",
            UncertaintyKind.DEGRADED_CONTAINMENT,
        ),
        (
            {"probe_at": (_NOW + timedelta(seconds=6)).isoformat()},
            "containment_probe_future",
            UncertaintyKind.DEGRADED_CONTAINMENT,
        ),
        (
            {"policy_contract_digest": hashlib.sha256(b"other").hexdigest()},
            "policy_version_mismatch",
            UncertaintyKind.POLICY_VERSION_MISMATCH,
        ),
        (
            {"runtime_fingerprint": hashlib.sha256(b"drift").hexdigest()},
            "daemon_runtime_drift",
            UncertaintyKind.PROTECTION_HEALTH_DEGRADED,
        ),
    ),
)
def test_faults_fail_closed_and_surface_degraded(
    overrides: dict[str, object],
    reason: str,
    uncertainty: UncertaintyKind,
) -> None:
    evidence = _evidence(**overrides)
    signals = containment_health_signals(evidence.to_dict(), now=_NOW)
    uncertainties = containment_health_uncertainties(evidence.to_dict(), now=_NOW)
    payload = _runtime_payload(evidence.to_dict())

    assert all(signal.status.value == "fail" for signal in signals.values())
    assert {signal.reason_code for signal in signals.values()} == {reason}
    assert uncertainty in uncertainties
    assert payload["state"] == "degraded"
    assert payload["label"] == "Degraded"


def test_daemon_drift_has_an_explicit_daemon_failure() -> None:
    evidence = _evidence(runtime_fingerprint=hashlib.sha256(b"drift").hexdigest())
    payload = _runtime_payload(evidence.to_dict())
    checks = cast(list[dict[str, str]], payload["checks"])
    daemon = next(item for item in checks if item["check_id"] == "daemon")

    assert daemon == {
        "check_id": "daemon",
        "status": "fail",
        "reason_code": "daemon_runtime_drift",
    }


def test_missing_or_malformed_health_is_blocking_not_unknown() -> None:
    for value in (None, {}, {"schema_version": "future"}, ["not", "a", "mapping"]):
        signals = containment_health_signals(value, now=_NOW)
        assert all(signal.status.value == "fail" for signal in signals.values())
        assert containment_health_uncertainties(value, now=_NOW) == (
            UncertaintyKind.DEGRADED_CONTAINMENT,
            UncertaintyKind.PROTECTION_HEALTH_DEGRADED,
        )


def test_health_mapping_is_strict_and_privacy_safe(tmp_path: Path) -> None:
    evidence = _evidence()
    serialized = repr(evidence.to_dict())
    assert str(tmp_path) not in serialized
    with pytest.raises(ValueError, match="fields"):
        _ = ContainmentHealthEvidence.from_mapping({**evidence.to_dict(), "raw_command": "secret"})


def test_request_fixture_remains_path_pinned(tmp_path: Path) -> None:
    output = tmp_path / "output"
    output.mkdir()
    request = ContainmentRequest(
        argv=("/usr/bin/true",),
        cwd=str(tmp_path.resolve()),
        environment=(),
        policy=ContainmentPolicy(str(tmp_path.resolve()), (str(output.resolve()),)),
        inputs=(),
        launch_digest=hashlib.sha256(b"launch").hexdigest(),
        executable_digest=file_sha256("/usr/bin/true"),
        operation_id="test",
    )
    assert request.argv == ("/usr/bin/true",)
