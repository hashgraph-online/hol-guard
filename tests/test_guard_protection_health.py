from __future__ import annotations

import hashlib
import itertools
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import cast

from codex_plugin_scanner.guard.models import GuardRuntimeState
from codex_plugin_scanner.guard.runtime.containment_contract import ContainmentBackend
from codex_plugin_scanner.guard.runtime.containment_health import (
    CONTAINMENT_POLICY_CONTRACT_DIGEST,
    ContainmentHealthEvidence,
)
from codex_plugin_scanner.guard.runtime.protection_health import (
    PROTECTION_CHECK_IDS,
    PROTECTION_HEALTH_SCHEMA_VERSION,
    ProtectionCheckStatus,
    ProtectionSignal,
    evaluate_protection_health,
)
from codex_plugin_scanner.guard.runtime.protection_health_runtime import (
    build_runtime_protection_health,
)

_NOW = datetime(2026, 7, 19, 15, 0, tzinfo=timezone.utc)


def test_runtime_state_brackets_ipv6_approval_center_origin() -> None:
    state = GuardRuntimeState(
        session_id="session-ipv6",
        daemon_host="::1",
        daemon_port=5474,
        started_at=_NOW.isoformat(),
        last_heartbeat_at=_NOW.isoformat(),
    )
    assert state.to_dict()["approval_center_url"] == "http://[::1]:5474"


@dataclass(frozen=True)
class _ActivityHealth:
    dropped_event_count: int
    persistence_error_count: int


class _Store:
    def __init__(self, *, count: int, dropped: int, errors: int) -> None:
        self._count: int = count
        self._health: _ActivityHealth = _ActivityHealth(dropped, errors)

    def count_command_activities(self) -> int:
        return self._count

    def get_command_activity_persistence_health(self) -> _ActivityHealth:
        return self._health


def _containment_evidence() -> dict[str, object]:
    digest = hashlib.sha256(b"stable").hexdigest()
    return ContainmentHealthEvidence(
        backend=ContainmentBackend.MACOS_SANDBOX,
        backend_digest=hashlib.sha256(b"backend").hexdigest(),
        policy_contract_digest=CONTAINMENT_POLICY_CONTRACT_DIGEST,
        daemon_fingerprint=digest,
        runtime_fingerprint=digest,
        probe_at=_NOW.isoformat(),
        probe_enforced=True,
    ).to_dict()


def _payload(
    *,
    installs: list[dict[str, object]] | None = None,
    trust: dict[str, object] | None = None,
    dropped: int = 0,
    errors: int = 0,
    activity_count: int = 1,
    runtime_state: dict[str, object] | None = None,
) -> dict[str, object]:
    if runtime_state is None:
        runtime_state = {
            "last_heartbeat_at": _NOW.isoformat(),
            "containment_health": _containment_evidence(),
        }
    return build_runtime_protection_health(
        store=_Store(count=activity_count, dropped=dropped, errors=errors),
        runtime_state=runtime_state,
        managed_installs=installs or [],
        trust_status=trust or {},
        now=_NOW,
    )


def test_active_install_is_not_hook_interception_proof() -> None:
    payload = _payload(
        installs=[{"harness": "codex", "active": True}],
        trust={"runtime_protection": "protected", "remembered_rules": "enforced"},
        activity_count=3,
    )
    assert payload["state"] == "degraded"
    checks = cast(list[dict[str, str]], payload["checks"])
    by_id = {check["check_id"]: check for check in checks}
    assert by_id["harness_hooks"] == {
        "check_id": "harness_hooks",
        "status": "unknown",
        "reason_code": "hook_attestation_unavailable",
    }
    assert by_id["rule_packs"]["status"] == "pass"
    assert by_id["tamper_checks"]["status"] == "pass"
    assert by_id["decision_stream"]["status"] == "unknown"
    assert by_id["decision_stream"]["reason_code"] == "decision_stream_completeness_unavailable"


def test_trust_signals_fail_closed_when_degraded() -> None:
    payload = _payload(
        installs=[{"harness": "codex", "active": False}],
        trust={"runtime_protection": "degraded", "remembered_rules": "disabled_degraded"},
        dropped=1,
    )
    checks = cast(list[dict[str, str]], payload["checks"])
    by_id = {check["check_id"]: check for check in checks}
    assert by_id["harness_hooks"]["status"] == "fail"
    assert by_id["rule_packs"]["status"] == "fail"
    assert by_id["tamper_checks"]["status"] == "fail"
    assert by_id["decision_stream"]["status"] == "fail"


def test_report_distinguishes_failed_and_unproven_facts() -> None:
    active = _payload(
        installs=[{"harness": "codex", "active": True}],
        trust={"runtime_protection": "protected", "remembered_rules": "enforced"},
    )
    raw_checks = active["checks"]
    assert isinstance(raw_checks, list)
    checks = cast(list[dict[str, str]], raw_checks)
    by_id = {check["check_id"]: check for check in checks}
    assert by_id["daemon"]["status"] == "pass"
    assert by_id["harness_hooks"]["status"] == "unknown"
    assert by_id["decision_plane_compatibility"]["status"] == "pass"
    assert by_id["sandbox"]["status"] == "pass"

    degraded = _payload(
        installs=[{"harness": "codex", "active": False}],
        trust={"runtime_protection": "degraded", "remembered_rules": "disabled_degraded"},
        dropped=1,
    )
    raw_degraded_checks = degraded["checks"]
    assert isinstance(raw_degraded_checks, list)
    degraded_checks = cast(list[dict[str, str]], raw_degraded_checks)
    degraded_by_id = {check["check_id"]: check for check in degraded_checks}
    assert degraded_by_id["harness_hooks"] == {
        "check_id": "harness_hooks",
        "status": "fail",
        "reason_code": "one_or_more_hooks_inactive",
    }
    assert degraded_by_id["tamper_checks"]["status"] == "fail"
    assert degraded_by_id["decision_stream"]["status"] == "fail"
    assert degraded_by_id["rule_packs"]["status"] == "fail"


def test_duplicate_harness_rows_preserve_the_most_restrictive_signal() -> None:
    for installs in (
        [{"harness": "codex", "active": False}, {"harness": "codex", "active": True}],
        [{"harness": "codex", "active": True}, {"harness": "codex", "active": False}],
    ):
        payload = _payload(installs=cast(list[dict[str, object]], installs))
        apps = cast(list[dict[str, object]], payload["apps"])
        assert len(apps) == 1
        assert apps[0]["state"] == "degraded"
        checks = cast(list[dict[str, str]], apps[0]["checks"])
        assert checks[0] == {
            "check_id": "harness_hooks",
            "status": "fail",
            "reason_code": "hooks_inactive",
        }


def test_stale_or_invalid_runtime_rows_never_prove_daemon_health() -> None:
    stale = _payload(runtime_state={"last_heartbeat_at": (_NOW - timedelta(seconds=31)).isoformat()})
    invalid = _payload(runtime_state={"last_heartbeat_at": "not-a-time"})
    for payload, expected_status, expected_reason in (
        (stale, "fail", "daemon_heartbeat_stale"),
        (invalid, "unknown", "daemon_heartbeat_invalid"),
    ):
        checks = cast(list[dict[str, str]], payload["checks"])
        daemon = next(check for check in checks if check["check_id"] == "daemon")
        assert daemon["status"] == expected_status
        assert daemon["reason_code"] == expected_reason
        assert payload["state"] == "degraded"


def test_partial_is_reserved_for_evidence_gap_after_core_proof() -> None:
    passing = {
        check_id: ProtectionSignal(ProtectionCheckStatus.PASS, f"{check_id}_verified")
        for check_id in PROTECTION_CHECK_IDS
    }
    protected = evaluate_protection_health(passing)
    assert protected["state"] == "protected"
    evidence_gap = {
        **passing,
        "decision_stream": ProtectionSignal(ProtectionCheckStatus.UNKNOWN, "decision_stream_gap"),
    }
    assert evaluate_protection_health(evidence_gap)["state"] == "partial"
    assert (
        evaluate_protection_health(evidence_gap)["detail"]
        == "Core protection passes, but decision-stream evidence is incomplete."
    )
    for core_check in set(PROTECTION_CHECK_IDS).difference({"decision_stream"}):
        core_gap = {
            **passing,
            core_check: ProtectionSignal(ProtectionCheckStatus.UNKNOWN, f"{core_check}_gap"),
        }
        assert evaluate_protection_health(core_gap)["state"] == "degraded"


def test_exhaustive_check_truth_table_is_monotonic() -> None:
    statuses = tuple(ProtectionCheckStatus)
    for combination in itertools.product(statuses, repeat=len(PROTECTION_CHECK_IDS)):
        signals = {
            check_id: ProtectionSignal(status, f"{check_id}_{status.value}")
            for check_id, status in zip(PROTECTION_CHECK_IDS, combination, strict=True)
        }
        actual = evaluate_protection_health(signals)["state"]
        evidence_status = combination[PROTECTION_CHECK_IDS.index("decision_stream")]
        core_statuses = tuple(
            status
            for check_id, status in zip(PROTECTION_CHECK_IDS, combination, strict=True)
            if check_id != "decision_stream"
        )
        if all(status is ProtectionCheckStatus.PASS for status in core_statuses):
            expected = (
                "protected"
                if evidence_status is ProtectionCheckStatus.PASS
                else ("partial" if evidence_status is ProtectionCheckStatus.UNKNOWN else "degraded")
            )
        else:
            expected = "degraded"
        assert actual == expected


def test_app_reports_are_bounded_and_privacy_safe() -> None:
    installs: list[dict[str, object]] = [
        {
            "harness": f"app-{index}",
            "active": True,
            "workspace": f"/private/workspace/{index}",
            "raw_command": f"secret-command-{index}",
        }
        for index in range(120)
    ]
    installs.append({"harness": "../../private", "active": True, "workspace": "/secret"})
    payload = _payload(installs=installs)
    assert payload["schema_version"] == PROTECTION_HEALTH_SCHEMA_VERSION
    raw_apps = payload["apps"]
    assert isinstance(raw_apps, list)
    apps = cast(list[dict[str, object]], raw_apps)
    assert len(apps) == 100
    serialized = repr(payload)
    assert "/private/" not in serialized
    assert "secret-command" not in serialized
    assert "../../private" not in serialized
    assert all(
        set(app) == {"harness", "state", "label", "detail", "evidence_gap", "checks", "reason_codes"} for app in apps
    )
