from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime.network_capability_contract import NetworkPrivacyPolicy
from codex_plugin_scanner.guard.runtime.network_evidence_ledger import NetworkEvidenceLedger
from codex_plugin_scanner.guard.runtime.network_policy_contract import (
    EnforcementGrade,
    NetworkAction,
    NetworkEvidence,
    NetworkProtocol,
)

_DIGEST = "e" * 64


class _Telemetry:
    def __init__(self) -> None:
        self.events: list[tuple[str, str | None]] = []

    def record(self, event: str, *, detail: str | None = None) -> bool:
        self.events.append((event, detail))
        return True


def _evidence(index: int, observed_at: int) -> NetworkEvidence:
    return NetworkEvidence(
        flow_id=f"flow.{index}",
        process_tree_digest=_DIGEST,
        destination_digest=_DIGEST,
        protocol=NetworkProtocol.TCP,
        port=443,
        action=NetworkAction.ALLOW,
        policy_digest=_DIGEST,
        backend_digest=_DIGEST,
        grade=EnforcementGrade.OBSERVE,
        observed_at_epoch_ms=observed_at,
    )


def _policy() -> NetworkPrivacyPolicy:
    return NetworkPrivacyPolicy(
        raw_destination_enabled=False,
        retention_seconds=60,
        maximum_events=2,
    )


def test_ledger_bounds_capacity_and_retention_without_raw_destinations() -> None:
    ledger = NetworkEvidenceLedger(policy=_policy())
    ledger.append(_evidence(1, 1_000))
    ledger.append(_evidence(2, 1_500))
    ledger.append(_evidence(3, 2_000))

    assert tuple(item.flow_id for item in ledger.snapshot(now_epoch_ms=2_000)) == ("flow.2", "flow.3")
    assert tuple(item.flow_id for item in ledger.snapshot(now_epoch_ms=61_501)) == ("flow.3",)
    assert ledger.clear() == 1
    assert ledger.snapshot(now_epoch_ms=3_000) == ()


def test_ledger_rejects_non_monotonic_evidence() -> None:
    ledger = NetworkEvidenceLedger(policy=_policy())
    ledger.append(_evidence(1, 2_000))

    with pytest.raises(ValueError, match="monotonic"):
        ledger.append(_evidence(2, 1_999))


def test_snapshot_reference_rejects_later_stale_evidence() -> None:
    ledger = NetworkEvidenceLedger(policy=_policy())
    ledger.append(_evidence(1, 2_000))
    assert ledger.snapshot(now_epoch_ms=100_000) == ()

    with pytest.raises(ValueError, match="monotonic"):
        ledger.append(_evidence(2, 3_000))


def test_ledger_limits_come_from_validated_privacy_policy() -> None:
    with pytest.raises(ValueError, match="retention_seconds"):
        _ = NetworkPrivacyPolicy(
            raw_destination_enabled=False,
            retention_seconds=59,
            maximum_events=2,
        )


def test_ledger_reuses_bounded_diagnostics_telemetry_without_destinations() -> None:
    telemetry = _Telemetry()
    ledger = NetworkEvidenceLedger(policy=_policy(), telemetry=telemetry)

    ledger.append(_evidence(1, 1_000))

    assert telemetry.events == [
        ("network_evidence_appended", "action=allow grade=observe"),
    ]
    assert _DIGEST not in repr(telemetry.events)
