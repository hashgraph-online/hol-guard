from __future__ import annotations

from codex_plugin_scanner.guard.runtime.network_policy_contract import (
    BackendAdvertisement,
    BackendCapability,
    EnforcementGrade,
)
from codex_plugin_scanner.guard.runtime.network_supervisor import NetworkSupervisor
from codex_plugin_scanner.guard.runtime.provider_recovery import RecoveryPhase

_DIGEST = "f" * 64


def _advertisement(*, healthy_until: int = 2_000) -> BackendAdvertisement:
    return BackendAdvertisement(
        backend_id="linux.test",
        backend_digest=_DIGEST,
        capabilities=frozenset({BackendCapability.OBSERVE}),
        maximum_grade=EnforcementGrade.OBSERVE,
        healthy_until_epoch_ms=healthy_until,
    )


def test_supervisor_never_reports_grade_without_current_health() -> None:
    supervisor = NetworkSupervisor()
    initial = supervisor.health(now_epoch_ms=1_000)
    assert initial.phase is RecoveryPhase.UNAVAILABLE
    assert initial.effective_grade is EnforcementGrade.UNAVAILABLE

    healthy = supervisor.record_probe(_advertisement(), now_epoch_ms=1_000)
    assert healthy.phase is RecoveryPhase.HEALTHY
    assert healthy.effective_grade is EnforcementGrade.OBSERVE
    assert not healthy.permits_enforcement

    expired = supervisor.health(now_epoch_ms=2_000)
    assert expired.phase is RecoveryPhase.DEGRADED
    assert expired.effective_grade is EnforcementGrade.UNAVAILABLE


def test_supervisor_reuses_bounded_recovery_state_machine() -> None:
    supervisor = NetworkSupervisor()
    error_digest = "a" * 64

    first = supervisor.record_probe(None, now_epoch_ms=1_000, error_digest=error_digest)
    assert first.retry_attempt == 1
    assert first.next_retry_seconds == 2.0
    for offset in range(1, 5):
        failed = supervisor.record_probe(
            None,
            now_epoch_ms=1_000 + offset,
            error_digest=error_digest,
        )
    assert failed.phase is RecoveryPhase.UNAVAILABLE
    assert failed.retry_attempt == 5
    assert failed.next_retry_seconds == 30.0

    recovered = supervisor.record_probe(_advertisement(), now_epoch_ms=1_100)
    assert recovered.phase is RecoveryPhase.HEALTHY
    assert recovered.retry_attempt == 0
