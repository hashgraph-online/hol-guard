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
    assert not initial.permits_enforcement
