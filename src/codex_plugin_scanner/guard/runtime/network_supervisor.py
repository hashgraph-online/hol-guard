"""Truthful health and bounded recovery for a local network backend."""

from __future__ import annotations

from dataclasses import dataclass

from codex_plugin_scanner.guard.runtime.network_policy_contract import (
    BackendAdvertisement,
    EnforcementGrade,
)
from codex_plugin_scanner.guard.runtime.provider_recovery import (
    RecoveryPhase,
    RecoveryState,
    next_recovery_state,
)


@dataclass(frozen=True, slots=True)
class NetworkSupervisorHealth:
    phase: RecoveryPhase
    backend_id: str | None
    backend_digest: str | None
    effective_grade: EnforcementGrade
    healthy_until_epoch_ms: int | None
    retry_attempt: int
    next_retry_seconds: float

    @property
    def permits_enforcement(self) -> bool:
        return self.phase is RecoveryPhase.HEALTHY and self.effective_grade not in {
            EnforcementGrade.UNAVAILABLE,
            EnforcementGrade.OBSERVE,
        }


class NetworkSupervisor:
    def __init__(self) -> None:
        self._advertisement: BackendAdvertisement | None = None
        self._recovery: RecoveryState = RecoveryState(RecoveryPhase.UNAVAILABLE, 0, 0.0)

    def record_probe(
        self,
        advertisement: BackendAdvertisement | None,
        *,
        now_epoch_ms: int,
        error_digest: str | None = None,
    ) -> NetworkSupervisorHealth:
        succeeded = advertisement is not None and now_epoch_ms < advertisement.healthy_until_epoch_ms
        self._recovery = next_recovery_state(
            self._recovery,
            succeeded=succeeded,
            error_digest=None if succeeded else error_digest,
        )
        self._advertisement = advertisement if succeeded else None
        return self.health(now_epoch_ms=now_epoch_ms)

    def health(self, *, now_epoch_ms: int) -> NetworkSupervisorHealth:
        advertisement = self._advertisement
        if advertisement is None or now_epoch_ms >= advertisement.healthy_until_epoch_ms:
            return NetworkSupervisorHealth(
                phase=self._recovery.phase if advertisement is None else RecoveryPhase.DEGRADED,
                backend_id=None if advertisement is None else advertisement.backend_id,
                backend_digest=None if advertisement is None else advertisement.backend_digest,
                effective_grade=EnforcementGrade.UNAVAILABLE,
                healthy_until_epoch_ms=None if advertisement is None else advertisement.healthy_until_epoch_ms,
                retry_attempt=self._recovery.attempt,
                next_retry_seconds=self._recovery.next_retry_seconds,
            )
        return NetworkSupervisorHealth(
            phase=self._recovery.phase,
            backend_id=advertisement.backend_id,
            backend_digest=advertisement.backend_digest,
            effective_grade=advertisement.maximum_grade,
            healthy_until_epoch_ms=advertisement.healthy_until_epoch_ms,
            retry_attempt=self._recovery.attempt,
            next_retry_seconds=self._recovery.next_retry_seconds,
        )
