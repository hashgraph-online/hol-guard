"""Capacity- and retention-bounded local network evidence ledger."""

from collections import deque
from typing import Protocol

from codex_plugin_scanner.guard.runtime.network_capability_contract import NetworkPrivacyPolicy
from codex_plugin_scanner.guard.runtime.network_policy_contract import NetworkEvidence


class NetworkTelemetrySink(Protocol):
    def record(self, event: str, *, detail: str | None = None) -> bool: ...


class NetworkEvidenceLedger:
    def __init__(
        self,
        *,
        policy: NetworkPrivacyPolicy,
        telemetry: NetworkTelemetrySink | None = None,
    ) -> None:
        self._policy: NetworkPrivacyPolicy = policy
        self._capacity: int = policy.maximum_events
        self._retention_ms: int = policy.retention_seconds * 1_000
        self._entries: deque[NetworkEvidence] = deque()
        self._telemetry: NetworkTelemetrySink | None = telemetry
        self._latest_reference_epoch_ms: int | None = None

    def append(self, evidence: NetworkEvidence) -> None:
        if evidence.raw_destination is not None:
            raise ValueError("raw destinations are prohibited in the local ledger")
        latest_reference = self._latest_reference_epoch_ms
        if latest_reference is not None and evidence.observed_at_epoch_ms < latest_reference:
            raise ValueError("evidence timestamps must be monotonic")
        self._entries.append(evidence)
        self._latest_reference_epoch_ms = evidence.observed_at_epoch_ms
        self._prune(reference_epoch_ms=evidence.observed_at_epoch_ms)
        overflow = len(self._entries) - self._capacity
        for _unused in range(max(overflow, 0)):
            _ = self._entries.popleft()

        if self._telemetry is not None:
            _ = self._telemetry.record(
                "network_evidence_appended",
                detail=f"action={evidence.action.value} grade={evidence.grade.value}",
            )

    def snapshot(self, *, now_epoch_ms: int) -> tuple[NetworkEvidence, ...]:
        latest_reference = self._latest_reference_epoch_ms
        reference_epoch_ms = max(now_epoch_ms, latest_reference) if latest_reference is not None else now_epoch_ms
        self._latest_reference_epoch_ms = reference_epoch_ms
        self._prune(reference_epoch_ms=reference_epoch_ms)
        return tuple(self._entries)

    def clear(self) -> int:
        count = len(self._entries)
        self._entries.clear()
        return count

    def _prune(self, *, reference_epoch_ms: int) -> None:
        cutoff = reference_epoch_ms - self._retention_ms
        while self._entries and self._entries[0].observed_at_epoch_ms < cutoff:
            _ = self._entries.popleft()
