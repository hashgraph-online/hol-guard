"""Runtime producers for the conservative protection-health contract."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Protocol

from .protection_health import (
    ProtectionCheckStatus,
    ProtectionSignal,
    evaluate_protection_health,
)

_STABLE_HARNESS = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")


class CommandActivityHealth(Protocol):
    @property
    def dropped_event_count(self) -> int: ...

    @property
    def persistence_error_count(self) -> int: ...


class ProtectionHealthStore(Protocol):
    def count_command_activities(self) -> int: ...

    def get_command_activity_persistence_health(self) -> CommandActivityHealth: ...


def _signal(status: ProtectionCheckStatus, reason_code: str) -> ProtectionSignal:
    return ProtectionSignal(status, reason_code)


def _hook_signals(managed_installs: Sequence[Mapping[str, object]]) -> dict[str, ProtectionSignal]:
    result: dict[str, ProtectionSignal] = {}
    for install in managed_installs:
        harness = install.get("harness")
        if not isinstance(harness, str) or len(harness) > 64 or _STABLE_HARNESS.fullmatch(harness) is None:
            continue
        candidate = (
            _signal(ProtectionCheckStatus.UNKNOWN, "hook_attestation_unavailable")
            if install.get("active") is True
            else _signal(ProtectionCheckStatus.FAIL, "hooks_inactive")
        )
        existing = result.get(harness)
        result[harness] = (
            _signal(ProtectionCheckStatus.FAIL, "hooks_inactive")
            if candidate.status is ProtectionCheckStatus.FAIL
            or (existing is not None and existing.status is ProtectionCheckStatus.FAIL)
            else candidate
        )
    return result


def _global_hook_signal(harness_signals: Mapping[str, ProtectionSignal]) -> ProtectionSignal:
    if not harness_signals:
        return _signal(ProtectionCheckStatus.FAIL, "no_managed_harness")
    if any(signal.status is ProtectionCheckStatus.FAIL for signal in harness_signals.values()):
        return _signal(ProtectionCheckStatus.FAIL, "one_or_more_hooks_inactive")
    return _signal(ProtectionCheckStatus.UNKNOWN, "hook_attestation_unavailable")


def _rule_pack_signal() -> ProtectionSignal:
    return _signal(ProtectionCheckStatus.UNKNOWN, "rule_pack_runtime_proof_unavailable")


def _decision_stream_signal(store: ProtectionHealthStore) -> ProtectionSignal:
    try:
        health = store.get_command_activity_persistence_health()
        dropped = health.dropped_event_count
        errors = health.persistence_error_count
        activity_count = store.count_command_activities()
    except (AttributeError, RuntimeError, TypeError, ValueError):
        return _signal(ProtectionCheckStatus.FAIL, "decision_stream_health_unavailable")
    if dropped > 0 or errors > 0:
        return _signal(ProtectionCheckStatus.FAIL, "decision_stream_degraded")
    if activity_count == 0:
        return _signal(ProtectionCheckStatus.UNKNOWN, "decision_stream_not_observed")
    return _signal(ProtectionCheckStatus.UNKNOWN, "decision_stream_completeness_unavailable")


def _tamper_signal(trust_status: Mapping[str, object]) -> ProtectionSignal:
    runtime_protection = trust_status.get("runtime_protection")
    if runtime_protection == "protected":
        return _signal(ProtectionCheckStatus.UNKNOWN, "general_tamper_proof_unavailable")
    if runtime_protection == "degraded":
        return _signal(ProtectionCheckStatus.FAIL, "tamper_checks_failed")
    return _signal(ProtectionCheckStatus.UNKNOWN, "tamper_proof_unavailable")


def build_runtime_protection_health(
    *,
    store: ProtectionHealthStore,
    runtime_state: Mapping[str, object] | None,
    managed_installs: Sequence[Mapping[str, object]],
    trust_status: Mapping[str, object],
) -> dict[str, object]:
    """Build current health without treating configuration as runtime proof."""

    harness_signals = _hook_signals(managed_installs)
    signals = {
        "harness_hooks": _global_hook_signal(harness_signals),
        "daemon": _signal(
            ProtectionCheckStatus.PASS if runtime_state is not None else ProtectionCheckStatus.FAIL,
            "daemon_healthy" if runtime_state is not None else "daemon_runtime_unavailable",
        ),
        "policy_engine": _signal(ProtectionCheckStatus.UNKNOWN, "policy_engine_health_unavailable"),
        "rule_packs": _rule_pack_signal(),
        "decision_plane_compatibility": _signal(ProtectionCheckStatus.UNKNOWN, "decision_plane_proof_unavailable"),
        "containment_compatibility": _signal(ProtectionCheckStatus.UNKNOWN, "containment_proof_unavailable"),
        "sandbox": _signal(ProtectionCheckStatus.UNKNOWN, "sandbox_proof_unavailable"),
        "decision_stream": _decision_stream_signal(store),
        "tamper_checks": _tamper_signal(trust_status),
    }
    return evaluate_protection_health(signals, harness_signals=harness_signals)


__all__ = ("ProtectionHealthStore", "build_runtime_protection_health")
