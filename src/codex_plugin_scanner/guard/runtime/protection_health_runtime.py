"""Runtime producers for the conservative protection-health contract."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from typing import Protocol

from .containment_health import ContainmentHealthEvidence, containment_health_signals
from .protection_health import (
    ProtectionCheckStatus,
    ProtectionSignal,
    evaluate_protection_health,
)

_STABLE_HARNESS = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_DAEMON_HEARTBEAT_MAX_AGE = timedelta(seconds=30)
_DAEMON_HEARTBEAT_FUTURE_TOLERANCE = timedelta(seconds=5)


class CommandActivityHealth(Protocol):
    @property
    def dropped_event_count(self) -> int: ...

    @property
    def persistence_error_count(self) -> int: ...

    @property
    def active_error_count(self) -> int: ...


class ProtectionHealthStore(Protocol):
    def count_command_activities(self) -> int: ...

    def get_command_activity_persistence_health(self) -> CommandActivityHealth: ...


def _signal(status: ProtectionCheckStatus, reason_code: str) -> ProtectionSignal:
    return ProtectionSignal(status, reason_code)


def _hook_signals(
    managed_installs: Sequence[Mapping[str, object]],
    hook_verification: Mapping[str, bool] | None,
) -> dict[str, ProtectionSignal]:
    result: dict[str, ProtectionSignal] = {}
    for install in managed_installs:
        harness = install.get("harness")
        if not isinstance(harness, str) or len(harness) > 64 or _STABLE_HARNESS.fullmatch(harness) is None:
            continue
        if install.get("active") is not True:
            candidate = _signal(ProtectionCheckStatus.FAIL, "hooks_inactive")
        elif hook_verification is None or harness not in hook_verification:
            candidate = _signal(ProtectionCheckStatus.UNKNOWN, "hook_verification_unavailable")
        elif hook_verification[harness]:
            candidate = _signal(ProtectionCheckStatus.PASS, "hooks_verified")
        else:
            candidate = _signal(ProtectionCheckStatus.FAIL, "hooks_verification_failed")
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
    if all(signal.status is ProtectionCheckStatus.PASS for signal in harness_signals.values()):
        return _signal(ProtectionCheckStatus.PASS, "hooks_verified")
    return _signal(ProtectionCheckStatus.UNKNOWN, "hook_verification_unavailable")


def _rule_pack_signal(trust_status: Mapping[str, object]) -> ProtectionSignal:
    remembered = trust_status.get("remembered_rules")
    if remembered == "enforced":
        return _signal(ProtectionCheckStatus.PASS, "rule_packs_enforced")
    if remembered == "disabled_degraded":
        return _signal(ProtectionCheckStatus.FAIL, "rule_packs_disabled")
    return _signal(ProtectionCheckStatus.UNKNOWN, "rule_pack_runtime_proof_unavailable")


def _daemon_signal(runtime_state: Mapping[str, object] | None, *, now: datetime) -> ProtectionSignal:
    if runtime_state is None:
        return _signal(ProtectionCheckStatus.FAIL, "daemon_runtime_unavailable")
    heartbeat_value = runtime_state.get("last_heartbeat_at")
    if not isinstance(heartbeat_value, str):
        return _signal(ProtectionCheckStatus.UNKNOWN, "daemon_heartbeat_unavailable")
    try:
        heartbeat = datetime.fromisoformat(heartbeat_value.replace("Z", "+00:00"))
    except ValueError:
        return _signal(ProtectionCheckStatus.UNKNOWN, "daemon_heartbeat_invalid")
    if heartbeat.tzinfo is None or now.tzinfo is None:
        return _signal(ProtectionCheckStatus.UNKNOWN, "daemon_heartbeat_invalid")
    age = now.astimezone(timezone.utc) - heartbeat.astimezone(timezone.utc)
    if age < -_DAEMON_HEARTBEAT_FUTURE_TOLERANCE:
        return _signal(ProtectionCheckStatus.UNKNOWN, "daemon_heartbeat_future")
    if age > _DAEMON_HEARTBEAT_MAX_AGE:
        return _signal(ProtectionCheckStatus.FAIL, "daemon_heartbeat_stale")
    containment_health = runtime_state.get("containment_health")
    if containment_health is not None:
        try:
            evidence = ContainmentHealthEvidence.from_mapping(containment_health)
        except (TypeError, ValueError):
            return _signal(ProtectionCheckStatus.FAIL, "daemon_containment_health_invalid")
        if evidence.daemon_fingerprint != evidence.runtime_fingerprint:
            return _signal(ProtectionCheckStatus.FAIL, "daemon_runtime_drift")
    return _signal(ProtectionCheckStatus.PASS, "daemon_healthy")


def _decision_stream_signal(store: ProtectionHealthStore) -> ProtectionSignal:
    try:
        health = store.get_command_activity_persistence_health()
        active_errors = health.active_error_count
        activity_count = store.count_command_activities()
    except (AttributeError, RuntimeError, TypeError, ValueError):
        return _signal(ProtectionCheckStatus.FAIL, "decision_stream_health_unavailable")
    if active_errors > 0:
        return _signal(ProtectionCheckStatus.FAIL, "decision_stream_degraded")
    return _signal(
        ProtectionCheckStatus.PASS,
        "decision_stream_ready" if activity_count == 0 else "decision_stream_healthy",
    )


def _tamper_signal(trust_status: Mapping[str, object]) -> ProtectionSignal:
    runtime_protection = trust_status.get("runtime_protection")
    if runtime_protection == "protected":
        return _signal(ProtectionCheckStatus.PASS, "runtime_protection_trusted")
    if runtime_protection == "degraded":
        return _signal(ProtectionCheckStatus.FAIL, "tamper_checks_failed")
    return _signal(ProtectionCheckStatus.UNKNOWN, "tamper_proof_unavailable")


def build_runtime_protection_health(
    *,
    store: ProtectionHealthStore,
    runtime_state: Mapping[str, object] | None,
    managed_installs: Sequence[Mapping[str, object]],
    hook_verification: Mapping[str, bool] | None = None,
    trust_status: Mapping[str, object],
    now: datetime,
) -> dict[str, object]:
    """Build current health using only operational runtime and trust proof."""

    harness_signals = _hook_signals(managed_installs, hook_verification)
    containment_signals = containment_health_signals(
        runtime_state.get("containment_health") if runtime_state is not None else None,
        now=now,
    )
    signals = {
        "harness_hooks": _global_hook_signal(harness_signals),
        "daemon": _daemon_signal(runtime_state, now=now),
        "policy_engine": containment_signals["policy_engine"],
        "rule_packs": _rule_pack_signal(trust_status),
        "decision_plane_compatibility": containment_signals["decision_plane_compatibility"],
        "containment_compatibility": containment_signals["containment_compatibility"],
        "sandbox": containment_signals["sandbox"],
        "decision_stream": _decision_stream_signal(store),
        "tamper_checks": _tamper_signal(trust_status),
    }
    return evaluate_protection_health(signals, harness_signals=harness_signals)


__all__ = ("ProtectionHealthStore", "build_runtime_protection_health")
