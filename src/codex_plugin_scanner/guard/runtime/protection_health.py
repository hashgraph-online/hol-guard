"""Truthful, privacy-safe protection-health assessment."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Final

from .effect_contract import ProtectionHealth, TruthfulState, derive_protection_state

PROTECTION_HEALTH_SCHEMA_VERSION: Final = "guard.protection-health.v1"
PROTECTION_CHECK_IDS: Final = (
    "harness_hooks",
    "daemon",
    "policy_engine",
    "rule_packs",
    "decision_plane_compatibility",
    "containment_compatibility",
    "sandbox",
    "decision_stream",
    "tamper_checks",
)
_STABLE_ID = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_MAX_HARNESSES = 100


class ProtectionCheckStatus(str, Enum):
    PASS = "pass"
    UNKNOWN = "unknown"
    FAIL = "fail"


class ProtectionState(str, Enum):
    PROTECTED = "protected"
    PARTIAL = "partial"
    DEGRADED = "degraded"


@dataclass(frozen=True, slots=True)
class ProtectionSignal:
    status: ProtectionCheckStatus
    reason_code: str

    def __post_init__(self) -> None:
        if not _STABLE_ID.fullmatch(self.reason_code):
            raise ValueError("protection signal reason_code must be a stable identifier")

    def to_dict(self, check_id: str) -> dict[str, str]:
        return {
            "check_id": check_id,
            "status": self.status.value,
            "reason_code": self.reason_code,
        }


UNKNOWN_SIGNAL: Final = ProtectionSignal(ProtectionCheckStatus.UNKNOWN, "proof_unavailable")


def _state_for(signals: Sequence[ProtectionSignal]) -> ProtectionState:
    if any(signal.status is ProtectionCheckStatus.FAIL for signal in signals):
        return ProtectionState.DEGRADED
    by_id: dict[str, ProtectionSignal] = dict(zip(PROTECTION_CHECK_IDS, signals, strict=True))

    def passes(check_id: str) -> bool:
        return by_id[check_id].status is ProtectionCheckStatus.PASS

    state = derive_protection_state(
        ProtectionHealth(
            required_hooks=passes("harness_hooks"),
            daemon_and_policy=passes("daemon") and passes("policy_engine"),
            rules_and_containment=all(
                passes(check_id)
                for check_id in (
                    "rule_packs",
                    "decision_plane_compatibility",
                    "containment_compatibility",
                    "sandbox",
                )
            ),
            tamper_checks=passes("tamper_checks"),
            evidence_health=passes("decision_stream"),
        )
    )
    return {
        TruthfulState.PROTECTED: ProtectionState.PROTECTED,
        TruthfulState.PARTIAL: ProtectionState.PARTIAL,
        TruthfulState.DEGRADED: ProtectionState.DEGRADED,
    }[state]


def _copy_for(state: ProtectionState) -> tuple[str, str]:
    if state is ProtectionState.PROTECTED:
        return "Protected", "All required protection checks have current proof."
    if state is ProtectionState.DEGRADED:
        return "Degraded", "One or more required protection checks failed or remain unproven."
    return "Partially protected", "Guard cannot prove every required protection check."


def evaluate_protection_health(
    signals: Mapping[str, ProtectionSignal],
    *,
    harness_signals: Mapping[str, ProtectionSignal] | None = None,
) -> dict[str, object]:
    """Evaluate global and per-harness state without inferring missing proof."""

    unknown_ids = set(signals).difference(PROTECTION_CHECK_IDS)
    if unknown_ids:
        raise ValueError(f"unsupported protection check IDs: {', '.join(sorted(unknown_ids))}")
    ordered = [signals.get(check_id, UNKNOWN_SIGNAL) for check_id in PROTECTION_CHECK_IDS]
    state = _state_for(ordered)
    label, detail = _copy_for(state)
    shared = {
        check_id: signal
        for check_id, signal in zip(PROTECTION_CHECK_IDS, ordered, strict=True)
        if check_id != "harness_hooks"
    }
    apps: list[dict[str, object]] = []
    for harness, hook_signal in sorted((harness_signals or {}).items())[:_MAX_HARNESSES]:
        if len(harness) > 64 or not _STABLE_ID.fullmatch(harness):
            raise ValueError("harness protection identity must be a stable identifier")
        scoped_signals = {"harness_hooks": hook_signal, **shared}
        scoped_ordered = [scoped_signals[check_id] for check_id in PROTECTION_CHECK_IDS]
        scoped_state = _state_for(scoped_ordered)
        scoped_label, scoped_detail = _copy_for(scoped_state)
        apps.append(
            {
                "harness": harness,
                "state": scoped_state.value,
                "label": scoped_label,
                "detail": scoped_detail,
                "evidence_gap": any(signal.status is ProtectionCheckStatus.UNKNOWN for signal in scoped_ordered),
                "checks": [scoped_signals[check_id].to_dict(check_id) for check_id in PROTECTION_CHECK_IDS],
                "reason_codes": [signal.reason_code for signal in scoped_ordered],
            }
        )
    return {
        "schema_version": PROTECTION_HEALTH_SCHEMA_VERSION,
        "state": state.value,
        "label": label,
        "detail": detail,
        "evidence_gap": any(signal.status is ProtectionCheckStatus.UNKNOWN for signal in ordered),
        "checks": [signal.to_dict(check_id) for check_id, signal in zip(PROTECTION_CHECK_IDS, ordered, strict=True)],
        "reason_codes": [signal.reason_code for signal in ordered],
        "apps": apps,
    }


__all__ = (
    "PROTECTION_CHECK_IDS",
    "PROTECTION_HEALTH_SCHEMA_VERSION",
    "ProtectionCheckStatus",
    "ProtectionSignal",
    "ProtectionState",
    "evaluate_protection_health",
)
