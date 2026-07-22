"""Canonical command risk-class to effect-kind mapping."""

from __future__ import annotations

from collections.abc import Iterable
from types import MappingProxyType
from typing import Final

from .effect_contract import EffectKind

COMMAND_RISK_EFFECTS: Final = MappingProxyType(
    {
        "credential_exfiltration": frozenset({EffectKind.CREDENTIAL_OR_SECRET_OPERATION}),
        "data_flow_exfiltration": frozenset({EffectKind.NETWORK_WRITE}),
        "destructive_shell": frozenset({EffectKind.DESTRUCTIVE_OR_IRREVERSIBLE_OPERATION}),
        "encoded_execution": frozenset({EffectKind.PROCESS_EXECUTION}),
        "execution": frozenset({EffectKind.PROCESS_EXECUTION}),
        "local_secret_read": frozenset({EffectKind.SENSITIVE_READ}),
        "network_egress": frozenset({EffectKind.NETWORK_WRITE}),
        "policy_bypass": frozenset({EffectKind.GUARD_CONTROL_OPERATION}),
        "supply_chain": frozenset({EffectKind.PACKAGE_OR_SOURCE_INSTALLATION}),
    }
)


def command_risk_effects(
    risk_classes: Iterable[str],
    *,
    unknown_fallback: frozenset[EffectKind] | None = None,
) -> frozenset[EffectKind]:
    """Resolve effect kinds, rejecting unknown classes unless policy supplies a fallback."""

    effects: set[EffectKind] = set()
    for risk_class in risk_classes:
        mapped = COMMAND_RISK_EFFECTS.get(risk_class)
        if mapped is None:
            if unknown_fallback is None:
                raise ValueError(f"unsupported command risk class: {risk_class}")
            mapped = unknown_fallback
        effects.update(mapped)
    return frozenset(effects)
