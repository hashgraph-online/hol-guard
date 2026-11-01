"""Test drivers that decode authoritative decisions through the native authority."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from codex_plugin_scanner.guard.native_decisions import _shape, decision_authority
from codex_plugin_scanner.guard.runtime.decisions import AuthoritativeGuardDecision, _authoritative


def project_native_authoritative_decision(payload: dict[str, Any]) -> AuthoritativeGuardDecision:
    """Project a decision already bound by another native operation, without RPC."""

    _shape(payload, "authoritative")
    return _authoritative(payload)


def authoritative_decision_from_artifact(
    payload: Mapping[str, object],
    *,
    require_authoritative: bool = False,
) -> AuthoritativeGuardDecision:
    return _authoritative(
        decision_authority(
            "decision_artifact_decode",
            {
                "payload": dict(payload),
                "require_authoritative": require_authoritative,
            },
        )
    )
