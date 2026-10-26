"""Observation responses cannot advertise approval capabilities."""

from typing import Any

import pytest

from codex_plugin_scanner.guard.daemon import hook_native_exact_action as bridge


def _response() -> dict[str, Any]:
    return {
        "evidence": {
            "schema": "guard-native-launch-evidence.v1",
            "inventory_sha256": "a" * 64,
            "code_identity_complete": False,
            "unknown_edges": ["unverified_code_closure"],
            "risk_verdict": "not_evaluated",
            "execution_binding": "unavailable",
            "duration": "none",
            "scope": "observed_invocation",
            "can_run_once": False,
            "can_persist": False,
        },
        "unavailable_reason": None,
    }


@pytest.mark.parametrize(
    "field,value",
    [
        ("code_identity_complete", True),
        ("can_run_once", True),
        ("can_persist", True),
        ("can_persist", 0),
        ("duration", "persistent"),
        ("execution_binding", "bound"),
        ("risk_verdict", "safe"),
        ("unknown_edges", []),
        ("scope", "project"),
        ("inventory_sha256", "guard-approval-context:v1:" + "a" * 64),
        ("inventory_sha256", "A" * 64),
        ("token", "a" * 64),
    ],
)
def test_observation_rejects_authority_or_ambiguous_identity(field, value):
    response = _response()
    bridge._validate_launch_evidence(response)
    response["evidence"][field] = value
    with pytest.raises(bridge.NativeExactActionError, match="native_exact_action_payload_invalid"):
        bridge._validate_launch_evidence(response)


def test_observation_requires_an_exclusive_known_refusal():
    response = _response()
    response["unavailable_reason"] = "unproven_launch"
    with pytest.raises(bridge.NativeExactActionError):
        bridge._validate_launch_evidence(response)
    response["evidence"] = None
    bridge._validate_launch_evidence(response)
    for invalid in (None, "allow", "unverified_code_closure"):
        response["unavailable_reason"] = invalid
        with pytest.raises(bridge.NativeExactActionError):
            bridge._validate_launch_evidence(response)
