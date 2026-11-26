from __future__ import annotations

import json
import uuid

import pytest

from codex_plugin_scanner.guard.runtime_transition_hook_probe import (
    PROBE_FIELD,
    PROBE_SCHEMA,
    transition_hook_observation,
    transition_hook_probe,
)
from tests.test_native_decision_receipt import _receipt


def probe_payload(command="pwd"):
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        PROBE_FIELD: {
            "schema": PROBE_SCHEMA,
            "operation_id": str(uuid.uuid4()),
            "request_id": "transition-hook-" + uuid.uuid4().hex,
        },
    }


@pytest.mark.parametrize("fault", ["missing", "extended", "schema", "operation", "request", "not_object"])
def test_probe_metadata_is_strict_and_never_a_decision_override(fault):
    payload = probe_payload()
    if fault == "missing":
        payload.pop(PROBE_FIELD)
    elif fault == "not_object":
        payload[PROBE_FIELD] = "allow"
    else:
        field, value = {
            "extended": ("approval", "allow"),
            "schema": ("schema", "foreign"),
            "operation": ("operation_id", "foreign"),
            "request": ("request_id", "request-1"),
        }[fault]
        payload[PROBE_FIELD][field] = value
    assert transition_hook_probe(payload) is None
    assert transition_hook_observation(payload, None) is None


@pytest.mark.parametrize("fault", [None, "request", "event", "harness", "observe", "secret"])
def test_bridge_probe_sideband_requires_fresh_redacted_enforcing_receipt(fault):
    payload = probe_payload()
    request_id = payload[PROBE_FIELD]["request_id"]
    overrides = {"request_id": request_id, "harness": "codex", "event_name": "PreToolUse"}
    if fault in {"request", "event", "harness", "observe"}:
        field, value = {
            "request": ("request_id", "foreign"),
            "event": ("event_name", "PostToolUse"),
            "harness": ("harness", "claude-code"),
            "observe": ("observe_mode", True),
        }[fault]
        overrides[field] = value
    receipt = _receipt(**overrides)
    if fault == "secret":
        receipt["command"] = "private command must not be emitted"
    observation = transition_hook_observation(payload, receipt)
    if fault is None:
        assert observation is not None and "private command must not be emitted" not in json.dumps(observation)
    else:
        assert observation is None


def test_omp_receipt_is_bound_to_fresh_probe_id():
    """The OMP transport uses the same strict receipt correlation as Codex."""
    payload = probe_payload("ollama rm synthetic-model")
    request_id = payload[PROBE_FIELD]["request_id"]
    receipt = _receipt(
        request_id=request_id,
        harness="omp",
        event_name="PreToolUse",
        decision="deny",
        model_output_action="block",
        policy_action="block",
        observed_policy_action="block",
        reason_code="native_command_permission_disabled",
    )
    observation = transition_hook_observation(payload, receipt)
    assert observation is not None
    assert observation["native_receipt"]["harness"] == "omp"
    assert observation["native_receipt"]["decision_id"] == receipt["decision_id"]


def test_probe_spends_no_more_than_the_hook_has_left(monkeypatch):
    import time

    from codex_plugin_scanner.guard import runtime_transition_hook_probe as module

    calls = []

    def digest(kind, material, **kwargs):
        calls.append(kwargs)
        return None

    monkeypatch.setattr(module, "native_context_digest", digest)
    deadline = time.monotonic() + 0.4

    assert transition_hook_probe(probe_payload(), deadline_monotonic=deadline) is None
    assert calls[-1]["hard_deadline_monotonic"] == deadline
    # The digest grants a cold resident a multi-second allowance on top of its
    # timeout; the hard deadline is what keeps that inside the hook's answer.
    assert 0 < calls[-1]["timeout_seconds"] <= 0.4

    transition_hook_probe(probe_payload())
    assert "hard_deadline_monotonic" not in calls[-1]
