from __future__ import annotations

import json
import time
import uuid

import pytest

from codex_plugin_scanner.guard.adapters import codex_daemon_hook_bridge as bridge
from codex_plugin_scanner.guard.runtime_transition_hook_probe import (
    OBSERVATION_FIELD,
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
def test_bridge_probe_sideband_requires_fresh_redacted_enforcing_receipt(capsys, fault):
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
    response = {"policy_action": "allow", "hookSpecificOutput": {"permissionDecision": "allow"}}
    ordinary = bridge._codex_hook_response(response, event_name="PreToolUse")
    if observation is not None:
        response[OBSERVATION_FIELD] = observation
    bridge._write_transition_observation(json.dumps(payload), response)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert bridge._codex_hook_response(response, event_name="PreToolUse") == ordinary
    if fault is None:
        assert json.loads(captured.err) == observation
    else:
        assert observation is None and captured.err == ""


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


@pytest.mark.parametrize("layout", ["legacy", "current", "partial", "foreign_path"])
def test_observation_package_identity_requires_complete_new_roles_and_preserves_legacy(monkeypatch, layout):
    from pathlib import Path

    from codex_plugin_scanner.guard import codex_hook_runtime_trust as trust
    from codex_plugin_scanner.guard.adapters.codex import _hook_packaged_file_paths

    paths = dict(_hook_packaged_file_paths())
    assert {"hook_probe", "native_receipt"} <= paths.keys()
    if layout == "legacy":
        paths.pop("hook_probe")
        paths.pop("native_receipt")
    elif layout == "partial":
        paths.pop("native_receipt")
    elif layout == "foreign_path":
        paths["hook_probe"] = Path("/untrusted/probe.py")
    manifest = {"packaged_files": [{"role": role, "path": str(path)} for role, path in paths.items()]}
    # File identity validation is covered by the authenticated install suites;
    # this fixture isolates legacy/new dependency-set and path admission.
    monkeypatch.setattr(trust, "verify_regular_file_identity", lambda _identity: None)
    if layout in {"partial", "foreign_path"}:
        with pytest.raises(ValueError):
            identities = trust._verified_packaged_files(manifest)
            trust._verify_transport(identities, manifest)
    else:
        assert set(trust._verified_packaged_files(manifest)) == set(paths)


@pytest.mark.usefixtures("native_hook_force")
@pytest.mark.parametrize("command,decision", [("pwd", "allow"), ("rm -rf /", "deny")])
def test_actual_native_hook_worker_binds_observation_to_fresh_probe_id(tmp_path, capsys, command, decision):
    from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
    from codex_plugin_scanner.guard.native_resident_client import close_native_residents
    from codex_plugin_scanner.guard.store import GuardStore

    home, workspace = tmp_path / "guard-home", tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(home)
    deadline = time.monotonic() + 10
    worker = HookWorker(store=store)
    payload = probe_payload(command)
    try:
        result = worker.review_http_payload(
            payload=payload,
            params={},
            default_harness="codex",
            home_dir=tmp_path,
            guard_home=home,
            workspace=workspace,
            deadline=deadline,
        )
        receipt = worker.last_native_decision_receipt
        assert receipt is not None and receipt["decision"] == decision
        observation = transition_hook_observation(payload, receipt)
        assert observation is not None
        assert observation["request_id"] == payload[PROBE_FIELD]["request_id"]
        result[OBSERVATION_FIELD] = observation
        bridge._write_transition_observation(json.dumps(payload), result)
        assert json.loads(capsys.readouterr().err) == observation
    finally:
        assert worker.close(deadline_monotonic=deadline)
        assert close_native_residents(guard_home=home, deadline_monotonic=deadline)
