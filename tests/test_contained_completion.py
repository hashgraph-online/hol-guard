"""Private one-use completion contracts; mocked receipts are not native proof."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from copy import deepcopy
from dataclasses import replace

import pytest

from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.native_policy_snapshot import provision_native_policy_verifier_key
from codex_plugin_scanner.guard.runtime import contained_completion as module

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="native completion proof is Linux-only")


@pytest.mark.parametrize("status", [0, 1])
def test_workspace_authorized_stderr_duplication_keeps_completed_output(case, monkeypatch, status):
    from codex_plugin_scanner.guard.runtime import contained_test_hook as hook
    from codex_plugin_scanner.guard.runtime.restricted_workspace import receipt_matches

    artifact, payload, options, _ = case
    command = payload["tool_input"]["command"] + " 2>&1"
    payload["tool_input"] = {"command": command}
    options["payload"]["tool_input"] = dict(payload["tool_input"])
    options["payload"]["is_error"] = status != 0
    text = module.output_text(status, "actual output", "actual diagnostic")
    options["payload"]["tool_response"] = [{"type": "text", "text": text}]
    options["native_edge"]["reviewed_output_sha256"] = hashlib.sha256(text.encode()).hexdigest()
    authorized = []

    def authorize(original):
        authorized.append(original["tool_input"]["command"])
        return {
            "decision": "deny",
            "policy_action": "sandbox-required",
            "reason_code": "native_workspace_containment_required",
            "required_execution_profile": "workspace-contained-v1",
            "command_binding_digest": hashlib.sha256(original["tool_input"]["command"].encode()).hexdigest(),
        }

    def backend(original, *, authorize, first_receipt, **kwargs):
        second = authorize(original)
        assert receipt_matches(second)
        assert second["command_binding_digest"] == first_receipt["command_binding_digest"]
        print("actual output", end="")
        print("actual diagnostic", end="", file=module.sys.stderr)
        return status

    monkeypatch.setattr(hook, "run_workspace_contained", backend)
    result = module.run_with_completion(
        lambda callback: hook.run_authorized_contained_test(
            payload, workspace=options["workspace"], authorize=callback, timeout_seconds=10
        ),
        authorize=authorize,
        payload=payload,
        harness="omp",
        workspace=options["workspace"],
        guard_home=options["guard_home"],
    )
    assert result == status
    proofs = list((options["guard_home"] / module.DIRECTORY).iterdir())
    assert len(proofs) == 1, "contained execution did not record its output proof"
    if os.environ.get("HOL_GUARD_TEST_USE_INSTALLED") != "1":
        # The builder checks this wrapper before compiling the native runtime.
        # Its post-build contract run verifies the proof with that exact binary.
        return
    completed = module.completed_output_artifact(artifact, **options)
    assert completed is not artifact, "completed original input lost its private output proof"
    assert completed.metadata["contained_completion_schema"] == module.SCHEMA
    assert authorized == [command, command]
    assert module.completed_output_artifact(artifact, **options) is artifact


@pytest.fixture(params=["destructive_shell", "execution"])
def case(tmp_path, request):
    home = tmp_path / "guard"
    home.mkdir(mode=0o700)
    provision_native_policy_verifier_key(home, b"x" * 32)
    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o700)
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "bash",
        "tool_call_id": "call-1",
        "session_id": "session-1",
        "config_path": "/public/omp.json",
        "tool_input": {"command": "python3 -m unittest discover -s tests -v"},
        "guard_contained_output_profile": "controller-contained-output.v1",
        "guard_execution_environment": {"path": "/usr/bin:/bin"},
    }
    artifact = GuardArtifact(
        artifact_id="omp:project:stable-command",
        name="bash destructive shell command",
        harness="omp",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path="/public/omp.json",
        metadata={
            "action_class": "destructive shell command",
            "risk_classes": ["destructive_shell"],
            "command_action_floor": "require-reapproval",
            "command_decision_plane": {"action": "review"},
        },
    )
    if request.param == "execution":
        payload["tool_input"] = {"command": "/usr/bin/node --test tests/node-control.test.cjs"}
        artifact = replace(
            artifact,
            metadata={
                **artifact.metadata,
                "action_class": "local script execution shell command",
                "risk_classes": ["execution"],
                "reason_code": "shell_local_script_execution_review",
            },
        )
    post = {
        **deepcopy(payload),
        "hook_event_name": "PostToolUse",
        "tool_response": [{"type": "text", "text": module.output_text(0, "actual output", "actual diagnostic")}],
        "is_error": False,
    }
    edge = {
        "decision": "allow",
        "policy_action": "warn",
        "model_output_action": "allow_original",
        "reviewed_output_sha256": hashlib.sha256(post["tool_response"][0]["text"].encode()).hexdigest(),
    }
    options = {
        "payload": post,
        "harness": "omp",
        "workspace": workspace,
        "guard_home": home,
        "native_edge": edge,
        "has_data_flow": False,
        "config": GuardConfig(guard_home=home, workspace=workspace),
    }

    def record(**changes):
        kwargs = {
            "payload": payload,
            "harness": "omp",
            "workspace": workspace,
            "guard_home": home,
            "exit_code": 0,
            "stdout": "actual output",
            "stderr": "actual diagnostic",
            "receipts": ["native-binding"] * 2,
        }
        return module.record_completion(**{**kwargs, **changes})

    return artifact, payload, options, record


def test_without_actual_private_completion_default_execution_policy_stays(case):
    artifact, _, options, _ = case
    assert module.completed_output_artifact(artifact, **options) is artifact
    assert artifact.metadata["command_action_floor"] == "require-reapproval"


def test_proof_is_output_only_one_use_and_retains_configured_artifact_identity(case):
    artifact, _, options, record = case
    assert record()
    completed = module.completed_output_artifact(artifact, **options)
    assert completed.artifact_id == artifact.artifact_id and completed.config_path == artifact.config_path
    assert completed.harness == artifact.harness and completed.source_scope == artifact.source_scope
    assert completed.metadata["contained_completion_schema"] == module.SCHEMA
    assert completed.metadata["guard_default_action"] == "warn"
    assert "command_action_floor" not in completed.metadata
    assert completed.metadata.get("reason_code") != "shell_local_script_execution_review"
    assert artifact.metadata["command_action_floor"] == "require-reapproval"
    assert module.completed_output_artifact(artifact, **options) is artifact
    assert list((options["guard_home"] / module.DIRECTORY).iterdir()) == []


@pytest.mark.parametrize(
    "field,value",
    [
        ("hook_event_name", "PreToolUse"),
        ("tool_call_id", "other"),
        ("session_id", "other"),
        ("tool_input", {"command": "rm -rf /"}),
        ("is_error", True),
        ("guard_contained_output_profile", "forged-profile"),
        ("tool_response", [{"type": "text", "text": "forged output"}]),
    ],
)
def test_changed_context_or_output_cannot_claim_completion(case, field, value):
    artifact, _, options, record = case
    assert record()
    options["payload"][field] = value
    # An attacker cannot avoid the independent native review binding check.
    if field == "tool_response":
        options["native_edge"]["reviewed_output_sha256"] = hashlib.sha256(b"forged output").hexdigest()
    assert module.completed_output_artifact(artifact, **options) is artifact


@pytest.mark.parametrize(
    "change",
    [
        {"has_data_flow": True},
        {"native_edge": None},
        {"harness": "codex"},
        {"native_edge": {"decision": "deny", "policy_action": "block"}},
    ],
)
def test_native_output_and_data_flow_floors_remain_authoritative(case, change):
    artifact, _, options, record = case
    assert record()
    assert module.completed_output_artifact(artifact, **{**options, **change}) is artifact


@pytest.mark.parametrize(
    "metadata",
    [
        {"command_action_floor": "block"},
        {"action_class": "credential-looking tool output"},
        {"risk_classes": ["destructive_shell", "credential_read"]},
        {"risk_classes": ["execution", "execution"]},
        {"risk_classes": "execution"},
        {"compound_finding_count": 2},
        {"compound_finding_count": True},
        {"compound_finding_count": 1.0},
    ],
)
def test_explicit_current_blocks_sensitive_or_compound_artifacts_stay(case, metadata):
    artifact, _, options, record = case
    assert record()
    artifact = replace(artifact, metadata={**artifact.metadata, **metadata})
    assert module.completed_output_artifact(artifact, **options) is artifact


@pytest.mark.parametrize("reason", [None, "shell_sensitive_execution", "", True])
def test_local_script_completion_requires_exact_default_reason(case, reason):
    artifact, _, options, record = case
    artifact = replace(
        artifact,
        metadata={
            **artifact.metadata,
            "action_class": "local script execution shell command",
            "risk_classes": ["execution"],
            "reason_code": reason,
        },
    )
    assert record()
    assert module.completed_output_artifact(artifact, **options) is artifact


def test_completed_local_script_retires_only_execution_stage_reason(case):
    from codex_plugin_scanner.guard.cli.commands_support_runtime_artifact_policy import runtime_policy_artifact_facts

    artifact, _, options, record = case
    if artifact.metadata["risk_classes"] != ["execution"]:
        return
    assert runtime_policy_artifact_facts(options["config"], artifact, "omp")["shell_local_script_review"]
    assert record()
    completed = module.completed_output_artifact(artifact, **options)
    assert completed.metadata["contained_completion_original_reason_code"] == "shell_local_script_execution_review"
    assert not runtime_policy_artifact_facts(options["config"], completed, "omp")["shell_local_script_review"]


@pytest.mark.parametrize("receipts", [[], ["only-one"], ["changed", "binding"], [None, None], [True, True]])
def test_caller_flag_never_replaces_two_matching_live_receipts(case, receipts):
    _, _, options, record = case
    assert not record(receipts=receipts)
    assert not (options["guard_home"] / module.DIRECTORY).exists()


def test_expiry_uses_real_elapsed_time_and_boot_identity(case):
    artifact, _, options, record = case
    assert record()
    path = next((options["guard_home"] / module.DIRECTORY).iterdir())
    row = json.loads(path.read_bytes())
    row["created_ns"] = time.monotonic_ns() - module.TTL_NS - 1_000_000_000
    row["expires_ns"] = row["created_ns"] + module.TTL_NS
    path.write_bytes(module._canonical(row))
    assert module.completed_output_artifact(artifact, **options) is artifact
    assert record()
    path = next((options["guard_home"] / module.DIRECTORY).iterdir())
    row = json.loads(path.read_bytes())
    row["boot_id"] = "different-boot"
    path.write_bytes(module._canonical(row))
    assert module.completed_output_artifact(artifact, **options) is artifact


@pytest.mark.parametrize("mutation", ["world-readable", "symlink", "duplicate", "boolean-time"])
def test_private_state_tamper_fails_closed_without_following_paths(case, mutation):
    artifact, _, options, record = case
    assert record()
    path = next((options["guard_home"] / module.DIRECTORY).iterdir())
    if mutation == "world-readable":
        path.chmod(0o644)
    elif mutation == "symlink":
        outside = options["workspace"] / "outside"
        outside.write_text("not a receipt")
        path.unlink()
        path.symlink_to(outside)
    elif mutation == "duplicate":
        raw = path.read_text()
        path.write_text('{"schema":"forged",' + raw[1:])
    else:
        value = json.loads(path.read_bytes())
        value["created_ns"] = True
        path.write_text(json.dumps(value))
    assert module.completed_output_artifact(artifact, **options) is artifact
    assert not list((options["guard_home"] / module.DIRECTORY).iterdir())


def test_opt_in_capture_forwards_exact_text_and_never_records_exceptions(case, capsys):
    artifact, payload, options, _ = case
    receipt = {
        "decision": "deny",
        "policy_action": "sandbox-required",
        "reason_code": "native_workspace_containment_required",
        "required_execution_profile": "workspace-contained-v1",
        "command_binding_digest": "native-bound",
    }

    def run(authorize):
        authorize(payload)
        authorize(payload)
        print("actual output", end="")
        print("actual diagnostic", end="", file=module.sys.stderr)
        return 0

    assert (
        module.run_with_completion(
            run,
            authorize=lambda _: receipt,
            payload=payload,
            harness="omp",
            workspace=options["workspace"],
            guard_home=options["guard_home"],
        )
        == 0
    )
    captured = capsys.readouterr()
    assert captured.out == "actual output" and captured.err == "actual diagnostic"
    assert module.completed_output_artifact(artifact, **options) is not artifact

    def interrupted(authorize):
        authorize(payload)
        authorize(payload)
        raise InterruptedError("real runner interrupted")

    with pytest.raises(InterruptedError):
        module.run_with_completion(
            interrupted,
            authorize=lambda _: receipt,
            payload=payload,
            harness="omp",
            workspace=options["workspace"],
            guard_home=options["guard_home"],
        )
    assert not list((options["guard_home"] / module.DIRECTORY).iterdir())


def test_unprotected_guard_home_cannot_mint_completion(case):
    _, _, options, record = case
    options["guard_home"].chmod(0o755)
    assert not record()
    options["guard_home"].chmod(0o700)
    assert os.getuid() == options["guard_home"].stat().st_uid


def test_failed_durable_capture_cannot_leave_a_claimable_record(case, monkeypatch):
    artifact, _, options, record = case

    def fail_sync(_descriptor):
        raise OSError("test durability failure")

    monkeypatch.setattr(module.os, "fsync", fail_sync)
    assert not record()
    assert module.completed_output_artifact(artifact, **options) is artifact
    assert not list((options["guard_home"] / module.DIRECTORY).iterdir())


def test_explicit_artifact_policy_override_stays_bound_to_same_identity(case):
    from codex_plugin_scanner.guard.config import GuardConfig

    artifact, _, options, record = case
    config = GuardConfig(
        guard_home=options["guard_home"],
        workspace=options["workspace"],
        artifact_actions={artifact.artifact_id: "block"},
    )
    assert record()
    completed = module.completed_output_artifact(artifact, **options)
    assert completed is not artifact
    assert config.resolve_action_override("omp", completed.artifact_id, completed.publisher) == "block"


@pytest.mark.parametrize("action", ["block", "require-reapproval", "review", "sandbox-required"])
@pytest.mark.parametrize("scope", ["global", "harness"])
def test_explicit_risk_policy_is_never_erased_by_completed_proof(case, action, scope):
    artifact, _, options, record = case
    assert record()
    risk = artifact.metadata["risk_classes"][0]
    if scope == "global":
        options["config"] = replace(options["config"], risk_actions={risk: action})
    else:
        options["config"] = replace(options["config"], harness_risk_actions={"omp": {risk: action}})
    assert module.completed_output_artifact(artifact, **options) is artifact
