import hashlib
import json

import pytest

from ci.gauntlet.contained import _contained_case_batches, _ContainedRequestCapture, _source_snapshots_match
from ci.gauntlet.contained_judge import (
    _contained_workspace_identity_matches,
    _contained_wrapper_argv,
    assess_contained_execution,
)
from ci.gauntlet.evidence import public_events
from ci.gauntlet.input_evidence import input_digest
from ci.native_runtime.probe_workflow_matrix import contained_vitest_cases


def _project(tmp_path):
    project = tmp_path / "contained-project"
    (project / "tests").mkdir(parents=True)
    (project / "tests/workflow.test.mjs").write_text('import { test } from "vitest";\ntest("workflow", () => {});\n')
    (project / "tests/secondary.test.mjs").write_text('import { test } from "vitest";\ntest("secondary", () => {});\n')
    (project / "node_modules/vitest").mkdir(parents=True)
    (project / "node_modules/vitest/vitest.mjs").write_text("export {};\n")
    (project / "node_modules/.bin").mkdir()
    (project / "node_modules/.bin/vitest").symlink_to("../vitest/vitest.mjs")
    return project


_REQUEST_PATH = "/owned/hol-guard-contained-test-test/request.json"


def _contained_wrapper_command(workspace="/contained-project", request_sha="a" * 64):
    return (
        "'/fixture/bin/hol-guard' 'execute-contained-test' '--guard-home' '/fixture/guard-home' "
        "'--workspace' "
        f"'{workspace}' '--request-file' '{_REQUEST_PATH}' "
        f"'--request-sha256' '{request_sha}' '--home' '/fixture/home'"
    )


def _contained_events(
    case, *, exit_code=0, include_exit_code=True, wrapper_workspace="/contained-project", request_sha="a" * 64
):
    # This is the sanitized public OMP shape: the model/host carry the wrapper,
    # while the result details retain the exact original Bun command.
    tool_input = {"command": _contained_wrapper_command(wrapper_workspace, request_sha)}
    result_details = {
        "holGuardContainedTest": {
            "schema": "guard-contained-test-presentation.v1",
            "toolCallId": "call-1",
            "input": {"command": case.command},
            "command": _contained_wrapper_command(wrapper_workspace, request_sha),
        },
    }
    if include_exit_code:
        result_details["exitCode"] = exit_code
    return [
        {
            "type": "message_end",
            "message": {
                "role": "assistant",
                "provider": "gauntlet-live",
                "model": "deepseek",
                "content": [{"type": "toolCall", "id": "call-1", "name": "bash", "arguments": tool_input}],
            },
        },
        {
            "type": "tool_execution_start",
            "toolCallId": "call-1",
            "toolName": "bash",
            "args": tool_input,
        },
        {
            "type": "tool_execution_end",
            "toolCallId": "call-1",
            "toolName": "bash",
            "isError": False,
            "result": {
                "details": result_details,
                "content": [{"type": "text", "text": "2 passed"}],
            },
        },
        {"type": "agent_end", "isTerminal": True},
    ]


def _assessment_inputs(case, *, filesystem=None, events=None, wrapper_workspace="/contained-project"):
    original_input = {"command": case.command}
    request = {
        "schema": "guard-contained-test-request.v1",
        "workspace": wrapper_workspace,
        "payload": {
            "hook_event_name": "PreToolUse",
            "config_path": "/fixture/settings.json",
            "tool_call_id": "call-1",
            "session_id": "session-1",
            "tool_name": "bash",
            "tool_input": original_input,
        },
    }
    request_bytes = json.dumps(request, separators=(",", ":")).encode()
    request_sha = hashlib.sha256(request_bytes).hexdigest()
    raw_events = events or _contained_events(
        case,
        wrapper_workspace=wrapper_workspace,
        request_sha=request_sha,
    )
    public = public_events(raw_events, {})
    tool_input = {"command": _contained_wrapper_command(wrapper_workspace, request_sha)}
    digest = input_digest(tool_input)
    original_digest = input_digest(original_input)
    observations = [
        {
            "tool_call_id": "call-1",
            "event": "PreToolUse",
            "tool": "bash",
            "decision": "deny",
            "reason_code": "native_vitest_readonly_containment_required",
            "policy_action": "sandbox-required",
            "http_status": 200,
            "input": original_input,
            "input_sha256": original_digest,
            "observed_input_sha256": "a" * 64,
            "native_observation": {
                "native_receipt": {
                    "authority": "rust",
                    "harness": "omp",
                    "event_name": "PreToolUse",
                    "decision": "deny",
                    "policy_action": "sandbox-required",
                    "reason_code": "native_vitest_readonly_containment_required",
                    "request_id": "request-1",
                    "decision_id": "decision-1",
                    "command_extensions": {
                        "program_digest": "a" * 64,
                        "catalog_digest": "b" * 64,
                        "trust_digest": "c" * 64,
                    },
                },
                "required_execution_profile": "vitest-readonly-v1",
            },
            "probe_request_id": "request-1",
        },
        {
            "tool_call_id": "call-1",
            "event": "PostToolUse",
            "tool": "bash",
            "decision": "allow",
            "reason_code": "native_policy_allow",
            "policy_action": "allow",
            "http_status": 200,
            "input": tool_input,
            "input_sha256": digest,
            "observed_input_sha256": "b" * 64,
        },
    ]
    return {
        "raw_events": raw_events,
        "events": public,
        "guard_observations": observations,
        "native_routes": {"native_resident": 2},
        "inference": {
            "live_rounds": [
                {
                    "status": "completed",
                    "request_sha256": "c" * 64,
                    "response_sha256": "d" * 64,
                    "response_bytes": 1,
                    "response_models": ["deepseek"],
                }
            ],
            "canary_export_violations": 0,
        },
        "filesystem": filesystem
        or {
            "contained-test-files-unchanged": True,
            "contained-dependencies-unchanged": True,
            "contained-project-files-unchanged": True,
            "contained-project-local-dependencies": True,
        },
        "returncode": 0,
        "timed_out": False,
        "cleanup_ok": True,
        "approval_delta": 0,
        "egress_requests": [],
        "expected_commands": [case.command],
        "caller_workspaces": ["/contained-project"],
        "target_workspaces": [None],
        "expected_wrapper": "/fixture/bin/hol-guard",
        "expected_guard_home": "/fixture/guard-home",
        "expected_home": "/fixture/home",
        "request_records": {_REQUEST_PATH: request_bytes},
        "request_workspaces": [wrapper_workspace],
    }


def test_contained_factory_returns_the_reviewed_seven_commands(tmp_path):
    cases = contained_vitest_cases(_project(tmp_path))

    assert [case.name for case in cases] == [
        "bunx-vitest",
        "bun-x-vitest",
        "bun-no-install",
        "bun-cwd",
        "bun-cwd-equals",
        "bun-cross-project",
        "bun-cross-project-equals",
    ]
    assert all(case.protected_reason == "native_vitest_readonly_containment_required" for case in cases)
    assert all("execute-contained-test" not in case.command for case in cases)


def test_contained_batches_derive_caller_workspace_from_case_identity(tmp_path):
    project = _project(tmp_path)
    workspace = tmp_path / "caller-workspace"
    workspace.mkdir()
    cases = contained_vitest_cases(project)

    batches = _contained_case_batches(cases, project, workspace)

    assert [[case.name for case in batch] for batch, _ in batches] == [
        [case.name for case in cases[:5]],
        ["bun-cross-project", "bun-cross-project-equals"],
    ]
    assert [cwd for _, cwd in batches] == [project, workspace]


def test_contained_factory_requires_both_fixture_tests_and_local_dependencies(tmp_path):
    project = _project(tmp_path)
    outside = tmp_path / "outside-vitest.mjs"
    outside.write_text("export {};\n")
    (project / "node_modules/.bin/vitest").unlink()
    (project / "node_modules/.bin/vitest").symlink_to(outside)

    with pytest.raises(AssertionError, match="escapes project"):
        contained_vitest_cases(project)

    project = _project(tmp_path / "missing")
    (project / "tests/secondary.test.mjs").unlink()
    with pytest.raises(AssertionError, match="two-file"):
        contained_vitest_cases(project)


def test_contained_request_capture_is_root_scoped(tmp_path):
    owned = tmp_path / "request-tmp"
    unrelated = tmp_path / "unrelated-tmp"
    owned.mkdir(mode=0o700)
    unrelated.mkdir(mode=0o700)
    owned_request = owned / "hol-guard-contained-test-owned" / "request.json"
    unrelated_request = unrelated / "hol-guard-contained-test-unrelated" / "request.json"
    owned_request.parent.mkdir(mode=0o700)
    unrelated_request.parent.mkdir(mode=0o700)
    owned_request.write_bytes(b"owned")
    unrelated_request.write_bytes(b"unrelated")
    owned_request.chmod(0o600)
    unrelated_request.chmod(0o600)

    capture = _ContainedRequestCapture(owned)
    capture._scan_once()

    assert str(owned_request) in capture.records
    assert str(unrelated_request) not in capture.records


def test_contained_assessment_requires_native_sink_and_physical_proof(tmp_path):
    case = contained_vitest_cases(_project(tmp_path))[0]
    inputs = _assessment_inputs(case)

    result = assess_contained_execution([case], **inputs)

    assert result["profile_pass"] is True
    assert result["cases"][0]["outcome"] == "pass"
    assert result["request_proofs"][0]["schema"] == "guard-contained-test-request-proof.v1"

    missing_route = {**inputs, "native_routes": {"python_fallback": 2}}
    result = assess_contained_execution([case], **missing_route)
    assert result["profile_pass"] is False
    assert result["cases"][0]["outcome"] == "harness-error"

    missing_physical = {**inputs, "filesystem": {"contained-test-files-unchanged": True}}
    result = assess_contained_execution([case], **missing_physical)
    assert result["profile_pass"] is False
    assert result["cases"][0]["outcome"] == "task-incomplete"


def test_contained_snapshot_covers_new_project_files(tmp_path):
    from ci.gauntlet.contained_judge import _contained_project_checks, _contained_project_snapshot

    project = _project(tmp_path)
    before = _contained_project_snapshot(project)
    (project / "unreviewed-source.mjs").write_text("export const changed = true;\n")

    checks, after = _contained_project_checks(project, before)

    assert after is not None
    assert checks["contained-project-files-unchanged"] is False


def test_contained_assessment_binds_wrapper_and_cross_project_workspaces(tmp_path):
    project = _project(tmp_path)
    case = contained_vitest_cases(project)[5]
    inputs = _assessment_inputs(case, wrapper_workspace="/caller-workspace")
    inputs["caller_workspaces"] = ["/caller-workspace"]
    inputs["target_workspaces"] = [str(project)]

    result = assess_contained_execution([case], **inputs)
    assert result["profile_pass"] is True

    same_workspace = _assessment_inputs(case, wrapper_workspace=str(project))
    same_workspace["caller_workspaces"] = [str(project)]
    same_workspace["target_workspaces"] = [str(project)]
    result = assess_contained_execution([case], **same_workspace)
    assert result["profile_pass"] is False
    assert "distinct caller and target" in result["cases"][0]["reason"]

    wrong_wrapper = _assessment_inputs(case)
    wrong_wrapper["expected_wrapper"] = "/fixture/bin/fake-wrapper"
    result = assess_contained_execution([case], **wrong_wrapper)
    assert result["profile_pass"] is False
    assert "approved Guard wrapper path" in result["cases"][0]["reason"]


def test_contained_assessment_binds_equals_form_cross_project_workspace(tmp_path):
    project = _project(tmp_path)
    case = contained_vitest_cases(project)[6]
    inputs = _assessment_inputs(case, wrapper_workspace="/caller-workspace")
    inputs["caller_workspaces"] = ["/caller-workspace"]
    inputs["target_workspaces"] = [str(project)]

    result = assess_contained_execution([case], **inputs)

    assert result["profile_pass"] is True


def test_contained_wrapper_accepts_only_known_redacted_absolute_alias():
    command = _contained_wrapper_command("{{contained_project}}").replace(
        "'/fixture/bin/hol-guard'", "'{{contained_project}}/bin/hol-guard'"
    )
    valid = _contained_wrapper_argv(
        command,
        expected_wrapper="{{contained_project}}/bin/hol-guard",
        expected_guard_home="/fixture/guard-home",
        expected_workspace="{{contained_project}}",
        expected_home="/fixture/home",
    )
    assert valid[1] is None

    invalid = _contained_wrapper_argv(
        command.replace("{{contained_project}}/bin", "relative/bin"),
        expected_wrapper="relative/bin/hol-guard",
        expected_guard_home="/fixture/guard-home",
        expected_workspace="{{contained_project}}",
        expected_home="/fixture/home",
    )
    assert invalid[0] is None
    assert "approved Guard wrapper path" in invalid[1]


def test_contained_request_workspace_accepts_only_absolute_same_realpath(tmp_path):
    physical = tmp_path / "caller"
    physical.mkdir()
    alias = tmp_path / "caller-alias"
    alias.symlink_to(physical, target_is_directory=True)

    assert _contained_workspace_identity_matches(str(alias), str(physical))
    assert not _contained_workspace_identity_matches("caller", str(physical))
    assert not _contained_workspace_identity_matches(str(tmp_path / "other"), str(physical))


def test_contained_assessment_rejects_shell_syntax_in_request_path(tmp_path):
    case = contained_vitest_cases(_project(tmp_path))[0]
    unsafe_path = "/owned/hol-guard-contained-test-test;echo/request.json"
    unsafe_wrapper = _contained_wrapper_command().replace(_REQUEST_PATH, unsafe_path)
    raw_events = _contained_events(case)
    raw_events[0]["message"]["content"][0]["arguments"]["command"] = unsafe_wrapper
    raw_events[1]["args"]["command"] = unsafe_wrapper
    raw_events[2]["result"]["details"]["holGuardContainedTest"]["command"] = unsafe_wrapper
    inputs = _assessment_inputs(case, events=raw_events)
    post = inputs["guard_observations"][1]
    post["input"] = {"command": unsafe_wrapper}
    post["input_sha256"] = input_digest(post["input"])

    result = assess_contained_execution([case], **inputs)

    assert result["profile_pass"] is False
    assert "shell syntax" in result["cases"][0]["reason"]


@pytest.mark.parametrize("profile", [None, "wrong-profile"])
def test_contained_assessment_requires_native_execution_profile(tmp_path, profile):
    case = contained_vitest_cases(_project(tmp_path))[0]
    inputs = _assessment_inputs(case)
    native = inputs["guard_observations"][0]["native_observation"]
    if profile is None:
        native.pop("required_execution_profile")
    else:
        native["required_execution_profile"] = profile

    result = assess_contained_execution([case], **inputs)

    assert result["profile_pass"] is False
    assert "authoritative Rust denial receipt" in result["cases"][0]["reason"]


@pytest.mark.parametrize("exit_code", [1, False, "0"])
def test_contained_assessment_rejects_unproven_success_output(tmp_path, exit_code):
    case = contained_vitest_cases(_project(tmp_path))[0]
    raw_events = _contained_events(case, exit_code=exit_code)
    result = assess_contained_execution([case], **_assessment_inputs(case, events=raw_events))

    assert result["profile_pass"] is False
    assert result["cases"][0]["outcome"] == "harness-error"
    assert any("did not exit successfully" in error for error in result["protocol_errors"])


def test_contained_profile_cli_contract_requires_explicit_project(monkeypatch, capsys):
    from ci.gauntlet import __main__

    monkeypatch.setenv("GUARD_GAUNTLET_PROVIDER_URL", "http://127.0.0.1:9")
    monkeypatch.setenv("GUARD_GAUNTLET_MODEL", "deepseek")
    monkeypatch.setenv("GUARD_GAUNTLET_PROVIDER_IDENTITY", "focused-test")
    monkeypatch.setattr(
        "sys.argv",
        [
            "gauntlet",
            "run",
            "--expected-source-sha",
            "a" * 40,
            "--output",
            "/owned/gauntlet-contained-contract-test",
            "--profile",
            "contained-bun-vitest",
            "--allow-loopback-provider",
        ],
    )

    assert __main__.main() == 2
    assert "requires --contained-test-project" in capsys.readouterr().err


def test_contained_evidence_helper_is_json_safe(tmp_path):
    case = contained_vitest_cases(_project(tmp_path))[0]
    evidence = _assessment_inputs(case)
    evidence.pop("request_records")
    json.dumps(evidence)


def test_contained_profile_rejects_source_or_runner_drift():
    binding = {"tested_source_sha": "a" * 40, "candidate_sha": "a" * 40}
    runner_files = {"contained.py": "before", "runner.py": "before"}

    assert _source_snapshots_match(binding, dict(binding), runner_files, dict(runner_files))
    assert not _source_snapshots_match(
        binding,
        {**binding, "tested_source_sha": "b" * 40},
        runner_files,
        runner_files,
    )
    assert not _source_snapshots_match(
        binding,
        dict(binding),
        runner_files,
        {**runner_files, "runner.py": "changed"},
    )


def test_contained_verifier_never_treats_profile_as_qualification(tmp_path):
    from ci.gauntlet.verify import verify_report

    (tmp_path / "summary.json").write_text(
        json.dumps(
            {
                "schema": "hol.guard-gauntlet.contained-bun-vitest.evidence.v1",
                "candidate_sha": "a" * 40,
            }
        )
    )

    with pytest.raises(ValueError, match="additive"):
        verify_report(tmp_path, expected_sha="a" * 40)
