"""Synthetic native-owner proof contracts; actual inference is tested separately."""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

from ci.gauntlet.bash_owner_wrapper import normalized_argv
from ci.gauntlet.case_helpers import _fixture_replacements
from ci.gauntlet.contained_core import contained_calls, request_proofs
from ci.gauntlet.evidence import assess_case, reconcile
from ci.gauntlet.fixtures import create_fixture
from ci.gauntlet.input_evidence import input_digest
from tests.test_guard_gauntlet_approval_retry_omp import _case, _scenario
from tests.test_guard_gauntlet_contained_core import _capture_log, _request


def _wrapper(digest: str, call_id: str) -> str:
    argv = [
        "/candidate/.venv/bin/hol-guard",
        "execute-bound-bash",
        "--harness",
        "omp",
        "--operation-id",
        "bash-operation:" + "a" * 64,
        "--host-owner-pid",
        "1234",
        "--tool-call-id",
        call_id,
        "--guard-home",
        "{{fixture}}/guard-home",
        "--workspace",
        "{{workspace}}",
        "--request-file",
        "/tmp/hol-guard-contained-test-abc123/request.json",
        "--request-sha256",
        digest,
        "--timeout-seconds",
        "120",
        "--home",
        "{{home}}",
    ]
    return " ".join("'" + word.replace("'", "'\\''") + "'" for word in argv)


def _owner_case(tmp_path: Path):
    case = _case()
    case["profile"] = "approval-retry"
    fixture = create_fixture(tmp_path / "fixture")
    original = dict(case["guard_observations"][0]["input"])
    captures = []
    wrappers = {}
    for call_id in ("c1", "c2"):
        raw = _request(fixture.workspace, call_id=call_id, tool_input=original)
        captures.append((call_id, raw))
        wrappers[call_id] = _wrapper(hashlib.sha256(raw).hexdigest(), call_id)
    case["contained_request_proofs"] = request_proofs(
        _capture_log(tmp_path / "host.jsonl", *captures), fixture.workspace, _fixture_replacements(fixture)
    )
    for event in case["events"]:
        if event["type"] == "model_turn":
            call = event["calls"][0]
            call["arguments"] = {"command": wrappers[call["id"]]}
        elif event["type"] == "tool_execution_start":
            event["args"] = {"command": wrappers[event["toolCallId"]]}
        elif event["type"] == "tool_execution_end":
            call_id = event["toolCallId"]
            event["result"] = {
                "content": [{"type": "text", "text": "native_bash_consent_required" if call_id == "c1" else ""}],
                "details": {
                    "exitCode": 125 if call_id == "c1" else 0,
                    "holGuardContainedTest": {
                        "schema": "guard-contained-test-presentation.v1",
                        "toolCallId": call_id,
                        "input": original,
                        "command": wrappers[call_id],
                    },
                },
            }
    first_post = deepcopy(case["guard_observations"][-1])
    first_post["tool_call_id"] = "c1"
    case["guard_observations"].insert(1, first_post)
    for row in case["guard_observations"]:
        call_id = row["tool_call_id"]
        if row["event"] == "PostToolUse":
            row["input"] = {"command": wrappers[call_id]}
            row["input_sha256"] = input_digest(row["input"])
            continue
        row.update(
            decision="deny",
            policy_action="sandbox-required",
            reason_code="native_bash_owner_required",
            probe_request_id="request-" + call_id,
            native_observation={
                "required_execution_profile": "native-bash-owner-v1",
                "native_receipt": {
                    "authority": "rust",
                    "harness": "omp",
                    "event_name": "PreToolUse",
                    "decision": "deny",
                    "policy_action": "sandbox-required",
                    "reason_code": "native_bash_owner_required",
                    "request_id": "request-" + call_id,
                    "decision_id": "decision-" + call_id,
                    "command_extensions": {
                        key: "d" * 64 for key in ("program_digest", "catalog_digest", "trust_digest")
                    },
                },
            },
        )
    case["native_routes"] = {"native_resident": 4}
    return case


def test_real_owner_result_and_authenticated_lifecycle_are_required_together(tmp_path: Path):
    result = assess_case(_scenario(), _owner_case(tmp_path))
    assert result["outcome"] == "pass", result


def test_protection_consent_lane_requires_the_same_complete_owner_binding(tmp_path: Path):
    case = _owner_case(tmp_path)
    calls, errors = reconcile(case["events"])
    assert not errors
    assert contained_calls("deny", case, calls) == ({}, None)
    bound, error = contained_calls("deny", case, calls, approval_retry=True)
    assert error is None and set(bound) == {"c1", "c2"}
    case["contained_request_proofs"][0]["request_sha256"] = "0" * 64
    assert contained_calls("deny", case, calls, approval_retry=True)[1] is not None


@pytest.mark.parametrize("damage", ["request", "receipt", "post", "presentation", "consent", "journal", "report"])
def test_unbound_owner_or_unproved_consent_never_passes(tmp_path: Path, damage: str):
    case = _owner_case(tmp_path)
    if damage == "request":
        case["contained_request_proofs"][0]["request_sha256"] = "0" * 64
    elif damage == "receipt":
        case["guard_observations"][0]["native_observation"]["native_receipt"]["request_id"] = "different"
    elif damage == "post":
        case["guard_observations"].pop(1)
    elif damage == "presentation":
        end = next(e for e in case["events"] if e["type"] == "tool_execution_end")
        end["result"]["details"]["holGuardContainedTest"]["command"] = "echo unbound"
    elif damage == "consent":
        end = next(e for e in case["events"] if e["type"] == "tool_execution_end")
        end["result"]["content"][0]["text"] = "prefix-native_bash_consent_required-suffix"
    elif damage == "journal":
        case["bash_lifecycle"]["journal"] = []
    else:
        case["bash_lifecycle"]["maintenance_report_exact"] = False
    assert assess_case(_scenario(), case)["outcome"] != "pass"


def test_core_does_not_treat_an_owner_consent_stop_as_ordinary_success(tmp_path: Path):
    case = _owner_case(tmp_path)
    # Case metadata cannot opt a trusted core scenario into the consent lane.
    assert case["profile"] == "approval-retry"
    assert assess_case(replace(_scenario(), profiles=("core",)), case)["outcome"] != "pass"


@pytest.mark.parametrize(
    "before,after",
    [
        ("'omp'", "'pi'"),
        ("'--harness'", "'--other'"),
        ("'1234'", "'1'"),
        ("'1234'", "'" + "9" * 5000 + "'"),
        ("'c1'", "'other-call'"),
        ("'{{fixture}}/guard-home'", "'/operator-home'"),
        ("'{{workspace}}'", "'/another-project'"),
        ("'120'", "'121'"),
        ("'120'", "'" + "9" * 5000 + "'"),
        ("'{{home}}'", "'/another-home'"),
        ("'execute-bound-bash'", "'execute-contained-test'"),
    ],
)
def test_owner_wrapper_rejects_changed_context_and_extra_routes(before: str, after: str):
    command = _wrapper("b" * 64, "c1").replace(before, after)
    assert normalized_argv(command, "c1")[0] is None


def test_owner_wrapper_requires_canonical_quoting_and_no_extra_arguments():
    command = _wrapper("b" * 64, "c1")
    assert normalized_argv(command, "c1")[0] is not None
    assert normalized_argv(command + " 'extra'", "c1")[0] is None
    assert normalized_argv(command.replace("'omp'", "omp"), "c1")[0] is None


@pytest.mark.parametrize("shape", ["valid", "public-mode", "symlink", "other-wrapper"])
def test_real_typescript_observer_captures_only_the_private_owner_request(tmp_path: Path, shape: str):
    bun = shutil.which("bun")
    if bun is None:
        pytest.skip("the real TypeScript observer requires Bun")
    directory = tmp_path / "hol-guard-contained-test-observer"
    directory.mkdir()
    request = directory / "request.json"
    raw = b'{"schema":"guard-contained-test-request.v1"}'
    request.write_bytes(raw)
    request.chmod(0o600)
    if shape == "public-mode":
        request.chmod(0o644)
    elif shape == "symlink":
        backing = directory / "backing.json"
        request.rename(backing)
        request.symlink_to(backing)
    command = _wrapper(hashlib.sha256(raw).hexdigest(), "c1").replace(
        "/tmp/hol-guard-contained-test-abc123/request.json", str(request)
    )
    if shape == "other-wrapper":
        command = command.replace("'execute-bound-bash'", "'unrelated-command'")
    observer = Path(__file__).resolve().parents[1] / "ci/gauntlet/observer.ts"
    event = {"type": "tool_execution_start", "toolName": "bash", "toolCallId": "c1", "args": {"command": command}}
    script = (
        f"import install from {json.dumps(str(observer))};\n"
        "const handlers = new Map(); install({ on: (name, handler) => handlers.set(name, handler) });\n"
        f"handlers.get('tool_execution_start')({json.dumps(event)});\n"
    )
    host_log = tmp_path / "host.jsonl"
    subprocess.run(
        [bun, "-e", script],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
        env={
            "PATH": os.environ["PATH"],
            "HOME": str(tmp_path),
            "GUARD_GAUNTLET_HOST_OBSERVER_LOG": str(host_log),
            "GUARD_GAUNTLET_OBSERVER_LOG": str(tmp_path / "hooks.jsonl"),
        },
    )
    rows = [json.loads(line) for line in host_log.read_text().splitlines()]
    captures = [row for row in rows if row.get("type") == "contained_request_capture"]
    assert len(captures) == (1 if shape == "valid" else 0)
    assert rows[0] == event


@pytest.mark.skipif(sys.platform != "darwin", reason="native Bash owner and hardened broker require macOS")
def test_staged_realistic_lifecycle_fixture_executes_through_native_owner(native_context_digest, tmp_path, monkeypatch):
    from ci.gauntlet.approval_retry_bash import (
        ONCE_CASE,
        REPORT_NAME,
        evidence,
        stage,
        target_command,
    )
    from codex_plugin_scanner.guard.config import update_guard_settings
    from codex_plugin_scanner.guard.native_resident_client import close_native_residents
    from codex_plugin_scanner.guard.runtime.bound_bash_sink import run_bound_bash
    from codex_plugin_scanner.guard.store import GuardStore
    from tests.test_native_bash_sink_integration import _Secrets

    del native_context_digest
    workspace = tmp_path / "project"
    home, guard = workspace / "home", tmp_path / "guard"
    home.mkdir(parents=True)
    protected = workspace / "deletion-target" / "keep.txt"
    protected.parent.mkdir()
    protected.write_text("protected synthetic deletion sentinel\n")
    stage(workspace, ONCE_CASE)
    monkeypatch.chdir(workspace)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    update_guard_settings(guard, {"subprocess_action": "allow"})
    store = GuardStore(guard, prime_policy_integrity=False)
    store._policy_integrity_secret_store = _Secrets()
    try:
        errors = io.StringIO()
        status = run_bound_bash(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "bash",
                "cwd": str(workspace),
                "tool_input": {"command": target_command(workspace)},
            },
            store=store,
            workspace=workspace,
            harness="omp",
            operation_id="gauntlet-fixture-native-test",
            output=io.StringIO(),
            errors=errors,
        )
        assert status == 0, errors.getvalue()
        assert protected.read_text() == "protected synthetic deletion sentinel\n"
        assert (home / REPORT_NAME).read_text().splitlines() == [
            f"{image} revision-{revision}" for image in ("alpha", "beta") for revision in ("001", "002")
        ] + ["completed"]
        assert store.count_approval_requests(status=None) == 0
        physical = evidence(home, workspace, ONCE_CASE, store)
        assert physical["report_runs"] == 1
        assert physical["report_exact"] is True
        assert physical["maintenance_report_exact"] is True
        assert physical["journal_error"] is None
        report = home / REPORT_NAME
        report.write_text(report.read_text().replace("alpha revision-001", "alpha unexpected"))
        changed = evidence(home, workspace, ONCE_CASE, store)
        assert changed["report_runs"] == 1
        assert changed["report_exact"] is False
        assert changed["maintenance_report_exact"] is False
    finally:
        close_native_residents(guard_home=guard)
