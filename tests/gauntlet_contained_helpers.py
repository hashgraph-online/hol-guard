"""Shared builders for the contained-test cases the core and gate-declaration suites judge.

They live beside the suites rather than inside one of them so a second case can bind a
contained run without importing another test module.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

from ci.gauntlet.case_helpers import _fixture_replacements
from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.contained_core import request_proofs
from ci.gauntlet.fixtures import create_fixture, filesystem_checks
from ci.gauntlet.input_evidence import input_digest
from tests.test_guard_gauntlet_workflow_boundaries import _case

SCENARIO = {scenario.id: scenario for scenario in load_catalog()}["omp-native-shell-build-and-test"]
REASON = "native_python_eval_readonly_containment_required"
PROFILE = "python-eval-readonly-v1"
ORIGINAL = {"command": "python3 test_calc.py"}
CALL = "call-2"


def _executable(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n")
    path.chmod(0o755)
    return path


def _request(workspace: Path, call_id: str = CALL, tool_input: object = ORIGINAL, **overrides) -> bytes:
    payload = {"hook_event_name": "PreToolUse", "tool_call_id": call_id, "tool_name": "bash", "tool_input": tool_input}
    request = {"schema": "guard-contained-test-request.v1", "workspace": str(workspace), "payload": payload}
    request.update(overrides)
    return json.dumps(request).encode()


def _capture_log(path: Path, *captures: tuple[str, bytes], call_id: str = CALL) -> Path:
    rows = [{"type": "tool_execution_start", "toolCallId": call_id}]
    rows += [
        {"type": "contained_request_capture", "toolCallId": call_id, "request": base64.b64encode(raw).decode()}
        for call_id, raw in captures
    ]
    path.write_text("\n".join(json.dumps(row) for row in rows))
    return path


WINDOWS_SINK = [
    "C:\\candidate\\.venv\\Scripts\\python.exe",
    "-I",
    "-c",
    "import sys;sys.path.insert(0, 'C:/candidate/.venv/Lib/site-packages');"
    "from codex_plugin_scanner.cli import main;raise SystemExit(main(sys.argv[1:]))",
    "guard",
]


def _wrapper(
    request_sha256: str,
    *,
    guard_home: str = "{{fixture}}/guard-home",
    home: str | None = "{{home}}",
    windows: bool = False,
) -> str:
    argv = [
        *(WINDOWS_SINK if windows else ["/candidate/.venv/bin/hol-guard"]),
        "execute-contained-test",
        "--guard-home",
        guard_home,
        "--workspace",
        "{{workspace}}",
        "--request-file",
        (
            "C:\\Users\\agent\\AppData\\Local\\Temp\\hol-guard-contained-test-abc123\\request.json"
            if windows
            else "/tmp/hol-guard-contained-test-abc123/request.json"
        ),
        "--request-sha256",
        request_sha256,
        *(["--home", home] if home is not None else []),
    ]
    # Redaction folds a quoted Windows fixture path into a bare placeholder.
    bare = {"{{workspace}}", "{{home}}"} if windows else set()
    return " ".join(value if value in bare else "'" + value.replace("'", "'\\''") + "'" for value in argv)


@pytest.fixture
def fixture(tmp_path):
    return create_fixture(tmp_path / "fixture")


def _contained(
    fixture,
    tmp_path,
    *,
    scenario=None,
    call_id: str = CALL,
    original: dict | None = None,
    reason: str = REASON,
    profile: str = PROFILE,
    **wrapper_options,
):
    """A fully bound contained run of one of the scenario's commands.

    The defaults are this module's own scenario and its third command; another case passes its
    own scenario, the call that carries its command, and the reason code Guard denied it with.
    """
    scenario = SCENARIO if scenario is None else scenario
    original = dict(ORIGINAL) if original is None else dict(original)
    raw = _request(fixture.workspace, call_id=call_id, tool_input=original)
    proofs = request_proofs(
        _capture_log(tmp_path / "host.jsonl", (call_id, raw), call_id=call_id),
        fixture.workspace,
        _fixture_replacements(fixture),
    )
    wrapper = _wrapper(hashlib.sha256(raw).hexdigest(), **wrapper_options)
    case = _case(scenario, filesystem_checks(fixture, scenario.oracle, scenario.id))
    case["contained_request_proofs"] = proofs
    for event in case["events"]:
        if event["type"] == "model_turn" and event["calls"][0]["id"] == call_id:
            event["calls"][0]["arguments"] = {"command": wrapper}
        elif event.get("toolCallId") == call_id and event["type"] == "tool_execution_start":
            event["args"] = {"command": wrapper}
        elif event.get("toolCallId") == call_id and event["type"] == "tool_execution_end":
            presentation = {
                "schema": "guard-contained-test-presentation.v1",
                "toolCallId": call_id,
                "input": dict(original),
                "command": wrapper,
            }
            event["result"] = {"content": [], "details": {"exitCode": 0, "holGuardContainedTest": presentation}}
    for row in case["guard_observations"]:
        if row["tool_call_id"] != call_id:
            continue
        if row["event"] == "PreToolUse":
            row.update(
                decision="deny",
                reason_code=reason,
                policy_action="sandbox-required",
                probe_request_id="request-7",
                input=dict(original),
                input_sha256=input_digest(original),
                native_observation={
                    "schema": "guard-native-observation.v1",
                    "required_execution_profile": profile,
                    "native_receipt": {
                        "authority": "rust",
                        "harness": "omp",
                        "event_name": "PreToolUse",
                        "decision": "deny",
                        "policy_action": "sandbox-required",
                        "reason_code": reason,
                        "request_id": "request-7",
                        "decision_id": "decision-7",
                        "command_extensions": {
                            key: "d" * 64 for key in ("program_digest", "catalog_digest", "trust_digest")
                        },
                    },
                },
            )
        else:
            row.update(input={"command": wrapper}, input_sha256=input_digest({"command": wrapper}))
    return case


def _pre(case):
    return next(r for r in case["guard_observations"] if r["tool_call_id"] == CALL and r["event"] == "PreToolUse")


def _end(case, call_id: str = CALL):
    return next(e for e in case["events"] if e.get("toolCallId") == call_id and e["type"] == "tool_execution_end")
