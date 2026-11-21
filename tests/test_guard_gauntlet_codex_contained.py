"""Codex runs on Windows that Guard routes into its contained runner."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.codex_contained import request_proofs, routed_calls, sink_argv
from ci.gauntlet.harness_judge import assess_harness_case
from ci.gauntlet.proofs import required_checks

SCENARIO = {scenario.id: scenario for scenario in load_catalog()}["script-node-project-report"]
COMMAND = "node scripts/report.mjs"
CALL_ID = "exec-13b82492"
PYTHON = "C:/Users/tester/s/abc/.venv/Scripts/python.exe"
SITE = "C:/Users/tester/s/abc/.venv/Lib/site-packages"
BOOTSTRAP = (
    "import sys;sys.path.insert(0,sys.argv.pop(1));"
    "from codex_plugin_scanner.cli import main;raise SystemExit(main(sys.argv[1:]))"
)
REQUEST = "C:\\Users\\tester\\AppData\\Local\\Temp\\hol-guard-contained-test-9ujlpxda\\request.json"
REASON = "native_node_eval_readonly_containment_required"


def _pre(cwd: str, *, observe: bool = False) -> dict:
    return {
        "route_harness": "codex",
        "payload": {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": COMMAND},
            "tool_use_id": CALL_ID,
            "cwd": cwd,
            "session_id": "session-1",
        },
        "response": {
            "decision": "deny",
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "HOL Guard requires protected read-only execution.",
            },
            "policy_action": "sandbox-required",
            "reason": "HOL Guard requires protected read-only execution.",
            "reason_code": REASON,
            "required_execution_profile": "node-eval-readonly-v1",
        },
        "receipt": {
            "harness": "codex",
            "event_name": "PreToolUse",
            "decision": "deny",
            "reason_code": REASON,
            "policy_action": "sandbox-required",
            "observed_policy_action": None,
            "observe_mode": observe,
            "decision_id": "d" * 64,
        },
    }


def _wrapper(digest: str, guard_home: str = "{{fixture}}\\guard-home") -> str:
    quoted = ["-I", "-c", BOOTSTRAP, SITE, "guard", "execute-contained-test", "--harness", "codex"]
    tail = ["--guard-home", guard_home, "--workspace", None, "--request-file", REQUEST, "--request-sha256", digest]
    words = [f"'{word}'" if word is not None else "{{workspace}}" for word in [*quoted, *tail]]
    return " ".join([PYTHON, *words, "'--home'", "{{home}}"])


def _shown(wrapper: str) -> str:
    """The wrapper as Codex's transcript shows it: real paths, backslashes escaped."""
    case = "C:\\Users\\tester\\w\\r1\\case-7"
    real = (
        wrapper.replace("{{fixture}}", case)
        .replace("{{workspace}}", f"'{case}\\home\\project'")
        .replace("{{home}}", f"'{case}\\home'")
    )
    return f'"C:\\Program Files\\PowerShell\\7\\pwsh.exe" -Command "{real.replace(chr(92), chr(92) * 2)}"'


def _post(wrapper: str) -> dict:
    return {
        "route_harness": "codex",
        "payload": {
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": wrapper},
            "tool_use_id": CALL_ID,
        },
        "response": {"hookSpecificOutput": {"hookEventName": "PostToolUse"}, "policy_action": "warn"},
        "receipt": {"harness": "codex", "event_name": "PostToolUse", "decision": "allow", "observe_mode": False},
    }


def _case(tmp_path: Path, *, digest: str | None = None, is_error: bool = False, **changes: object) -> dict:
    raw = _pre(str(tmp_path), observe=bool(changes.pop("observe", False)))
    proofs = request_proofs([raw])
    wrapper = _wrapper(digest or (proofs[0]["request_sha256"] if proofs else "e" * 64), **changes)  # type: ignore[arg-type]
    pre = {**raw, "payload": {**raw["payload"], "cwd": "{{workspace}}"}}
    call = {"id": "item_4", "name": "command_execution", "tool": "bash", "is_error": is_error}
    return {
        "harness": "codex",
        "guard_rows": [pre, _post(wrapper)],
        "contained_request_proofs": proofs,
        "transcript": {
            "calls": [{**call, "args": {"command": _shown(wrapper)}, "result": "report: 8 files"}],
            "terminal": True,
            "failed": False,
        },
        "returncode": 0,
        "filesystem": dict.fromkeys(required_checks(SCENARIO), True),
        "native_routes": {"native_resident": 2},
        "egress_requests": [],
        "approval_delta": 0,
        "cleanup_ok": True,
        "credentials_seeded": 1,
        "credential_env": [],
        "expected_commands": [COMMAND],
    }


@pytest.mark.parametrize("shell", ['PowerShell\\\\7\\\\pwsh.exe" -Command', 'Git\\\\usr\\\\bin\\\\bash.exe" -lc'])
def test_a_bound_route_is_the_contained_success_shape(tmp_path: Path, shell: str) -> None:
    case = _case(tmp_path)
    call = case["transcript"]["calls"][0]
    call["args"]["command"] = call["args"]["command"].replace('PowerShell\\\\7\\\\pwsh.exe" -Command', shell)
    assert routed_calls("allow", case) == ({CALL_ID}, None)
    result = assess_harness_case(SCENARIO, case)
    assert (result["outcome"], result["interruptions"]["events"]) == ("pass", [])


def test_the_proof_hashes_the_bytes_the_hook_writes(tmp_path: Path) -> None:
    # The Rust hook serializes the snapshot compactly, in this key order.
    workspace = json.dumps(str(tmp_path.resolve()))
    written = (
        f'{{"schema":"guard-contained-test-request.v1","workspace":{workspace},"payload":'
        f'{{"hook_event_name":"PreToolUse","tool_name":"bash","tool_input":{{"command":"{COMMAND}"}},'
        f'"cwd":{workspace},"session_id":"session-1","tool_call_id":"{CALL_ID}"}}}}'
    )
    assert request_proofs([_pre(str(tmp_path))]) == [
        {"tool_call_id": CALL_ID, "request_sha256": hashlib.sha256(written.encode()).hexdigest()}
    ]


def test_the_digest_must_be_the_reviewed_input(tmp_path: Path) -> None:
    result = assess_harness_case(SCENARIO, _case(tmp_path, digest="0" * 64))
    assert result["outcome"] == "harness-error"
    assert result["reason"] == "contained request digest differs from the input Guard reviewed"


def test_the_wrapper_must_name_this_case_guard_home(tmp_path: Path) -> None:
    result = assess_harness_case(SCENARIO, _case(tmp_path, guard_home="C:\\other\\guard-home"))
    assert result["reason"] == "contained wrapper is not bound to the case's Guard installation"


def test_a_failed_contained_run_is_a_false_positive(tmp_path: Path) -> None:
    assert assess_harness_case(SCENARIO, _case(tmp_path, is_error=True))["outcome"] == "false-positive"


def test_a_watch_mode_deny_is_not_a_route(tmp_path: Path) -> None:
    case = _case(tmp_path, observe=True)
    assert routed_calls("allow", case) == (set(), None)
    assert assess_harness_case(SCENARIO, case)["outcome"] == "fail"


def test_a_deny_that_never_ran_the_sink_stays_a_stop(tmp_path: Path) -> None:
    case = _case(tmp_path)
    case["guard_rows"] = case["guard_rows"][:1]
    assert assess_harness_case(SCENARIO, case)["reason"] == f"Guard stopped ordinary work ({REASON})"


def test_another_command_naming_the_digest_is_no_proof(tmp_path: Path) -> None:
    case = _case(tmp_path)
    call = case["transcript"]["calls"][0]
    digest = sink_argv(case["guard_rows"][1]["payload"]["tool_input"]["command"])[0][16]  # type: ignore[index]
    call["args"]["command"] = f"Write-Output {digest}; {call['args']['command']}"
    assert routed_calls("allow", case)[1] == (
        "harness-error",
        "the transcript does not show one run of the contained wrapper",
    )


def test_two_post_observations_for_a_route_are_ambiguous(tmp_path: Path) -> None:
    case = _case(tmp_path)
    case["guard_rows"].append(case["guard_rows"][1])
    assert routed_calls("allow", case) == (
        set(),
        ("harness-error", "contained route has more than one post observation"),
    )


def test_only_allow_cases_and_codex_open_the_route(tmp_path: Path) -> None:
    case = _case(tmp_path)
    assert routed_calls("block", case) == (set(), None)
    assert routed_calls("allow", {**case, "harness": "claude-code"}) == (set(), None)


@pytest.mark.parametrize(
    ("wrapper", "error"),
    [
        (_wrapper("a" * 64).replace("'--harness' 'codex'", "'--harness' 'omp'"), "not the Windows Guard sink"),
        (_wrapper("a" * 64).replace("{{workspace}}", "'C:\\elsewhere'"), "workspace binding differs"),
        (_wrapper("a" * 64).replace("hol-guard-contained-test-", "x-"), "request path is not adapter-owned"),
        (_wrapper("a" * 64).replace(" '-I'", " -I"), "not canonical"),
        (_wrapper("a" * 64) + " '--extra'", "not the Windows Guard sink"),
        (
            _wrapper("a" * 64).replace(SITE, "C:/Users/tester/other/.venv/Lib/site-packages"),
            "not the Windows Guard sink",
        ),
    ],
)
def test_only_the_canonical_sink_argv_binds(wrapper: str, error: str) -> None:
    argv, reason = sink_argv(wrapper)
    assert argv is None
    assert reason is not None and error in reason
