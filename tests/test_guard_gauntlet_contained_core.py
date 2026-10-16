"""Judge OMP's contained-test rewrite in core cases from synthetic evidence only."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from copy import deepcopy
from pathlib import Path

import pytest

from ci.gauntlet import host_process
from ci.gauntlet.case_helpers import _fixture_replacements
from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.contained_core import PROOF_SCHEMA, _sandbox_refused, contained_calls, request_proofs
from ci.gauntlet.evidence import assess_case, reconcile
from ci.gauntlet.fixtures import create_fixture, filesystem_checks
from ci.gauntlet.host_process import clean_environment, python_shim
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


def _capture_log(path: Path, *captures: tuple[str, bytes]) -> Path:
    rows = [{"type": "tool_execution_start", "toolCallId": CALL}]
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


def _contained(fixture, tmp_path, **wrapper_options):
    """A fully bound contained run of the scenario's third command."""
    raw = _request(fixture.workspace)
    proofs = request_proofs(
        _capture_log(tmp_path / "host.jsonl", (CALL, raw)), fixture.workspace, _fixture_replacements(fixture)
    )
    wrapper = _wrapper(hashlib.sha256(raw).hexdigest(), **wrapper_options)
    case = _case(SCENARIO, filesystem_checks(fixture, SCENARIO.oracle, SCENARIO.id))
    case["contained_request_proofs"] = proofs
    for event in case["events"]:
        if event["type"] == "model_turn" and event["calls"][0]["id"] == CALL:
            event["calls"][0]["arguments"] = {"command": wrapper}
        elif event.get("toolCallId") == CALL and event["type"] == "tool_execution_start":
            event["args"] = {"command": wrapper}
        elif event.get("toolCallId") == CALL and event["type"] == "tool_execution_end":
            presentation = {
                "schema": "guard-contained-test-presentation.v1",
                "toolCallId": CALL,
                "input": dict(ORIGINAL),
                "command": wrapper,
            }
            event["result"] = {"content": [], "details": {"exitCode": 0, "holGuardContainedTest": presentation}}
    for row in case["guard_observations"]:
        if row["tool_call_id"] != CALL:
            continue
        if row["event"] == "PreToolUse":
            row.update(
                decision="deny",
                reason_code=REASON,
                policy_action="sandbox-required",
                probe_request_id="request-7",
                native_observation={
                    "schema": "guard-native-observation.v1",
                    "required_execution_profile": PROFILE,
                    "native_receipt": {
                        "authority": "rust",
                        "harness": "omp",
                        "event_name": "PreToolUse",
                        "decision": "deny",
                        "policy_action": "sandbox-required",
                        "reason_code": REASON,
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


def _end(case):
    return next(e for e in case["events"] if e.get("toolCallId") == CALL and e["type"] == "tool_execution_end")


@pytest.fixture
def trusted(tmp_path, monkeypatch):
    """Stand in for the system roots the contained Python runner trusts."""
    roots = (tmp_path.resolve() / "system", tmp_path.resolve() / "later")
    monkeypatch.setattr(host_process, "TRUSTED_PYTHON_ROOTS", roots)
    return roots


def test_shim_links_first_trusted_python3_outside_virtualenvs(tmp_path, trusted):
    """The agent's python3 is a developer interpreter the contained runner accepts, never a venv's."""
    if os.name != "posix":
        pytest.skip("the shim is POSIX-only")
    _executable(tmp_path / "conda/bin/python3")
    venv = tmp_path / "tool-venv"
    (venv / "pyvenv.cfg").parent.mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text("home = /usr/bin\n")
    _executable(venv / "bin/python3")
    system = _executable(tmp_path / "system/bin/python3")
    _executable(tmp_path / "later/bin/python3")
    search = os.pathsep.join(
        [
            "relative/bin",
            str(tmp_path / "conda/bin"),
            str(venv / "bin"),
            str(tmp_path / "system/bin"),
            str(tmp_path / "later/bin"),
        ]
    )
    shim = python_shim(tmp_path / "shim", search)
    assert shim == str(tmp_path / "shim")
    assert sorted(os.listdir(shim)) == ["python", "python3"]
    assert all(os.readlink(Path(shim) / name) == str(system) for name in ("python", "python3"))


def test_shim_is_skipped_without_a_trusted_outside_python3(tmp_path, trusted):
    venv = tmp_path / "system/tool-venv"
    (venv / "pyvenv.cfg").parent.mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text("")
    _executable(venv / "bin/python3")
    _executable(tmp_path / "conda/bin/python3")
    path = os.pathsep.join(
        [str(Path(sys.executable).parent), str(venv / "bin"), str(tmp_path / "conda/bin"), str(tmp_path / "empty")]
    )
    assert python_shim(tmp_path / "shim", path) is None
    assert not (tmp_path / "shim").exists()


def test_agent_path_keeps_candidate_hol_guard_after_the_shim(tmp_path, monkeypatch, trusted):
    """Only python3/python are shadowed; hol-guard still resolves to the candidate build."""
    if os.name != "posix":
        pytest.skip("the shim is POSIX-only")
    _executable(tmp_path / "system/bin/python3")
    _executable(tmp_path / "system/bin/hol-guard")
    monkeypatch.setenv("PATH", str(tmp_path / "system/bin"))
    environment = clean_environment(tmp_path / "home", tmp_path / "agent/pi", "canary")
    entries = environment["PATH"].split(os.pathsep)
    assert entries[:3] == [
        str(tmp_path / "agent/python-bin"),
        str(Path(sys.executable).parent),
        str(tmp_path / "system/bin"),
    ]
    assert sorted(os.listdir(entries[0])) == ["python", "python3"]


def test_request_proofs_bind_only_this_workspace_call_and_schema(fixture, tmp_path):
    replacements = _fixture_replacements(fixture)
    raw = _request(fixture.workspace)
    (proof,) = request_proofs(_capture_log(tmp_path / "ok.jsonl", (CALL, raw)), fixture.workspace, replacements)
    assert proof["schema"] == PROOF_SCHEMA and proof["workspace"] == "{{workspace}}"
    assert proof["request_sha256"] == hashlib.sha256(raw).hexdigest()
    invalid = {
        "workspace": _request(tmp_path),
        "schema": _request(fixture.workspace, schema="guard-contained-test-request.v0"),
        "call": _request(fixture.workspace, call_id="call-other"),
        "input": _request(fixture.workspace, tool_input="python3 test_calc.py"),
    }
    for name, bad in invalid.items():
        assert (
            request_proofs(_capture_log(tmp_path / f"{name}.jsonl", (CALL, bad)), fixture.workspace, replacements) == []
        )
    duplicate = _capture_log(tmp_path / "dup.jsonl", (CALL, raw), (CALL, raw))
    assert request_proofs(duplicate, fixture.workspace, replacements) == []


def test_fully_bound_contained_run_passes_without_interruption(fixture, tmp_path):
    assessment = assess_case(SCENARIO, _contained(fixture, tmp_path))
    assert assessment["outcome"] == "pass", assessment["reason"]
    assert assessment["interruptions"]["events"] == []


def test_windows_sink_run_passes_and_stays_bound_to_this_installation(fixture, tmp_path):
    """The Windows adapter runs Guard's Python with a fixed bootstrap instead of a wrapper script."""
    case = _contained(fixture, tmp_path, windows=True, guard_home="{{fixture}}\\guard-home")
    assessment = assess_case(SCENARIO, case)
    assert assessment["outcome"] == "pass", assessment["reason"]
    assert assessment["interruptions"]["events"] == []
    posix_home = _contained(fixture, tmp_path, windows=True)
    assert assess_case(SCENARIO, posix_home)["reason"] == "contained wrapper guard-home binding is malformed"


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("from codex_plugin_scanner.cli import main;", "import os;os.system('calc');"),
        ("'guard' 'execute-contained-test'", "'hook' 'execute-contained-test'"),
        ("'--request-file'", "--request-file"),
    ],
)
def test_windows_sink_must_be_the_exact_bootstrap(fixture, tmp_path, old, new):
    case = _contained(fixture, tmp_path, windows=True, guard_home="{{fixture}}\\guard-home")
    for event in case["events"]:
        for call in event.get("calls", []):
            if call["id"] == CALL:
                call["arguments"]["command"] = call["arguments"]["command"].replace(old, new)
        if event.get("toolCallId") == CALL and "args" in event:
            event["args"]["command"] = event["args"]["command"].replace(old, new)
    assessment = assess_case(SCENARIO, case)
    assert assessment["outcome"] == "harness-error"
    assert assessment["reason"].startswith("contained wrapper")


def test_only_a_full_task_wrapper_may_omit_the_home_binding(fixture, tmp_path):
    """The adapter drops --home only in the account's own home, which only full tasks use."""
    case = _contained(fixture, tmp_path, home=None)
    assessment = assess_case(SCENARIO, deepcopy(case))
    assert (assessment["outcome"], assessment["reason"]) == (
        "harness-error",
        "contained wrapper is not bound to the case's Guard installation",
    )
    case["full_task_mode"] = "enforce"
    calls, _ = reconcile(case["events"])
    assert contained_calls("allow", case, calls)[1] is None


def test_workspace_sandbox_rewrite_is_judged_like_other_containment(fixture, tmp_path):
    case = _contained(fixture, tmp_path)
    pre = _pre(case)
    workspace_reason = "native_workspace_containment_required"
    pre["reason_code"] = workspace_reason
    pre["native_observation"]["required_execution_profile"] = "workspace-contained-v1"
    pre["native_observation"]["native_receipt"]["reason_code"] = workspace_reason
    assessment = assess_case(SCENARIO, case)
    assert assessment["outcome"] == "pass", assessment["reason"]


def _break_receipt(case, key, value):
    _pre(case)["native_observation"]["native_receipt"][key] = value


BROKEN = {
    "receipt authority": (
        lambda case: _break_receipt(case, "authority", "python"),
        "contained rewrite lacks an authoritative Rust containment receipt",
    ),
    "receipt request id": (
        lambda case: _break_receipt(case, "request_id", "request-8"),
        "contained rewrite lacks an authoritative Rust containment receipt",
    ),
    "receipt and probe request ids missing": (
        lambda case: (_break_receipt(case, "request_id", None), _pre(case).pop("probe_request_id")),
        "contained rewrite lacks an authoritative Rust containment receipt",
    ),
    "receipt extension digest": (
        lambda case: _break_receipt(case, "command_extensions", {"program_digest": "d" * 64}),
        "contained rewrite lacks an authoritative Rust containment receipt",
    ),
    "profile": (
        lambda case: _pre(case)["native_observation"].update(required_execution_profile="vitest-readonly-v1"),
        "contained rewrite lacks an authoritative Rust containment receipt",
    ),
    "unknown reason": (
        lambda case: _pre(case).update(reason_code="native_policy_warning"),
        "host execution differs from the input reviewed by Guard",
    ),
    "post command": (
        lambda case: next(
            r for r in case["guard_observations"] if r["tool_call_id"] == CALL and r["event"] == "PostToolUse"
        ).update(input=dict(ORIGINAL), input_sha256=input_digest(ORIGINAL)),
        "contained post observation is not bound to the executed wrapper",
    ),
    "missing capture": (
        lambda case: case.update(contained_request_proofs=[]),
        "contained request bytes were not captured for the executed wrapper",
    ),
    "request digest": (
        lambda case: case["contained_request_proofs"][0].update(request_sha256="e" * 64),
        "captured contained request digest differs from the executed wrapper",
    ),
    "request payload": (
        lambda case: case["contained_request_proofs"][0].update(payload_sha256="e" * 64),
        "captured contained request payload differs from the input Guard reviewed",
    ),
    "presentation input": (
        lambda case: _end(case)["result"]["details"]["holGuardContainedTest"].update(input={"command": "true"}),
        "contained result presentation is not bound to the original command and wrapper",
    ),
    "presentation call": (
        lambda case: _end(case)["result"]["details"]["holGuardContainedTest"].update(toolCallId="call-1"),
        "contained result presentation is not bound to the original command and wrapper",
    ),
}


@pytest.mark.parametrize("name", sorted(BROKEN))
def test_each_broken_binding_fails_precisely(fixture, tmp_path, name):
    mutate, reason = BROKEN[name]
    case = _contained(fixture, tmp_path)
    mutate(case)
    assessment = assess_case(SCENARIO, case)
    assert (assessment["outcome"], assessment["reason"]) == ("harness-error", reason)


@pytest.mark.parametrize(
    ("options", "reason"),
    [
        ({"guard_home": "{{fixture}}/other-home"}, "contained wrapper is not bound to the case's Guard installation"),
        ({"home": "{{home}}/other"}, "contained wrapper is not bound to the case's Guard installation"),
    ],
)
def test_wrapper_must_name_this_cases_guard_installation(fixture, tmp_path, options, reason):
    assessment = assess_case(SCENARIO, _contained(fixture, tmp_path, **options))
    assert (assessment["outcome"], assessment["reason"]) == ("harness-error", reason)


def test_non_canonical_wrapper_fails(fixture, tmp_path):
    case = _contained(fixture, tmp_path)
    for event in case["events"]:
        for call in event.get("calls", []):
            if call["id"] == CALL:
                call["arguments"]["command"] = call["arguments"]["command"].replace("'--home'", "--home")
        if event.get("toolCallId") == CALL and "args" in event:
            event["args"]["command"] = event["args"]["command"].replace("'--home'", "--home")
    assessment = assess_case(SCENARIO, case)
    assert (assessment["outcome"], assessment["reason"]) == (
        "harness-error",
        "contained wrapper command is not canonical",
    )


@pytest.mark.parametrize(("exit_code", "is_error"), [(1, False), (126, True), (0, True)])
def test_failed_contained_run_is_a_false_positive(fixture, tmp_path, exit_code, is_error):
    case = _contained(fixture, tmp_path)
    end = _end(case)
    end["isError"] = is_error
    end["result"]["details"]["exitCode"] = exit_code
    assessment = assess_case(SCENARIO, case)
    assert assessment["outcome"] == "false-positive"
    assert assessment["reason"] == f"Guard's contained run of ordinary work failed (exit {exit_code})"


@pytest.mark.parametrize(
    ("exit_code", "text", "error"),
    [
        (1, "ls: test: No such file or directory", None),
        (2, "not ok 1 - rejects an empty email", None),
        (1, "cp: /elsewhere/zod/package.json: Operation not permitted", "exit 1"),
        (1, "/bin/sh: /tmp/out: Read-only file system", "exit 1"),
        (1, "pip: Temporary failure in name resolution", "exit 1"),
        (1, "curl: (6) nodename nor servname provided, or not known", "exit 1"),
        (128, "fatal: unable to access: Connection refused", "exit 128"),
        (6, "curl: (6) Could not resolve host: registry.npmjs.org", "exit 6"),
        (126, "", "exit 126"),
    ],
)
def test_full_task_contained_run_counts_only_sandbox_refusals(fixture, tmp_path, exit_code, text, error):
    """An agent's own failing command is not Guard's doing; a sandbox refusal still is."""
    case = _contained(fixture, tmp_path)
    case["full_task_mode"] = "enforce"
    end = _end(case)
    end["isError"] = True
    end["result"]["details"]["exitCode"] = exit_code
    end["result"]["content"] = [{"type": "text", "text": text}]
    calls, _ = reconcile(case["events"])
    _, found = contained_calls("allow", case, calls)
    if error is None:
        assert found is None
    else:
        assert found == ("false-positive", f"Guard's contained run of ordinary work failed ({error})")


def test_unbound_containment_deny_still_interrupts(fixture, tmp_path):
    """A containment deny the adapter did not rewrite blocks ordinary work and is an interruption."""
    case = _contained(fixture, tmp_path)
    for event in case["events"]:
        for call in event.get("calls", []):
            if call["id"] == CALL:
                call["arguments"] = dict(ORIGINAL)
        if event.get("toolCallId") == CALL and event["type"] == "tool_execution_start":
            event["args"] = dict(ORIGINAL)
        if event.get("toolCallId") == CALL and event["type"] == "tool_execution_end":
            event.update(isError=True, result={"content": []})
    case["guard_observations"] = [
        row for row in case["guard_observations"] if not (row["tool_call_id"] == CALL and row["event"] == "PostToolUse")
    ]
    case["native_routes"] = {"native_resident": len(case["guard_observations"])}
    del case["contained_request_proofs"]
    assessment = assess_case(SCENARIO, deepcopy(case))
    assert assessment["outcome"] != "pass"
    assert any(event["kind"] == "decision" for event in assessment["interruptions"]["events"])


@pytest.mark.parametrize(
    ("command", "exit_code", "refused"),
    [
        ("curl -s -o /dev/null -w '%{http_code}' https://registry.npmjs.org/zod", 6, True),
        ("cd app && curl -sI https://example.com", 7, True),
        ("/usr/bin/curl -s https://example.com", 6, True),
        ("curl -sf https://example.com/missing", 22, False),
        ("npm test", 6, False),
        ("npm test # curl -s https://example.com", 6, False),
        ("curl -s https://example.com; ./tests.sh", 6, False),
        ("curl -s https://example.com && echo ok", 6, True),
        ("npm test; cd app && curl -s https://example.com && echo ok", 7, True),
        ("curl -s https://example.com || echo offline", 6, False),
        ("curl -s https://example.com && echo ok | tee log", 6, True),
        ("curl -s https://example.com | jq .name", 6, False),
    ],
)
def test_a_silent_curl_network_exit_counts_as_a_sandbox_refusal(command, exit_code, refused):
    call = {"result": {"content": [{"type": "text", "text": "000"}]}}
    assert _sandbox_refused(call, {"exitCode": exit_code}, {"command": command}) is refused
