"""Local tool scripts do not turn into arbitrary package execution consent."""

import json
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_restricted_pytest as transport
from codex_plugin_scanner.guard.runtime import contained_test_hook as sink
from codex_plugin_scanner.guard.runtime import restricted_node_tool as tool
from codex_plugin_scanner.guard.runtime.restricted_pytest_model import RestrictedPytestError

# Which spellings name a tool, which modes only report and which arguments
# write are all one reading in native authority, tested there
# (`contained_node_tool_tests.rs`), and so is the whole plan outside Windows
# (`node_tool_plan_tests.rs`). These tests stand the Windows sink on that
# answer and cover what stays here: the route it asks and what it refuses.
_REPORT = {"kind": "tool", "runtime_arguments": [], "expected_entry": None, "mode": "report"}
_TSC = _REPORT | {"name": "tsc", "entries": ["typescript/bin/tsc"]}


def _routes(monkeypatch, answer, *, build_output=None):
    """Answer the sink's routing question the way native authority would.

    A build asks a second question: the one directory it may write, read from
    its own words and the project's Vite config. That reading is pinned in
    `node_build_output_tests.rs`, so `build_output` names the answer for the
    build under test and this stand-in never reads those words itself.
    """

    def _native(operation, fields, expected):
        if operation == "node_build_output_root":
            assert build_output is not None
            return str(build_output)
        assert operation == "node_tool_route"
        value = answer(fields) if callable(answer) else answer
        if isinstance(value, RestrictedPytestError):
            raise value
        return value

    monkeypatch.setattr(tool, "restricted_native", _native)


def test_a_refused_route_is_not_a_protected_plan(monkeypatch, tmp_path):
    _routes(monkeypatch, RestrictedPytestError("node_tool_invalid_command", "The input has write or shell effects."))
    with pytest.raises(RestrictedPytestError, match="write or shell"):
        tool._prepare_windows_route(["eslint", "--fix", "src"], workspace=tmp_path, cwd=tmp_path)


@pytest.mark.parametrize(
    "reply",
    [
        {"kind": "tool"},
        _TSC | {"entries": []},
        _TSC | {"mode": "rewrite"},
        _TSC | {"arguments": ["--noEmit", 7]},
        _TSC | {"runtime_arguments": "--max-old-space-size=12288"},
        _TSC | {"expected_entry": 7},
        {"kind": "script", "task": ""},
        {"kind": "verdict"},
    ],
)
def test_a_reply_that_is_not_a_route_stops_the_run(monkeypatch, tmp_path, reply):
    """An answer the sink cannot read is unavailability, not a weaker plan."""
    _routes(monkeypatch, {"arguments": ["--noEmit"]} | reply)
    with pytest.raises(RestrictedPytestError, match="unavailable"):
        tool._prepare_windows_route(["tsc", "--noEmit"], workspace=tmp_path, cwd=tmp_path)


@pytest.mark.parametrize("command", [["bun", "run", "lint"], ["npm", "run", "lint"]])
def test_a_package_script_is_not_a_contained_tool_run(monkeypatch, tmp_path, command):
    """Windows admission keeps a package script on the review prompt.

    The sink never reads the manifest for it: a script route is refused as a
    run this platform does not contain, whatever the script says.
    """
    (tmp_path / "package.json").write_text(json.dumps({"scripts": {"lint": "eslint src"}}))
    asked = []

    def answer(fields):
        asked.append(fields)
        return {"kind": "script", "task": "lint"}

    _routes(monkeypatch, answer)
    with pytest.raises(RestrictedPytestError, match="package script") as refused:
        tool._prepare_windows_route(command, workspace=tmp_path, cwd=tmp_path)
    assert refused.value.reason_code == "node_tool_invalid_command"
    assert [fields["script_body"] for fields in asked] == [None]


@pytest.mark.parametrize("denied", [False, True])
@pytest.mark.parametrize(
    "command", ["bun run lint", "node --max-old-space-size=12288 /tmp/project/node_modules/typescript/bin/tsc --noEmit"]
)
def test_underlying_native_policy_is_rechecked(monkeypatch, tmp_path, denied, command):
    plan = SimpleNamespace(
        profile_version="node-tool-readonly-v1",
        command=("/usr/bin/node", str(tmp_path / "node_modules/eslint/bin/eslint.js"), "src"),
    )
    executed, authorized = [], []
    monkeypatch.setattr(tool, "prepare_restricted_node_tool", lambda *args, **kwargs: plan)
    monkeypatch.setattr(tool, "run_restricted_node_tool", lambda *args, **kwargs: executed.append(True) or 0)

    def authorize(payload):
        authorized.append(payload["tool_input"]["command"])
        if denied and len(authorized) == 2:
            return {"decision": "deny", "policy_action": "block"}
        return {
            "decision": "deny",
            "policy_action": "sandbox-required",
            "reason_code": "native_node_tool_readonly_containment_required",
            "required_execution_profile": "node-tool-readonly-v1",
        }

    payload = {"tool_input": {"command": command}}
    if denied:
        with pytest.raises(RestrictedPytestError):
            sink.run_authorized_contained_test(payload, workspace=tmp_path, authorize=authorize, timeout_seconds=20)
        assert not executed
    else:
        assert (
            sink.run_authorized_contained_test(payload, workspace=tmp_path, authorize=authorize, timeout_seconds=20)
            == 0
        )
        assert executed == [True]
    assert authorized[0] == command and authorized[1].startswith("/usr/bin/node ")


@pytest.mark.parametrize(
    "response, allowed",
    [
        ({"decision": "allow", "policy_action": "allow"}, True),
        ({"decision": "deny", "policy_action": "block"}, False),
        ({"decision": "allow", "policy_action": "block"}, False),
        ({"decision": "allow", "policy_action": "allow", "observe_mode": True}, False),
    ],
)
def test_native_capability_gate_does_not_override_extension_denial(monkeypatch, tmp_path, response, allowed):
    plan = SimpleNamespace(profile_version="node-tool-readonly-v1", command=("/usr/bin/node", "eslint.js"))
    calls, executed = [], []
    monkeypatch.setattr(tool, "prepare_restricted_node_tool", lambda *args, **kwargs: plan)

    def run(plan, *, timeout_seconds, authorize_capability, merge_stderr=False):
        assert merge_stderr is False
        authorize_capability(("/usr/bin/node", "--help"))
        executed.append(True)
        return 0

    monkeypatch.setattr(tool, "run_restricted_node_tool", run)

    def authorize(payload):
        command = payload["tool_input"]["command"]
        calls.append(command)
        if command == "/usr/bin/node --help":
            return response
        return {
            "decision": "deny",
            "policy_action": "sandbox-required",
            "reason_code": "native_node_tool_readonly_containment_required",
            "required_execution_profile": "node-tool-readonly-v1",
        }

    payload = {"tool_input": {"command": "npm run lint"}}
    if allowed:
        assert (
            sink.run_authorized_contained_test(payload, workspace=tmp_path, authorize=authorize, timeout_seconds=20)
            == 0
        )
    else:
        with pytest.raises(RestrictedPytestError):
            sink.run_authorized_contained_test(payload, workspace=tmp_path, authorize=authorize, timeout_seconds=20)
    assert executed == ([True] if allowed else [])
    assert calls == ["npm run lint", "/usr/bin/node eslint.js", "/usr/bin/node --help"]


@pytest.mark.parametrize("name", ["src", ".git", ".env", "../outside", "."])
def test_build_outputs_cannot_grant_source_or_host_writes(tmp_path, name):
    with pytest.raises(RestrictedPytestError):
        tool.validate_build_output_root(tmp_path / name, workspace=tmp_path)


def test_a_package_below_the_workspace_builds_into_its_own_dist(tmp_path):
    app = tmp_path / "apps" / "dashboard"
    app.mkdir(parents=True)
    (app / "package.json").write_text("{}")
    tool.validate_build_output_root(app / "dist", workspace=tmp_path)
    for directory in (tmp_path / "apps", tmp_path / ".github" / "app", app / "node_modules" / "vite"):
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "package.json").write_text("{}")
    (tmp_path / "apps" / "package.json").unlink()
    for parent in (tmp_path / "apps", tmp_path / ".github" / "app", app / "node_modules" / "vite", app / "src"):
        with pytest.raises(RestrictedPytestError):
            tool.validate_build_output_root(parent / "dist", workspace=tmp_path)
    linked = tmp_path / "linked"
    linked.symlink_to(app)
    with pytest.raises(RestrictedPytestError):
        tool.validate_build_output_root(linked / "dist", workspace=tmp_path)


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "credential"])
def test_existing_output_links_and_protected_files_are_rejected(tmp_path, kind):
    output = tmp_path / "dist"
    output.mkdir()
    source = tmp_path / "ordinary.txt"
    source.write_text("source")
    if kind == "symlink":
        (output / "alias").symlink_to(source)
    elif kind == "hardlink":
        (output / "alias").hardlink_to(source)
    else:
        (output / ".env").write_text("synthetic fixture")
    with pytest.raises(RestrictedPytestError):
        tool.validate_build_output_root(output, workspace=tmp_path)
    assert source.read_text() == "source"


def test_a_missing_local_tool_keeps_its_own_refusal(monkeypatch):
    message = "The local lint/typecheck tool is unavailable; no replacement was downloaded."
    reply = {"reason_code": "node_tool_dependency_unavailable", "message": message}
    monkeypatch.setattr(transport, "_call", lambda *args, **kwargs: reply)
    with pytest.raises(RestrictedPytestError) as refused:
        transport._request("prepare_node_tool", {}, dict)
    assert refused.value.reason_code == "node_tool_dependency_unavailable"
    assert str(refused.value) == message
