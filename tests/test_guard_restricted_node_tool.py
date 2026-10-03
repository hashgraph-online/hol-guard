"""Local tool scripts do not turn into arbitrary package execution consent."""

import json
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.runtime import contained_test_hook as sink
from codex_plugin_scanner.guard.runtime import restricted_node_tool as tool
from codex_plugin_scanner.guard.runtime.restricted_pytest_model import RestrictedPytestError


@pytest.mark.parametrize(
    "command",
    [
        ["bunx", "eslint@evil", "src"],
        ["bun", "run", "other"],
        ["bunx", "tsc"],
        ["eslint", "--fix", "src"],
        ["eslint", "--output-file=.env", "src"],
        ["node", "--max-old-space-size=999999", "typescript/bin/tsc", "--noEmit"],
        ["node", "--require=evil", "typescript/bin/tsc", "--noEmit"],
        ["node", "--max-old-space-size=12288", "--require=evil", "typescript/bin/tsc", "--noEmit"],
    ],
)
def test_unsupported_or_writing_command_is_not_a_protected_plan(command, tmp_path):
    with pytest.raises(RestrictedPytestError):
        tool.prepare_restricted_node_tool(command, workspace=tmp_path)


def test_bounded_heap_option_is_preserved_before_verified_entry(monkeypatch, tmp_path):
    entry = tmp_path / "node_modules/typescript/bin/tsc"
    entry.parent.mkdir(parents=True)
    entry.write_text("// fixture compiler")
    base = SimpleNamespace(workspace=tmp_path, cwd=tmp_path, executable="/usr/bin/node", denied_capabilities=())
    monkeypatch.setattr(tool, "prepare_restricted_node_test", lambda *args, **kwargs: base)
    monkeypatch.setattr(tool, "replace", lambda original, **changes: SimpleNamespace(**{**vars(original), **changes}))
    plan = tool.prepare_restricted_node_tool(
        ["node", "--max-old-space-size=12288", str(entry), "--noEmit", "--incremental", "false"],
        workspace=tmp_path,
    )
    assert plan.profile_version == "node-tool-readonly-v1"
    assert plan.command == ("/usr/bin/node", "--max-old-space-size=12288", str(entry), "--noEmit", "--incremental", "false")


@pytest.mark.parametrize("script", ["curl https://example.invalid", "", "eslint src && curl https://example.invalid"])
def test_manifest_script_is_not_shell_consent(script, tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"scripts": {"lint": script}}))
    with pytest.raises(RestrictedPytestError):
        tool.prepare_restricted_node_tool(["bun", "run", "lint"], workspace=tmp_path)


@pytest.mark.parametrize("denied", [False, True])
def test_underlying_native_policy_is_rechecked(monkeypatch, tmp_path, denied):
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

    payload = {"tool_input": {"command": "bun run lint"}}
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
    assert authorized[0] == "bun run lint" and authorized[1].startswith("/usr/bin/node ")


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

    def run(plan, *, timeout_seconds, authorize_capability):
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


@pytest.mark.parametrize("phase", ["prelint", "postlint"])
def test_lifecycle_actions_are_not_silently_skipped(tmp_path, phase):
    (tmp_path / "package.json").write_text(json.dumps({"scripts": {"lint": "eslint src", phase: "node lifecycle.mjs"}}))
    with pytest.raises(RestrictedPytestError, match="lifecycle actions"):
        tool.prepare_restricted_node_tool(["npm", "run", "lint"], workspace=tmp_path)


@pytest.mark.parametrize("name", ["src", ".git", ".env", "../outside", "."])
def test_build_outputs_cannot_grant_source_or_host_writes(tmp_path, name):
    with pytest.raises(RestrictedPytestError):
        tool.validate_build_output_root(tmp_path / name, workspace=tmp_path)


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
