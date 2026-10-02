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
    ],
)
def test_unsupported_or_writing_command_is_not_a_protected_plan(command, tmp_path):
    with pytest.raises(RestrictedPytestError):
        tool.prepare_restricted_node_tool(command, workspace=tmp_path)


@pytest.mark.parametrize("script", ["curl https://example.invalid", "", "eslint src && curl https://example.invalid"])
def test_manifest_script_is_not_shell_consent(script, tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"scripts": {"lint": script}}))
    with pytest.raises(RestrictedPytestError):
        tool.prepare_restricted_node_tool(["bun", "run", "lint"], workspace=tmp_path)


@pytest.mark.parametrize("denied", [False, True])
def test_underlying_native_policy_is_rechecked(monkeypatch, tmp_path, denied):
    plan = SimpleNamespace(command=("/usr/bin/node", str(tmp_path / "node_modules/eslint/bin/eslint.js"), "src"))
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


@pytest.mark.parametrize("phase", ["prelint", "postlint"])
def test_lifecycle_actions_are_not_silently_skipped(tmp_path, phase):
    (tmp_path / "package.json").write_text(json.dumps({"scripts": {"lint": "eslint src", phase: "node lifecycle.mjs"}}))
    with pytest.raises(RestrictedPytestError, match="lifecycle actions"):
        tool.prepare_restricted_node_tool(["npm", "run", "lint"], workspace=tmp_path)
