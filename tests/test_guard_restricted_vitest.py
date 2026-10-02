"""Local-only wrapper parsing and underlying native-policy denial checks."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.runtime import contained_test_hook as sink
from codex_plugin_scanner.guard.runtime import restricted_vitest as vitest
from codex_plugin_scanner.guard.runtime.restricted_pytest_model import RestrictedPytestError


@pytest.mark.parametrize("version, supported", [("4.1.8", True), ("3.2.0", False), ("invalid", False)])
def test_readonly_config_loader_is_version_bounded(tmp_path: Path, version: str, supported: bool) -> None:
    manifest = tmp_path / "package.json"
    manifest.write_text(json.dumps({"name": "vitest", "version": version}))
    args = ("run", "tests/example.test.ts")
    assert vitest._readonly_config_arguments(args, manifest) == (
        (*args, "--configLoader", "runner") if supported else args
    )
    explicit = (*args, "--configLoader=native")
    assert vitest._readonly_config_arguments(explicit, manifest) == explicit


def test_invalid_manifest_cannot_enable_config_loader(tmp_path: Path) -> None:
    manifest = tmp_path / "package.json"
    for content in ('[]', '{broken', 'x' * 65537):
        manifest.write_text(content)
        assert vitest._readonly_config_arguments(("run",), manifest) == ("run",)


def test_manifest_symlink_is_not_read_for_config_capability(tmp_path: Path) -> None:
    target = tmp_path / "other.json"
    target.write_text(json.dumps({"name": "vitest", "version": "4.1.8"}))
    manifest = tmp_path / "package.json"
    manifest.symlink_to(target)
    assert vitest._readonly_config_arguments(("run",), manifest) == ("run",)


@pytest.mark.parametrize(
    "command",
    [
        ["bunx", "vitest", "run", "tests/example.test.ts"],
        ["npx", "--no-install", "vitest", "run"],
        ["vitest", "run"],
        ["node", "/project/node_modules/vitest/vitest.mjs", "run"],
    ],
)
def test_local_vitest_run_arguments(command: list[str]) -> None:
    assert vitest.vitest_arguments(command)[0] == "run"


@pytest.mark.parametrize(
    "command",
    [
        ["bunx", "vitest@evil", "run"],
        ["bunx", "other", "run"],
        ["vitest", "watch"],
        ["vitest", "run", ";", "sh"],
        ["node", "/outside/tool.mjs", "run"],
    ],
)
def test_downloads_other_tools_and_shell_operators_are_not_execution_plans(command: list[str]) -> None:
    with pytest.raises(RestrictedPytestError):
        vitest.vitest_arguments(command)


@pytest.mark.parametrize("underlying_denied", [False, True])
def test_underlying_native_deny_cannot_inherit_wrapper_permission(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    underlying_denied: bool,
) -> None:
    plan = SimpleNamespace(command=("/usr/bin/node", str(tmp_path / "node_modules/vitest/vitest.mjs"), "run"))
    executed, authorized = [], []
    monkeypatch.setattr(vitest, "prepare_restricted_vitest", lambda *args, **kwargs: plan)
    monkeypatch.setattr(
        vitest, "run_restricted_vitest", lambda *args, **kwargs: executed.append(kwargs["prepared_plan"]) or 0
    )

    def authorize(payload):
        authorized.append(payload["tool_input"]["command"])
        if underlying_denied and len(authorized) == 2:
            return {"decision": "deny", "policy_action": "block", "reason_code": "native_command_permission_disabled"}
        return {
            "decision": "deny",
            "policy_action": "sandbox-required",
            "reason_code": "native_vitest_readonly_containment_required",
            "required_execution_profile": "vitest-readonly-v1",
        }

    payload = {"tool_name": "bash", "tool_input": {"command": "bunx vitest run"}}
    if underlying_denied:
        with pytest.raises(RestrictedPytestError):
            sink.run_authorized_contained_test(payload, workspace=tmp_path, timeout_seconds=20, authorize=authorize)
        assert executed == []
    else:
        assert (
            sink.run_authorized_contained_test(payload, workspace=tmp_path, timeout_seconds=20, authorize=authorize)
            == 0
        )
        assert executed == [plan]
    assert authorized[0] == "bunx vitest run"
    assert authorized[1].startswith("/usr/bin/node ")
    assert payload["tool_input"]["command"] == "bunx vitest run"
