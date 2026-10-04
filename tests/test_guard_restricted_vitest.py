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
    for content in ("[]", "{broken", "x" * 65537):
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
        ["bun", "x", "vitest", "run"],
        ["bun", "--cwd", "/project", "x", "vitest", "run"],
        ["bun", "--cwd=/project", "x", "--no-install", "vitest", "run"],
        ["npx", "--no-install", "vitest", "run"],
        ["vitest", "run"],
        ["node", "/project/node_modules/vitest/vitest.mjs", "run"],
    ],
)
def test_local_vitest_run_arguments(command: list[str]) -> None:
    assert vitest.vitest_arguments(command)[0] == "run"


def test_node_vitest_preserves_bounded_heap_option() -> None:
    command = [
        "node",
        "--max-old-space-size=12288",
        "/project/node_modules/vitest/vitest.mjs",
        "run",
    ]
    assert vitest.vitest_arguments(command) == ("run",)


@pytest.mark.parametrize(
    "command",
    [
        ["bunx", "vitest@evil", "run"],
        ["bunx", "other", "run"],
        ["vitest", "watch"],
        ["vitest", "run", ";", "sh"],
        ["node", "/outside/tool.mjs", "run"],
        ["bun", "--cwd", "", "x", "vitest", "run"],
        ["bun", "--cwd=/project", "x", "vitest@evil", "run"],
        ["bun", "--cwd=/project", "x", "vitest", "run", ";", "sh"],
    ],
)
def test_downloads_other_tools_and_shell_operators_are_not_execution_plans(command: list[str]) -> None:
    with pytest.raises(RestrictedPytestError):
        vitest.vitest_arguments(command)


@pytest.mark.parametrize("denied_context", [None, "original", "selected"])
@pytest.mark.parametrize("wrapper", ["bunx vitest run", "bun --cwd target x vitest run"])
def test_underlying_native_deny_cannot_inherit_wrapper_permission(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    denied_context: str | None,
    wrapper: str,
) -> None:
    plan = SimpleNamespace(
        command=("/usr/bin/node", str(tmp_path / "node_modules/vitest/vitest.mjs"), "run"), cwd=tmp_path / "target"
    )
    executed, authorized = [], []
    monkeypatch.setattr(vitest, "prepare_restricted_vitest", lambda *args, **kwargs: plan)
    monkeypatch.setattr(
        vitest, "run_restricted_vitest", lambda *args, **kwargs: executed.append(kwargs["prepared_plan"]) or 0
    )

    def authorize(payload):
        authorized.append(payload)
        denied_cwd = str(tmp_path if denied_context == "original" else plan.cwd)
        if denied_context and len(authorized) > 1 and payload["cwd"] == denied_cwd:
            return {"decision": "deny", "policy_action": "block", "reason_code": "native_command_permission_disabled"}
        return {
            "decision": "deny",
            "policy_action": "sandbox-required",
            "reason_code": "native_vitest_readonly_containment_required",
            "required_execution_profile": "vitest-readonly-v1",
        }

    payload = {"tool_name": "bash", "tool_input": {"command": wrapper}}
    if denied_context:
        with pytest.raises(RestrictedPytestError):
            sink.run_authorized_contained_test(payload, workspace=tmp_path, timeout_seconds=20, authorize=authorize)
        assert executed == []
    else:
        assert (
            sink.run_authorized_contained_test(payload, workspace=tmp_path, timeout_seconds=20, authorize=authorize)
            == 0
        )
        assert executed == [plan]
        assert [item["cwd"] for item in authorized[1:]] == [str(tmp_path), str(plan.cwd)]
    assert authorized[0]["tool_input"]["command"] == wrapper
    assert authorized[1]["tool_input"]["command"].startswith("/usr/bin/node ")
    assert payload["tool_input"]["command"] == wrapper


@pytest.mark.parametrize("denied_context", [None, "original", "selected"])
def test_selected_vitest_capabilities_respect_both_project_policies(tmp_path, monkeypatch, denied_context):
    selected = tmp_path.parent / "sibling"
    plan = SimpleNamespace(command=("/usr/bin/node", "/local/vitest.mjs", "run"), cwd=selected)
    monkeypatch.setattr(vitest, "prepare_restricted_vitest", lambda *args, **kwargs: plan)
    checked, executed = [], []

    def authorize(request):
        if request["tool_input"]["command"] == "cat source.ts":
            checked.append(request["cwd"])
            blocked = request["cwd"] == str(tmp_path if denied_context == "original" else selected)
            return {
                "decision": "deny" if denied_context and blocked else "allow",
                "policy_action": "block" if denied_context and blocked else "allow",
            }
        return {
            "decision": "deny",
            "policy_action": "sandbox-required",
            "reason_code": "native_vitest_readonly_containment_required",
            "required_execution_profile": "vitest-readonly-v1",
        }

    def execute(*args, authorize_capability, **kwargs):
        authorize_capability(("cat", "source.ts"))
        executed.append(True)
        return 0

    monkeypatch.setattr(vitest, "run_restricted_vitest", execute)
    request = {
        "tool_name": "bash",
        "cwd": str(tmp_path),
        "tool_input": {"command": "bun --cwd ../sibling x vitest run"},
    }
    if denied_context:
        with pytest.raises(RestrictedPytestError):
            sink.run_authorized_contained_test(request, workspace=tmp_path, timeout_seconds=20, authorize=authorize)
        assert executed == []
    else:
        assert (
            sink.run_authorized_contained_test(request, workspace=tmp_path, timeout_seconds=20, authorize=authorize)
            == 0
        )
        assert checked == [str(tmp_path), str(selected)]
        assert executed == [True]


@pytest.mark.parametrize("blocked", [False, True])
def test_transform_capability_requires_the_same_native_profile(tmp_path, monkeypatch, blocked):
    plan = SimpleNamespace(command=("/usr/bin/node", "/local/vitest.mjs", "run"), cwd=tmp_path)
    monkeypatch.setattr(vitest, "prepare_restricted_vitest", lambda *args, **kwargs: plan)
    executed = []

    def authorize(request):
        child = "--service=" in request["tool_input"]["command"]
        return {
            "decision": "deny",
            "policy_action": "block" if child and blocked else "sandbox-required",
            "reason_code": "native_vitest_readonly_containment_required",
            "required_execution_profile": "vitest-readonly-v1",
        }

    def execute(*args, authorize_capability, **kwargs):
        authorize_capability(
            (str(tmp_path / "node_modules/@esbuild/darwin-arm64/bin/esbuild"), "--service=0.25.4", "--ping")
        )
        executed.append(True)
        return 0

    monkeypatch.setattr(vitest, "run_restricted_vitest", execute)
    payload = {"tool_name": "bash", "tool_input": {"command": "bunx vitest run"}}
    if blocked:
        with pytest.raises(RestrictedPytestError):
            sink.run_authorized_contained_test(payload, workspace=tmp_path, timeout_seconds=20, authorize=authorize)
        assert executed == []
    else:
        assert (
            sink.run_authorized_contained_test(payload, workspace=tmp_path, timeout_seconds=20, authorize=authorize)
            == 0
        )
        assert executed == [True]


@pytest.mark.parametrize("form", ["relative", "absolute", "equals"])
def test_bun_cwd_resolves_before_local_dependency_preparation(tmp_path, monkeypatch, form):
    target = tmp_path / "target"
    target.mkdir()
    arguments = ["--cwd=target"] if form == "equals" else ["--cwd", "target" if form == "relative" else str(target)]
    captured = []

    def prepare(command, *, workspace, cwd):
        captured.append((workspace, cwd))
        raise RestrictedPytestError("test_stop", "stop before backend preparation")

    monkeypatch.setattr(vitest, "prepare_restricted_node_test", prepare)
    with pytest.raises(RestrictedPytestError, match="stop before backend"):
        vitest.prepare_restricted_vitest(["bun", *arguments, "x", "vitest", "run"], workspace=tmp_path, cwd=tmp_path)
    assert captured == [(target.resolve(), target.resolve())]
