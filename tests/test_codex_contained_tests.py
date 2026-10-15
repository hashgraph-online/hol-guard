"""Codex reaches the contained runner only when the launching release applies updatedInput."""

from __future__ import annotations

import json
import shlex
import subprocess
import sys
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import codex_contained_tests as route
from codex_plugin_scanner.guard.adapters import codex_daemon_hook_bridge as bridge
from codex_plugin_scanner.guard.adapters.codex_hook_response import codex_hook_response


def receipt() -> dict[str, object]:
    return {
        "decision": "deny",
        "policy_action": "sandbox-required",
        "reason_code": "native_pytest_readonly_containment_required",
        "required_execution_profile": "pytest-readonly-v2",
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": "HOL Guard requires a contained run.",
        },
    }


def hook_input(workspace: Path, **extra: object) -> str:
    return json.dumps(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "cwd": str(workspace),
            "tool_input": {"command": "pytest -q"},
            **extra,
        }
    )


def capable(monkeypatch: pytest.MonkeyPatch, version: str | None) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(route, "launching_codex_executable", lambda: None if version is None else Path("/bin/codex"))

    def run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess([], 0, stdout=f"{version}\n", stderr="")

    monkeypatch.setattr(route.subprocess, "run", run)


def test_current_codex_rewrites_to_the_contained_sink(tmp_path, monkeypatch):
    capable(monkeypatch, "codex-cli 0.162.1")
    hook_home = tmp_path / "hook-home"
    result = route.route_codex_containment(
        receipt(),
        hook_input=hook_input(tmp_path),
        guard_home=tmp_path / "guard",
        home_dir=hook_home,
    )
    shaped = codex_hook_response(result, event_name="PreToolUse")
    assert shaped["hookSpecificOutput"]["permissionDecision"] == "allow"
    argv = shlex.split(shaped["hookSpecificOutput"]["updatedInput"]["command"])
    assert "execute-contained-test" in argv
    assert argv[argv.index("--harness") + 1] == "codex"
    assert argv[argv.index("--guard-home") + 1] == str(tmp_path / "guard")
    assert argv[argv.index("--home") + 1] == str(hook_home)
    assert argv[argv.index("--home") + 1] != str(Path.home())
    Path(argv[argv.index("--request-file") + 1]).unlink()


@pytest.mark.parametrize(
    "version",
    [
        None,
        "codex-cli 0.130.0",
        "codex-cli 0.131.0-alpha.3",
        "codex-cli 0.132.0-alpha.1",
        "codex-cli 2.0.0-rc.1",
        "codex 0.162.1",
        "codex-cli 1.0",
    ],
)
def test_old_or_unknown_codex_keeps_the_denial_with_an_update_hint(tmp_path, monkeypatch, version):
    capable(monkeypatch, version)
    result = route.route_codex_containment(
        receipt(),
        hook_input=hook_input(tmp_path),
        guard_home=tmp_path / "guard",
        home_dir=tmp_path / "hook-home",
    )
    shaped = codex_hook_response(result, event_name="PreToolUse")
    assert shaped["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "updatedInput" not in shaped["hookSpecificOutput"]
    assert shaped["hookSpecificOutput"]["permissionDecisionReason"].endswith(route.UPDATE_HINT)


@pytest.mark.parametrize("version", ["codex-cli 0.131.0", "codex-cli 0.131.1", "codex-cli 0.132.0", "codex-cli 1.0.0"])
def test_releases_from_0_131_apply_updated_input(monkeypatch, version):
    capable(monkeypatch, version)
    assert route.codex_applies_updated_input(Path("/bin/codex"))


def test_failed_version_probe_never_rewrites(monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")

    def boom(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired("codex", 3)

    monkeypatch.setattr(route.subprocess, "run", boom)
    assert not route.codex_applies_updated_input(Path("/bin/codex"))


@pytest.mark.parametrize(
    ("change", "extra"),
    [
        ({"policy_action": "review"}, {}),
        ({"decision": "allow"}, {}),
        ({}, {"guard_containment_receipt_only": True}),
    ],
)
def test_non_containment_and_sink_rechecks_pass_through(tmp_path, monkeypatch, change, extra):
    capable(monkeypatch, "codex-cli 0.162.1")
    native = {**receipt(), **change}
    result = route.route_codex_containment(
        native,
        hook_input=hook_input(tmp_path, **extra),
        guard_home=tmp_path / "guard",
        home_dir=tmp_path / "hook-home",
    )
    assert result is native


def test_unbound_or_relative_home_keeps_the_original_denial(tmp_path, monkeypatch):
    capable(monkeypatch, "codex-cli 0.162.1")
    native = receipt()
    assert (
        route.route_codex_containment(
            native,
            hook_input=hook_input(tmp_path),
            guard_home=tmp_path / "guard",
            home_dir=None,
        )
        is native
    )
    assert (
        route.route_codex_containment(
            native,
            hook_input=hook_input(tmp_path),
            guard_home=tmp_path / "guard",
            home_dir=Path("relative-home"),
        )
        is native
    )


def test_version_probe_stops_at_the_hook_deadline(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(route, "launching_codex_executable", lambda: Path("/bin/codex"))
    clock = {"now": 50.0}
    monkeypatch.setattr(route.time, "monotonic", lambda: clock["now"])
    recorded: dict[str, float] = {}

    def run(*_args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        recorded["timeout"] = float(kwargs["timeout"])
        return subprocess.CompletedProcess([], 0, stdout="codex-cli 0.162.1\n", stderr="")

    monkeypatch.setattr(route.subprocess, "run", run)
    allowed = route.route_codex_containment(
        receipt(),
        hook_input=hook_input(tmp_path),
        guard_home=tmp_path / "guard",
        home_dir=tmp_path / "hook-home",
        deadline=50.25,
    )
    shaped = codex_hook_response(allowed, event_name="PreToolUse")
    assert shaped["hookSpecificOutput"]["permissionDecision"] == "allow"
    assert recorded["timeout"] == 0.25
    allowed_argv = shlex.split(shaped["hookSpecificOutput"]["updatedInput"]["command"])
    Path(allowed_argv[allowed_argv.index("--request-file") + 1]).unlink()

    clock["now"] = 80.0
    denied = route.route_codex_containment(
        receipt(),
        hook_input=hook_input(tmp_path),
        guard_home=tmp_path / "guard",
        home_dir=tmp_path / "hook-home",
        deadline=80.0,
    )
    shaped_denial = codex_hook_response(denied, event_name="PreToolUse")
    assert shaped_denial["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "updatedInput" not in shaped_denial["hookSpecificOutput"]
    assert recorded["timeout"] == 0.25


def test_bridge_rewrite_uses_the_home_bound_into_the_hook(tmp_path, monkeypatch):
    capable(monkeypatch, "codex-cli 0.162.1")
    hook_home = tmp_path / "hook-home"
    stdout = bridge._bridge_output(
        receipt(),
        event_name="PreToolUse",
        hook_input=hook_input(tmp_path),
        state_path=tmp_path / "guard" / "daemon-state.json",
        deadline=time.monotonic() + 30,
        query=f"guard-home={tmp_path / 'guard'}&home={hook_home}",
    )
    shaped = json.loads(stdout)
    argv = shlex.split(shaped["hookSpecificOutput"]["updatedInput"]["command"])
    assert argv[argv.index("--home") + 1] == str(hook_home)
    assert argv[argv.index("--home") + 1] != str(Path.home())
    assert argv[argv.index("--guard-home") + 1] == str(tmp_path / "guard")
    Path(argv[argv.index("--request-file") + 1]).unlink()


def test_bridge_without_an_absolute_home_keeps_the_denial(tmp_path, monkeypatch):
    capable(monkeypatch, "codex-cli 0.162.1")
    stdout = bridge._bridge_output(
        receipt(),
        event_name="PreToolUse",
        hook_input=hook_input(tmp_path),
        state_path=tmp_path / "guard" / "daemon-state.json",
        deadline=time.monotonic() + 30,
        query="home=relative-home&home=/also/not/single",
    )
    shaped = json.loads(stdout)
    assert shaped["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "updatedInput" not in shaped["hookSpecificOutput"]


def test_other_platforms_and_missing_guard_home_pass_through(tmp_path, monkeypatch):
    capable(monkeypatch, "codex-cli 0.162.1")
    native = receipt()
    assert route.route_codex_containment(native, hook_input=hook_input(tmp_path), guard_home=None) is native
    monkeypatch.setattr(sys, "platform", "linux")
    assert (
        route.route_codex_containment(native, hook_input=hook_input(tmp_path), guard_home=tmp_path / "guard") is native
    )


def test_linux_routes_the_workspace_sandbox(tmp_path, monkeypatch):
    capable(monkeypatch, "codex-cli 0.162.1")
    monkeypatch.setattr(sys, "platform", "linux")
    native = {
        **receipt(),
        "reason_code": "native_workspace_containment_required",
        "required_execution_profile": "workspace-contained-v1",
    }
    result = route.route_codex_containment(
        native, hook_input=hook_input(tmp_path), guard_home=tmp_path / "guard", home_dir=tmp_path / "hook-home"
    )
    shaped = codex_hook_response(result, event_name="PreToolUse")
    assert shaped["hookSpecificOutput"]["permissionDecision"] == "allow"
    argv = shlex.split(shaped["hookSpecificOutput"]["updatedInput"]["command"])
    Path(argv[argv.index("--request-file") + 1]).unlink()


def test_linux_walks_proc_to_the_launching_codex(monkeypatch):
    executables = {"/proc/40/exe": "/usr/bin/bash", "/proc/30/exe": "/opt/codex/bin/codex"}
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(route.os, "getppid", lambda: 40)
    monkeypatch.setattr(route.os, "readlink", lambda path: executables[path])
    monkeypatch.setattr(route.Path, "read_text", lambda self, **_kwargs: "40 (sh (x) y) S 30 1 1")
    assert route.launching_codex_executable() == Path("/opt/codex/bin/codex")


def test_codex_response_drops_allow_without_updated_input():
    shaped = codex_hook_response(
        {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"}},
        event_name="PreToolUse",
    )
    assert shaped == {"hookSpecificOutput": {"hookEventName": "PreToolUse"}}


def test_policy_deny_overrides_an_updated_input_allow():
    shaped = codex_hook_response(
        {
            "policy_action": "deny",
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "updatedInput": {"command": "true"},
            },
        },
        event_name="PreToolUse",
    )
    assert shaped["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "updatedInput" not in shaped["hookSpecificOutput"]
