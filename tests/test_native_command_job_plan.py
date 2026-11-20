"""The native runtime plans every leased command job before Python runs it."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_command_job_plan
from codex_plugin_scanner.guard.harness_context import HarnessContext
from codex_plugin_scanner.guard.native_command_job_plan import CommandJobPlanError, plan_command_job
from codex_plugin_scanner.guard.runtime import command_executors
from codex_plugin_scanner.guard.store import GuardStore


@pytest.mark.usefixtures("native_command_capability_runtime")
def test_every_supported_operation_has_a_plan() -> None:
    for operation in command_executors.SUPPORTED_COMMAND_OPERATIONS:
        plan = plan_command_job(operation, {"harness": "codex"})
        assert plan["action"] in {"run", "confirm"}, operation
        if plan["action"] == "run":
            assert plan["operation"] == operation


@pytest.mark.usefixtures("native_command_capability_runtime")
def test_the_runtime_checks_arguments_and_builds_confirmations() -> None:
    assert plan_command_job("guard.packageShims.install", {"managers": [" NPM "]}) == {
        "action": "run",
        "operation": "guard.packageShims.install",
        "family": "package_shims",
        "managers": ["npm"],
        "harness": None,
        "surface": None,
    }
    assert plan_command_job("guard.packageShims.repair", {"managers": ["npm", "npm"]}) == {
        "action": "fail",
        "failure_code": "duplicate_manager",
        "failure_message": "duplicate manager",
    }
    removal = plan_command_job("guard.app.remove", {"harness": "codex"})
    assert removal["action"] == "confirm"
    assert removal["data"]["confirm_command"] == "hol-guard apps disconnect codex --confirm disconnect-codex"
    assert plan_command_job("guard.unknown", {})["failure_code"] == "unsupported_operation"


@pytest.mark.parametrize(
    "plan",
    [
        None,
        {"action": "fail", "failure_code": "", "failure_message": "x"},
        {"action": "confirm", "data": []},
        {"action": "run", "operation": "x", "family": "shell", "managers": None, "harness": None, "surface": None},
        {"action": "run", "operation": "x", "family": [], "managers": None, "harness": None, "surface": None},
        {"action": "run", "operation": "x", "family": {}, "managers": None, "harness": None, "surface": None},
        {"action": [], "operation": "x"},
        {"action": "run", "operation": "x", "family": "app", "managers": [1], "harness": None, "surface": None},
        {"action": "run", "operation": "x", "family": "app", "managers": None, "harness": None},
        {"action": "skip"},
    ],
)
def test_malformed_plans_are_refused(plan: object) -> None:
    assert not native_command_job_plan._valid_plan(plan)


def test_an_unplanned_job_fails_without_running(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def unavailable(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise CommandJobPlanError("native_command_job_plan_unavailable")

    ran: list[object] = []
    monkeypatch.setattr(command_executors, "plan_command_job", unavailable)
    monkeypatch.setattr(command_executors, "package_shim_status", ran.append)
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard")
    result = command_executors.execute_guard_command_job(
        {"id": "job-1", "operation": "guard.packageShims.status", "payload": {}},
        context=context,
        store=GuardStore(tmp_path / "guard"),
        now=lambda: "2026-11-20T00:00:00Z",
    )
    assert result["failureCode"] == "native_command_job_plan_unavailable"
    assert ran == []
