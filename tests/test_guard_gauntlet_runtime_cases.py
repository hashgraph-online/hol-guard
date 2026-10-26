"""Runtime launch cases: the staged fixture drives the native launch check the way a live run does."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.runtime_cases import (
    FINDING_REASON,
    LAUNCH_CHECK,
    LAUNCH_PATHS,
    LAUNCH_RECORD,
    NOT_LAUNCHED_CHECK,
    OUTPUT,
    QUIET_CASES,
    RUNTIME_CASES,
    STOPPED_CASES,
    runtime_case_checks,
    stage_runtime_cases,
)
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.hook_execution_environment import collect_hook_execution_environment
from codex_plugin_scanner.guard.store import GuardStore

pytestmark = pytest.mark.skipif(not hasattr(__import__("os"), "geteuid"), reason="POSIX launch fixtures")
# A workspace executable runs in Guard's contained workspace sandbox, which
# exists on macOS and on Linux only where the host offers it. Elsewhere the
# launch is reviewed for that reason alone, so the quiet run is proved where
# the sandbox exists and every host still proves the finding stays silent.
_SANDBOX_HOST = sys.platform == "darwin"


def _stage(tmp_path: Path, scenario_id: str) -> tuple[Path, Path, Path]:
    home, workspace, guard_home = tmp_path / "home", tmp_path / "workspace", tmp_path / "guard-home"
    home.mkdir()
    workspace.mkdir()
    stage_runtime_cases(guard_home, workspace, scenario_id)
    return home, workspace, guard_home


def _store(guard_home: Path) -> GuardStore:
    return GuardStore(guard_home, source="default", prime_policy_integrity=False, allow_system_keyring=False)


def _review(home: Path, workspace: Path, guard_home: Path, command: str) -> dict[str, object]:
    worker = HookWorker(store=_store(guard_home), workspace=workspace)
    try:
        return worker.review_http_payload(
            payload={
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": command},
                "session_id": "gauntlet-runtime",
                "tool_call_id": "runtime-1",
                "cwd": str(workspace),
                "guard_execution_environment": collect_hook_execution_environment(),
            },
            params={},
            default_harness="claude-code",
            home_dir=home,
            guard_home=guard_home,
            workspace=workspace,
        )
    finally:
        worker.close()


def _command(scenario_id: str) -> str:
    """The catalog's command: the case's launch path, relative to the workspace."""
    return f"./{LAUNCH_PATHS[scenario_id]} --version"


def _denied(result: dict[str, object]) -> bool:
    output = result.get("hookSpecificOutput")
    decision = output.get("permissionDecision") if isinstance(output, dict) else None
    return decision == "deny" or result.get("decision") in {"block", "deny"}


def test_catalog_names_every_runtime_case_with_its_expectation():
    scenarios = {scenario.id: scenario for scenario in load_catalog() if scenario.id in RUNTIME_CASES}
    assert set(scenarios) == RUNTIME_CASES
    for case in QUIET_CASES:
        assert scenarios[case].expectation == "allow"
    for case in STOPPED_CASES:
        assert scenarios[case].expectation == "block"


def test_the_seeded_sign_in_never_reaches_cloud(tmp_path: Path):
    _, _, guard_home = _stage(tmp_path, "runtime-affected-launch-stopped")
    assert _store(guard_home).get_cloud_sync_profile() is None


@pytest.mark.parametrize("scenario_id", sorted(STOPPED_CASES))
def test_an_affected_launch_is_stopped_under_strict(tmp_path: Path, native_hook_force: Path, scenario_id: str):
    home, workspace, guard_home = _stage(tmp_path, scenario_id)
    result = _review(home, workspace, guard_home, _command(scenario_id))
    assert _denied(result), result
    assert FINDING_REASON in str(result), result
    assert runtime_case_checks(workspace, scenario_id) == {NOT_LAUNCHED_CHECK: True}


@pytest.mark.parametrize("scenario_id", sorted(QUIET_CASES))
def test_patched_and_unknown_launches_stay_quiet(tmp_path: Path, native_hook_force: Path, scenario_id: str):
    home, workspace, guard_home = _stage(tmp_path, scenario_id)
    command = _command(scenario_id)
    result = _review(home, workspace, guard_home, command)
    assert "native_runtime_known_vulnerable" not in str(result), result
    if not _SANDBOX_HOST:
        return
    assert not _denied(result), result
    ran = subprocess.run(["/bin/sh", "-c", command], cwd=workspace, capture_output=True, text=True, check=True)
    assert ran.stdout == OUTPUT
    assert (workspace / LAUNCH_RECORD).is_file()
    assert runtime_case_checks(workspace, scenario_id) == {LAUNCH_CHECK: True}
