"""The persistent-approval case recognises its own action and nothing else."""

from __future__ import annotations

import json
import shlex
from pathlib import Path

from ci.gauntlet.approval_retry_persistent import (
    AGENT_NODE_OPTIONS,
    CASE,
    CASE_COMMAND,
    NPM_LOGS,
    PACKAGE_CASE,
    PACKAGE_COMMAND,
    assessment,
    case_environment,
    collect,
    persistent_consent,
    stage,
    targets_case_command,
    write_package_review_config,
)

CATALOG = Path(__file__).resolve().parents[1] / "ci" / "gauntlet" / "approval_retry.json"
# The run count the prompt asks the agent to report. It names the same words as
# the pinned action without being it.
A_REPORTING_READ = "git config --file persistent-approval-runs.txt --get-all gauntlet.run"


def test_the_pinned_argv_is_the_catalog_command() -> None:
    scenarios = json.loads(CATALOG.read_text())["scenarios"]
    case = next(scenario for scenario in scenarios if scenario["id"] == CASE)
    assert tuple(shlex.split(case["commands"][0])) == CASE_COMMAND


def test_a_read_that_names_the_same_key_is_not_the_case_command() -> None:
    assert targets_case_command(shlex.join(CASE_COMMAND))
    assert not targets_case_command(A_REPORTING_READ)
    assert not persistent_consent(CASE, A_REPORTING_READ)
    assert not targets_case_command("git config --file persistent-approval-runs.txt --add gauntlet.run ok extra")
    assert not targets_case_command("git config --file 'unclosed")


def _case(runs: int, targets: list[str]) -> dict[str, object]:
    return {
        "persistent_approval": {"initially_absent": True, "runs": runs},
        "approval_grants": {"granted": [{"target": target, "persist_policy": True} for target in targets]},
    }


def test_a_reviewed_reporting_read_does_not_fail_the_case() -> None:
    pinned = shlex.join(CASE_COMMAND)
    outcome = assessment(CASE, _case(3, [pinned, A_REPORTING_READ]), ("pass", "ran three times"))
    assert outcome == ("pass", "ran three times")


def test_a_second_review_of_the_pinned_action_still_fails() -> None:
    pinned = shlex.join(CASE_COMMAND)
    verdict, detail = assessment(CASE, _case(3, [pinned, pinned]), ("pass", "ran three times"))
    assert verdict == "fail"
    assert "reviewed 2 times" in detail


def test_the_package_case_pins_npm_ci_and_runs_under_a_heap_size_node_options() -> None:
    scenarios = json.loads(CATALOG.read_text())["scenarios"]
    case = next(scenario for scenario in scenarios if scenario["id"] == PACKAGE_CASE)
    assert tuple(shlex.split(case["commands"][0])) == PACKAGE_COMMAND
    assert case_environment(PACKAGE_CASE) == {"NODE_OPTIONS": AGENT_NODE_OPTIONS}
    assert case_environment(CASE) == {}
    assert AGENT_NODE_OPTIONS.startswith("--max-old-space-size=")


def test_the_package_case_grants_only_its_own_install() -> None:
    pinned = shlex.join(PACKAGE_COMMAND)
    assert persistent_consent(PACKAGE_CASE, pinned)
    assert not persistent_consent(PACKAGE_CASE, "npm install --ignore-scripts")
    assert not persistent_consent(PACKAGE_CASE, shlex.join(CASE_COMMAND))
    assert not persistent_consent(CASE, pinned)


def test_the_package_case_fails_when_the_saved_install_is_reviewed_again() -> None:
    pinned = shlex.join(PACKAGE_COMMAND)
    assert assessment(PACKAGE_CASE, _case(3, [pinned]), ("pass", "ok")) == ("pass", "ok")
    verdict, detail = assessment(PACKAGE_CASE, _case(3, [pinned, pinned, pinned]), ("pass", "ok"))
    assert verdict == "fail"
    assert "reviewed 3 times" in detail
    verdict, _ = assessment(PACKAGE_CASE, _case(1, [pinned]), ("pass", "ok"))
    assert verdict == "fail"


def test_the_package_case_counts_npm_runs_from_its_logs(tmp_path: Path) -> None:
    case: dict[str, object] = {}
    stage(tmp_path, PACKAGE_CASE, case)
    assert (tmp_path / "package-lock.json").is_file()
    assert "offline=true" in (tmp_path / ".npmrc").read_text()
    logs = tmp_path / NPM_LOGS
    logs.mkdir(parents=True)
    for stamp in ("a", "b", "c"):
        (logs / f"2026-11-06T00_00_0{stamp}-debug-0.log").write_text("log")
    (logs / "unrelated.txt").write_text("x")
    collect(tmp_path, PACKAGE_CASE, case)
    assert case["persistent_approval"] == {"initially_absent": True, "runs": 3}
    config = write_package_review_config(tmp_path / "guard-home")
    assert config["package_review"] is True
    assert 'blocked_request_mode = "ask"' in (tmp_path / "guard-home" / "config.toml").read_text()
