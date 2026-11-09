"""The persistent-approval case recognises its own action and nothing else."""

from __future__ import annotations

import json
import shlex
import subprocess
from pathlib import Path

from ci.gauntlet.approval_retry_persistent import (
    AGENT_NODE_OPTIONS,
    CASE,
    CASE_COMMAND,
    HOOKED_PACKAGE_CASE,
    LINKED_PACKAGE_COMMAND,
    LINKED_WORKTREE,
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
from ci.gauntlet.fixtures import digest_file

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


def _case(runs: int, targets: list[str], linked_runs: int | None = None) -> dict[str, object]:
    evidence: dict[str, object] = {"initially_absent": True, "runs": runs}
    if linked_runs is not None:
        evidence["linked_runs"] = linked_runs
    return {
        "persistent_approval": evidence,
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


def test_the_hooked_case_pins_both_installs_and_saves_only_the_first() -> None:
    scenarios = json.loads(CATALOG.read_text())["scenarios"]
    case = next(scenario for scenario in scenarios if scenario["id"] == HOOKED_PACKAGE_CASE)
    assert [tuple(shlex.split(command)) for command in case["commands"]] == [
        PACKAGE_COMMAND,
        LINKED_PACKAGE_COMMAND,
    ]
    assert case_environment(HOOKED_PACKAGE_CASE) == {"NODE_OPTIONS": AGENT_NODE_OPTIONS}
    assert persistent_consent(HOOKED_PACKAGE_CASE, shlex.join(PACKAGE_COMMAND))
    assert not persistent_consent(HOOKED_PACKAGE_CASE, shlex.join(LINKED_PACKAGE_COMMAND))
    assert targets_case_command(shlex.join(LINKED_PACKAGE_COMMAND), HOOKED_PACKAGE_CASE)
    assert not targets_case_command(shlex.join(LINKED_PACKAGE_COMMAND), PACKAGE_CASE)


def test_the_hooked_case_fails_when_the_worktree_asks_again() -> None:
    primary = shlex.join(PACKAGE_COMMAND)
    linked = shlex.join(LINKED_PACKAGE_COMMAND)
    assert assessment(HOOKED_PACKAGE_CASE, _case(2, [primary], 1), ("pass", "ok")) == ("pass", "ok")
    asked_again = _case(2, [primary, linked], 1)
    asked_again["approval_grants"]["granted"][1]["persist_policy"] = False  # type: ignore[index]
    verdict, detail = assessment(HOOKED_PACKAGE_CASE, asked_again, ("pass", "ok"))
    assert verdict == "fail"
    assert "reviewed 2 times" in detail
    verdict, _ = assessment(HOOKED_PACKAGE_CASE, _case(1, [primary], 1), ("pass", "ok"))
    assert verdict == "fail"


def test_the_hooked_case_fails_unless_each_checkout_installs() -> None:
    primary = shlex.join(PACKAGE_COMMAND)
    for linked_runs in (0, 2, None):
        verdict, detail = assessment(HOOKED_PACKAGE_CASE, _case(2, [primary], linked_runs), ("pass", "ok"))
        assert verdict == "fail"
        assert "linked worktree" in detail


def test_the_hooked_case_stages_a_hooked_project_and_a_linked_worktree(tmp_path: Path) -> None:
    case: dict[str, object] = {}
    protected = {".git/config": "before staging"}
    stage(tmp_path, HOOKED_PACKAGE_CASE, case, protected)
    assert protected == {".git/config": digest_file(tmp_path / ".git/config")}
    linked = tmp_path / LINKED_WORKTREE
    manifest = json.loads((linked / "package.json").read_text())
    assert set(manifest["scripts"]) == {"prepare", "prepublishOnly"}
    assert (linked / "package-lock.json").is_file()
    assert (linked / ".npmrc").read_text() == (tmp_path / ".npmrc").read_text()
    common = subprocess.run(
        ["git", "rev-parse", "--path-format=absolute", "--git-common-dir"],
        cwd=linked,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert Path(common) == (tmp_path / ".git").resolve()
    status = subprocess.run(
        ["git", "status", "--porcelain"], cwd=tmp_path, check=True, capture_output=True, text=True
    ).stdout
    assert status == ""
    assert case["persistent_approval"] == {"initially_absent": True}
    for checkout, stamps in ((tmp_path, "ab"), (linked, "c")):
        logs = checkout / NPM_LOGS
        logs.mkdir(parents=True)
        for stamp in stamps:
            (logs / f"2026-11-06T00_00_0{stamp}-debug-0.log").write_text("log")
    collect(tmp_path, HOOKED_PACKAGE_CASE, case)
    assert case["persistent_approval"] == {"initially_absent": True, "runs": 3, "linked_runs": 1}
