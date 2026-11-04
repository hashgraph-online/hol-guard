"""Approval proof requires the harmless marker, without executing any deletion."""

import json
from pathlib import Path

import pytest

from ci.gauntlet.approval_retry import CATALOG, write_review_config
from ci.gauntlet.approval_retry_marker import CASE, CONTENT, MARKER, assessment, collect, stage
from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.harness_judge import assess_harness_case
from tests.test_guard_gauntlet_approval_retry import _lane_case


def test_marker_judge_requires_the_approved_command_to_create_content(tmp_path: Path) -> None:
    scenario = next(s for s in load_catalog(CATALOG) if s.id == CASE)
    command_json = json.dumps(scenario.commands[0])[1:-1]
    case = json.loads(json.dumps(_lane_case()).replace("git status --short", command_json))
    case["id"] = CASE
    assert assess_harness_case(scenario, case)["outcome"] == "harness-error"
    stage(tmp_path, CASE, case)
    assert not (tmp_path / MARKER).exists()
    collect(tmp_path, CASE, case)
    assert assess_harness_case(scenario, case)["outcome"] == "fail"
    (tmp_path / MARKER).write_text(CONTENT, encoding="utf-8")
    collect(tmp_path, CASE, case)
    assert assess_harness_case(scenario, case)["outcome"] == "pass"


def test_marker_cannot_replace_a_failed_approval_check(tmp_path: Path) -> None:
    case = {}
    stage(tmp_path, CASE, case)
    (tmp_path / MARKER).write_text(CONTENT, encoding="utf-8")
    collect(tmp_path, CASE, case)
    assert assessment(CASE, case, ("fail", "approval missing")) == ("fail", "approval missing")


def test_marker_does_not_accept_a_symlink(tmp_path: Path) -> None:
    case = {}
    stage(tmp_path, CASE, case)
    target = tmp_path / "other-file"
    target.write_text(CONTENT, encoding="utf-8")
    try:
        (tmp_path / MARKER).symlink_to(target)
    except OSError:
        pytest.skip("this host cannot create symlinks")
    collect(tmp_path, CASE, case)
    assert assessment(CASE, case, ("pass", "approved"))[0] == "fail"


def test_marker_uses_its_native_review_without_a_posttool_floor(tmp_path: Path) -> None:
    recorded = write_review_config(tmp_path, intrinsic_review=True)
    config = (tmp_path / "config.toml").read_text()
    assert 'blocked_request_mode = "ask"' in config
    assert "subprocess_action" not in config
    assert recorded == {"intrinsic_review": True, "blocked_request_mode": "ask"}
