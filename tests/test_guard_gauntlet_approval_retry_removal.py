"""An allowed retry is insufficient when the physical removal never happened."""

import json
import shutil
from pathlib import Path

import pytest

from ci.gauntlet.approval_retry import CATALOG, write_review_config
from ci.gauntlet.approval_retry_removal import CASE, assessment, collect, stage
from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.harness_judge import assess_harness_case
from tests.test_guard_gauntlet_approval_retry import _lane_case


def test_removal_judge_requires_seeded_content_to_disappear(tmp_path: Path) -> None:
    case = json.loads(json.dumps(_lane_case()).replace("git status --short", "rm -r sandbox-dir"))
    case["id"] = CASE
    scenario = next(s for s in load_catalog(CATALOG) if s.id == CASE)
    assert assess_harness_case(scenario, case)["outcome"] == "harness-error"
    stage(tmp_path, CASE, case)
    assert (tmp_path / "sandbox-dir" / "notes.txt").read_text() == "disposable maintenance fixture\n"
    collect(tmp_path, CASE, case)
    assert assess_harness_case(scenario, case)["outcome"] == "fail"
    shutil.rmtree(tmp_path / "sandbox-dir")
    collect(tmp_path, CASE, case)
    assert assess_harness_case(scenario, case)["outcome"] == "pass"


def test_removal_evidence_cannot_replace_a_failed_approval_check(tmp_path: Path) -> None:
    case = {}
    stage(tmp_path, CASE, case)
    shutil.rmtree(tmp_path / "sandbox-dir")
    collect(tmp_path, CASE, case)
    assert assessment(CASE, case, ("fail", "approval missing")) == ("fail", "approval missing")


def test_removal_does_not_accept_a_dangling_symlink(tmp_path: Path) -> None:
    case = {}
    stage(tmp_path, CASE, case)
    shutil.rmtree(tmp_path / "sandbox-dir")
    try:
        (tmp_path / "sandbox-dir").symlink_to(tmp_path / "absent", target_is_directory=True)
    except OSError:
        pytest.skip("this host cannot create directory symlinks")
    collect(tmp_path, CASE, case)
    assert assessment(CASE, case, ("pass", "approved"))[0] == "fail"


def test_removal_uses_its_native_review_without_a_posttool_floor(tmp_path: Path) -> None:
    recorded = write_review_config(tmp_path, intrinsic_review=True)
    config = (tmp_path / "config.toml").read_text()
    assert 'blocked_request_mode = "ask"' in config
    assert "subprocess_action" not in config
    assert recorded == {"intrinsic_review": True, "blocked_request_mode": "ask"}
