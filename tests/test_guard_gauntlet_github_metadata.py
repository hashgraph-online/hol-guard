"""Metadata cases must execute the isolated recorder and prove the complete argv sequence."""

import os
import shlex
import subprocess
from pathlib import Path

from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.fixtures import create_fixture, filesystem_checks
from ci.gauntlet.proofs import required_checks
from ci.gauntlet.review_fixtures import (
    GH_LOG,
    GITHUB_METADATA_CASE,
    GITHUB_METADATA_CONTROL,
    GITHUB_STUB_CASES,
    METADATA_CALLS,
)


def test_live_metadata_pair_requires_the_isolated_recorder(tmp_path: Path) -> None:
    scenarios = {scenario.id: scenario for scenario in load_catalog()}
    assert {GITHUB_METADATA_CASE, GITHUB_METADATA_CONTROL} <= GITHUB_STUB_CASES
    scenario = scenarios[GITHUB_METADATA_CASE]
    assert [tuple(shlex.split(command)[1:]) for command in scenario.commands] == list(METADATA_CALLS)
    check = "github-metadata-calls-exact"
    assert check in required_checks(scenario)
    fixture = create_fixture(tmp_path / "metadata", realistic=True, scenario_id=GITHUB_METADATA_CASE)
    assert filesystem_checks(fixture, "native-tools", GITHUB_METADATA_CASE)[check] is False
    for args in METADATA_CALLS:
        subprocess.run(
            [str(fixture.root / "bin" / ("gh.cmd" if os.name == "nt" else "gh")), *args],
            capture_output=True,
            check=True,
            timeout=10,
        )
    assert filesystem_checks(fixture, "native-tools", GITHUB_METADATA_CASE)[check] is True
    log = fixture.gh_log_root / GH_LOG
    completed = log.read_bytes()
    log.write_bytes(completed + completed)
    assert filesystem_checks(fixture, "native-tools", GITHUB_METADATA_CASE)[check] is False


def test_mutation_control_proves_the_recorder_never_ran(tmp_path: Path) -> None:
    scenario = next(s for s in load_catalog() if s.id == GITHUB_METADATA_CONTROL)
    check = "github-metadata-control-not-executed"
    assert check in required_checks(scenario)
    fixture = create_fixture(tmp_path / "control", realistic=True, scenario_id=GITHUB_METADATA_CONTROL)
    assert filesystem_checks(fixture, "blocked-command", GITHUB_METADATA_CONTROL)[check] is True
    log = fixture.gh_log_root / GH_LOG
    log.write_text("release\x1fdelete-asset\x1fv1\x1fasset.zip\x1f--yes\x1f\n")
    assert filesystem_checks(fixture, "blocked-command", GITHUB_METADATA_CONTROL)[check] is False
