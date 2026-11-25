"""The live cases added for earlier false-positive fixes run cleanly on the fixture.

Each case asks the agent to run its listed commands and report what they
printed. A command that exits non-zero reads to the oracle as a host tool
failure with no Guard deny, so a case whose command cannot succeed on the
fixture could never pass on any build.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.fixtures import create_fixture
from ci.gauntlet.nested_package_fixtures import NESTED_PACKAGE_CASES

SCENARIOS = {scenario.id: scenario for scenario in load_catalog()}
BACKFILLED_CASES = (
    "omp-native-git-stage-then-status-trailing-report",
    "omp-native-git-commit-message-credential-word",
    "omp-native-sed-counted-print-range-sibling-file",
    "omp-native-ls-missing-name-in-sibling-hidden-folder",
    "omp-native-missing-file-fallback-then-cd-subfolder-status",
    "omp-native-route-folder-bracket-name-reads",
    *NESTED_PACKAGE_CASES,
    "omp-native-git-worktree-prune-then-list",
    "omp-native-shell-label-then-stdin-size",
    "omp-native-find-files-newer-than-date",
    "omp-native-find-print0-xargs-grep",
    "omp-native-shell-brace-sequence-loops",
    "omp-native-cd-folder-grep-unmatched-glob",
    "omp-native-tool-version-banners",
    "omp-native-grep-recursive-screens-folder-with-capture",
    "omp-native-report-script-pass-names-output",
    "python-heredoc-accented-text-in-strings-and-comments",
    "omp-native-rg-system-header-tree",
    "omp-native-cat-hidden-project-script-in-sibling-checkout",
    "omp-native-grep-recursive-committed-design-dot-folder",
)


def _run(command: str, workspace: Path, home: Path) -> subprocess.CompletedProcess[str]:
    environment = {
        "HOME": str(home),
        "GIT_CONFIG_NOSYSTEM": "1",
        "PATH": os.environ.get("PATH", ""),
    }
    return subprocess.run(
        ["bash", "-c", command], cwd=workspace, env=environment, capture_output=True, text=True, timeout=60
    )


@pytest.mark.skipif(
    os.name == "nt" or shutil.which("rg") is None or shutil.which("bash") is None,
    reason="needs bash and ripgrep",
)
@pytest.mark.parametrize("scenario_id", BACKFILLED_CASES)
def test_every_listed_command_exits_cleanly(tmp_path: Path, scenario_id: str) -> None:
    # A space in the fixture path checks the quoting the live runner applies.
    fixture = create_fixture(tmp_path / "fixture root", realistic=True, scenario_id=scenario_id)
    scenario = SCENARIOS[scenario_id].render(
        {"home": str(fixture.home), "workspace": str(fixture.workspace), "root": str(fixture.root)}
    )
    for command in scenario.commands:
        completed = _run(command, fixture.workspace, fixture.home)
        assert completed.returncode == 0, (command, completed.stderr)


def test_the_package_layout_is_only_added_for_its_own_cases(tmp_path: Path) -> None:
    fixture = create_fixture(tmp_path / "fixture", realistic=True, scenario_id="omp-native-todo-plan")
    assert not (fixture.workspace / "packages" / "app").exists()
    assert not (fixture.workspace / "tsconfig.base.json").exists()


@pytest.mark.skipif(os.name == "nt" or shutil.which("bash") is None, reason="needs bash")
def test_the_stage_case_leaves_its_edit_in_the_index(tmp_path: Path) -> None:
    scenario_id = "omp-native-git-stage-then-status-trailing-report"
    fixture = create_fixture(tmp_path / "fixture root", realistic=True, scenario_id=scenario_id)
    before = _run("git status --short", fixture.workspace, fixture.home)
    assert " M src/one.ts" in before.stdout.splitlines()
    scenario = SCENARIOS[scenario_id].render(
        {"home": str(fixture.home), "workspace": str(fixture.workspace), "root": str(fixture.root)}
    )
    (command,) = scenario.commands
    completed = _run(command, fixture.workspace, fixture.home)
    assert completed.returncode == 0, completed.stderr
    lines = completed.stdout.splitlines()
    assert "M  src/one.ts" in lines
    assert lines[-1] == "check exit: 0"


def _gate_case(case_id: str) -> dict:
    gate = Path(__file__).parent / "fixtures" / "benign_false_positive_gate.json"
    (case,) = [case for case in json.loads(gate.read_text(encoding="utf-8"))["cases"] if case["id"] == case_id]
    return case


@pytest.mark.skipif(os.name == "nt" or shutil.which("bash") is None, reason="needs bash")
def test_the_report_case_prints_what_its_gate_case_scans(tmp_path: Path) -> None:
    scenario_id = "omp-native-report-script-pass-names-output"
    fixture = create_fixture(tmp_path / "fixture root", realistic=True, scenario_id=scenario_id)
    completed = _run("python3 tools/report.py", fixture.workspace, fixture.home)
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == _gate_case("post-tool-report-test-result-pass-names")["tool_response"]["stdout"]


def test_the_screens_case_commits_a_full_size_capture(tmp_path: Path) -> None:
    scenario_id = "omp-native-grep-recursive-screens-folder-with-capture"
    fixture = create_fixture(tmp_path / "fixture root", realistic=True, scenario_id=scenario_id)
    capture = fixture.workspace / "docs/screens/auth-desktop-policy-review.png"
    assert capture.stat().st_size > 3 * 1024 * 1024
    tracked = _run("git ls-files docs/screens", fixture.workspace, fixture.home).stdout.split()
    assert sorted(tracked) == [
        "docs/screens/README.md",
        "docs/screens/auth-desktop-login.png",
        "docs/screens/auth-desktop-policy-review.png",
    ]


def test_the_backfill_shapes_stay_out_of_other_cases(tmp_path: Path) -> None:
    fixture = create_fixture(tmp_path / "fixture", realistic=True, scenario_id="omp-native-todo-plan")
    assert not (fixture.workspace / "docs/screens").exists()
    assert not (fixture.workspace / "tools/report.py").exists()
    assert not (fixture.workspace / "design").exists()
    assert not (fixture.home / "Code" / "acme-platform").exists()


def test_the_hidden_script_case_reads_a_committed_dotfile(tmp_path: Path) -> None:
    scenario_id = "omp-native-cat-hidden-project-script-in-sibling-checkout"
    fixture = create_fixture(tmp_path / "fixture root", realistic=True, scenario_id=scenario_id)
    checkout = fixture.home / "Code" / "acme-platform"
    tracked = _run("git ls-files", checkout, fixture.home).stdout.split()
    assert sorted(tracked) == [".repair-stage.py", "README.md"]


def test_the_design_folder_case_commits_the_tool_dot_folder(tmp_path: Path) -> None:
    scenario_id = "omp-native-grep-recursive-committed-design-dot-folder"
    fixture = create_fixture(tmp_path / "fixture root", realistic=True, scenario_id=scenario_id)
    tracked = _run("git ls-files design", fixture.workspace, fixture.home).stdout.split()
    assert sorted(tracked) == ["design/.designtool/design.json", "design/README.md"]
    found = _run("grep -rn palette design", fixture.workspace, fixture.home).stdout
    assert "design/.designtool/design.json" in found
