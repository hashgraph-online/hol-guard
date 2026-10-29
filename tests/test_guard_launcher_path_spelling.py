from __future__ import annotations

import os
import shlex
from pathlib import Path

import pytest

from tests.native_command_test_support import _native_binaries, real_native_command_evaluation

pytestmark = pytest.mark.skipif(
    os.name == "nt", reason="the fixture spells the launcher as a symlink to the running runtime"
)


def _spelled(directory: Path, target: Path) -> str:
    """Spell a launcher the way an installed bundle does: a path, not a name."""
    directory.mkdir(parents=True)
    launcher = directory / "hol-guard"
    launcher.symlink_to(target)
    return shlex.quote(str(launcher))


def _reviewed(command: str, cwd: Path) -> str:
    return real_native_command_evaluation(command, cwd=cwd).payload["minimum_action"]


def test_a_path_spelled_launcher_reads_its_own_approval_without_a_second_row(tmp_path: Path) -> None:
    """The command Guard's own review hint tells a blocked agent to run.

    An agent on a Desktop install spells the launcher inside the bundle. Before
    this bound every such wait raised a second approval row for the row the
    agent was already waiting on.
    """
    _, runtime = _native_binaries()
    cwd = tmp_path / "project"
    cwd.mkdir()
    launcher = _spelled(tmp_path / "bundle", runtime)

    assert _reviewed(f"{launcher} approvals wait req-1 --json", cwd) == "allow"
    assert _reviewed(f"{launcher} status --json", cwd) == "allow"


def test_a_planted_launcher_beside_it_is_still_reviewed(tmp_path: Path) -> None:
    """Any account that can run commands can write an installed location, so
    the path a launcher is spelled with proves nothing about the program."""
    cwd = tmp_path / "project"
    cwd.mkdir()
    planted = _spelled(tmp_path / "planted", Path("/bin/echo"))

    assert _reviewed(f"{planted} approvals wait req-1 --json", cwd) != "allow"


def test_the_launchers_control_subcommands_keep_their_review(tmp_path: Path) -> None:
    _, runtime = _native_binaries()
    cwd = tmp_path / "project"
    cwd.mkdir()
    launcher = _spelled(tmp_path / "bundle", runtime)

    assert _reviewed(f"{launcher} approvals approve req-1", cwd) != "allow"
