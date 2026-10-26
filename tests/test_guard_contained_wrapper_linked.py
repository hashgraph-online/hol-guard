from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.contained_wrapper import OutputFilter, peel_contained_wrapper


def linked_home(tmp_path: Path) -> tuple[Path, Path, Path]:
    """A home holding a checkout and a linked worktree beside it."""
    home = tmp_path / "home"
    workspace = home / "project"
    worktree = home / "project-report"
    (workspace / "web").mkdir(parents=True)
    (worktree / "scripts").mkdir(parents=True)
    (worktree / ".git").write_text("gitdir: /nonexistent\n")
    (home / "loose").mkdir()
    return home, workspace, worktree


@pytest.fixture(autouse=True)
def _peel_from_the_resident(native_contained_wrapper_runtime: Path) -> None:
    """Every peel here is the classifier's answer, asked of the session resident."""


def test_relative_cd_into_a_sibling_root_peels_an_and_list(tmp_path: Path) -> None:
    home, workspace, worktree = linked_home(tmp_path)
    command = "cd ../project-report && node scripts/report.mjs && cat 'report out.md'"
    assert peel_contained_wrapper(command, workspace=workspace, home=home, cwd=workspace) == (
        "node scripts/report.mjs && cat 'report out.md'",
        worktree.resolve(),
        None,
    )
    # A final status echo reports the list's status; no filter is peeled.
    echoed = f'cd {worktree} && npm test && git status; echo "exit=$?"'
    assert peel_contained_wrapper(echoed, workspace=workspace, home=home, cwd=workspace) == (
        "npm test && git status",
        worktree.resolve(),
        OutputFilter("all", 0, False, status_label="exit="),
    )
    # A single command after the cd keeps the bounded filter.
    assert peel_contained_wrapper(
        "cd ../project-report && npm test 2>&1 | tail -5", workspace=workspace, home=home, cwd=workspace
    ) == ("npm test", worktree.resolve(), OutputFilter("tail", 5, merge_stderr=True))


def test_a_sequence_after_cd_into_a_sibling_root_peels_like_an_and_list(tmp_path: Path) -> None:
    home, workspace, worktree = linked_home(tmp_path)
    assert peel_contained_wrapper(
        f"cd {worktree}; node scripts/report.mjs", workspace=workspace, home=home, cwd=workspace
    ) == ("node scripts/report.mjs", worktree.resolve(), None)
    assert peel_contained_wrapper(
        "cd ../project-report ; npm test && git status", workspace=workspace, home=home, cwd=workspace
    ) == ("npm test && git status", worktree.resolve(), None)
    # The cd target is resolved before anything runs, so a missing root is never
    # peeled: the sink runs the text whole in the sandbox instead of the core in
    # the session directory the shell would fall back to.
    with pytest.raises((ValueError, OSError)):
        peel_contained_wrapper(f"cd {home / 'gone'}; npm test", workspace=workspace, home=home, cwd=workspace)


@pytest.mark.parametrize(
    "command",
    [
        # Relative targets inside the workspace, below a sibling root, or outside any repository.
        "cd web && pytest -q",
        "cd ./web && pytest -q",
        "cd ../project-report/scripts && node report.mjs",
        "cd ../loose && pytest -q",
        "cd .. && pytest -q",
        # Lists other than plain `&&` words, or with a filter that binds to the last command alone.
        "cd ../project-report && npm test && npm run build | tail -5",
        "cd ../project-report && npm test && npm run build 2>&1",
        "cd ../project-report && npm test || rm -rf /",
        "cd ../project-report && npm test && rm -rf / &",
        "cd ../project-report && npm test && && ls",
        "cd ../project-report && npm test && echo $HOME",
        "cd ../project-report && npm test; ls",
        # `;` after the cd only for a sibling root, and nowhere later in the list.
        "cd ../project-report; npm test; ls",
        "cd ../project-report;; npm test",
        "cd web; pytest -q",
        "cd ../loose; pytest -q",
    ],
)
def test_other_relative_or_list_shapes_stay_rejected(tmp_path: Path, command: str) -> None:
    home, workspace, _worktree = linked_home(tmp_path)
    with pytest.raises((ValueError, OSError)):
        peel_contained_wrapper(command, workspace=workspace, home=home, cwd=workspace)


def test_a_list_inside_the_workspace_or_without_home_stays_rejected(tmp_path: Path) -> None:
    home, workspace, worktree = linked_home(tmp_path)
    with pytest.raises(ValueError):
        peel_contained_wrapper(f"cd {workspace / 'web'} && npm test && npm run build", workspace=workspace, home=home)
    for command in ("cd ../project-report && npm test", f"cd {worktree} && npm test && npm run build"):
        with pytest.raises(ValueError):
            peel_contained_wrapper(command, workspace=workspace, cwd=workspace)
