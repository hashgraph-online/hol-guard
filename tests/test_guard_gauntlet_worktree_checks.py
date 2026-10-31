"""Filesystem proofs for the linked-worktree and tracked catalog edit cases."""

from __future__ import annotations

import json
from pathlib import Path

from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.extension_catalog_fixtures import CATALOG_CASE, CATALOG_CHECK, CATALOG_PATH, CATALOG_SOURCE
from ci.gauntlet.proofs import required_checks
from ci.gauntlet.review_fixtures import WORKTREE_CASE, WORKTREE_DELIMITER_CASE, WORKTREE_NAME, worktree_checks

BEFORE = "retryLimit: 3\n"
AFTER = "retryLimit: 5\n"
CATALOG = {scenario.id: scenario for scenario in load_catalog()}


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _worktrees(tmp_path: Path) -> tuple[Path, Path]:
    home, workspace = tmp_path / "home", tmp_path / "workspace"
    _write(home / WORKTREE_NAME / "src/settings.ts", AFTER)
    _write(workspace / "src/settings.ts", BEFORE)
    return home, workspace


def test_delimiter_case_passes_without_a_note(tmp_path: Path) -> None:
    home, workspace = _worktrees(tmp_path)
    checks = worktree_checks(home, workspace, WORKTREE_DELIMITER_CASE, BEFORE, AFTER)

    assert checks.keys() == required_checks(CATALOG[WORKTREE_DELIMITER_CASE]) & checks.keys()
    assert "linked-worktree-note-exact" not in checks
    assert all(checks.values())


def test_main_worktree_case_still_requires_the_note(tmp_path: Path) -> None:
    home, workspace = _worktrees(tmp_path)

    assert worktree_checks(home, workspace, WORKTREE_CASE, BEFORE, AFTER)["linked-worktree-note-exact"] is False
    _write(home / WORKTREE_NAME / "docs/change.md", "Retry limit increased from 3 to 5.\n")
    assert all(worktree_checks(home, workspace, WORKTREE_CASE, BEFORE, AFTER).values())


def test_catalog_case_requires_the_edited_version(tmp_path: Path) -> None:
    assert CATALOG_CHECK in required_checks(CATALOG[CATALOG_CASE])
    target = tmp_path / CATALOG_PATH

    def check() -> bool:
        return worktree_checks(tmp_path / "home", tmp_path, CATALOG_CASE, BEFORE, AFTER) == {CATALOG_CHECK: True}

    assert not check()
    _write(target, CATALOG_SOURCE)
    assert not check()
    edited = {**json.loads(CATALOG_SOURCE), "version": "1.1.0"}
    _write(target, json.dumps({**edited, "title": "Changed"}))
    assert not check()
    _write(target, CATALOG_SOURCE.replace('"1.0.0"', '"1.1.0"'))
    assert check()
