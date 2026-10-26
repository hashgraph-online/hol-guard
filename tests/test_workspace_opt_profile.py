"""Workspace opt-level overrides apply per member and never to dependencies."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.release.workspace_opt_profile import main, render_profile, workspace_member_names

ROOT = Path(__file__).resolve().parents[1]


def _metadata(tmp_path: Path, members: list[str] | None = None, packages: list[dict] | None = None) -> Path:
    if packages is None:
        packages = [
            {"name": "hol-guard-runtime", "id": "path+file:///rust/hol-guard-runtime#3.0.0"},
            {"name": "guard-command", "id": "path+file:///rust/guard-command#3.0.0"},
            {"name": "third-party-dep", "id": "registry+https://index/third-party-dep#1.2.3"},
        ]
    if members is None:
        members = [package["id"] for package in packages[:2]]
    path = tmp_path / "metadata.json"
    path.write_text(
        json.dumps(
            {
                "packages": packages,
                "workspace_members": members,
            }
        ),
        encoding="utf-8",
    )
    return path


def test_writes_sorted_member_overrides_with_unquoted_numeric_level(tmp_path: Path) -> None:
    output = tmp_path / "profile.toml"
    assert main(["--opt-level", "0", "--output", str(output), "--metadata", str(_metadata(tmp_path))]) == 0
    assert output.read_text() == (
        '[profile.release.package."guard-command"]\nopt-level = 0\n\n'
        '[profile.release.package."hol-guard-runtime"]\nopt-level = 0\n\n'
    )


def test_non_member_packages_are_never_emitted(tmp_path: Path) -> None:
    names = workspace_member_names(json.loads(_metadata(tmp_path).read_text()))
    assert names == ["guard-command", "hol-guard-runtime"]
    assert "third-party-dep" not in render_profile(names, "0")


def test_string_levels_are_quoted(tmp_path: Path) -> None:
    output = tmp_path / "profile.toml"
    main(["--opt-level", "s", "--output", str(output), "--metadata", str(_metadata(tmp_path))])
    assert 'opt-level = "s"' in output.read_text()
    assert "opt-level = s\n" not in output.read_text()


def test_invalid_opt_level_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        main(["--opt-level", "4", "--output", str(tmp_path / "p.toml"), "--metadata", str(_metadata(tmp_path))])
    with pytest.raises(SystemExit):
        main(["--opt-level", "fast", "--output", str(tmp_path / "p.toml"), "--metadata", str(_metadata(tmp_path))])


def test_empty_workspace_members_are_rejected(tmp_path: Path) -> None:
    path = _metadata(tmp_path, members=[])
    with pytest.raises(ValueError, match="no workspace members"):
        workspace_member_names(json.loads(path.read_text()))


def test_invalid_member_names_are_rejected(tmp_path: Path) -> None:
    path = _metadata(
        tmp_path,
        members=['evil"]\nopt-level = 0'],
        packages=[{"name": 'evil"]\nopt-level = 0', "id": 'evil"]\nopt-level = 0'}],
    )
    with pytest.raises(ValueError, match="invalid workspace member name"):
        workspace_member_names(json.loads(path.read_text()))
