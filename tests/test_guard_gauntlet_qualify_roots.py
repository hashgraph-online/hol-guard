"""Private qualification roots, driver-owned mode tightening and numbered work dirs. No live inference."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ci.gauntlet import fixtures, qualify, qualify_setup
from tests.test_guard_gauntlet_qualify import _args, _fake_setup, _summary


def test_private_dir_requires_an_owned_mode_700_directory(tmp_path: Path) -> None:
    path = tmp_path / "private"
    assert qualify_setup.private_dir(path) == path
    assert (path.stat().st_mode & 0o777) == 0o700
    link = tmp_path / "link"
    link.symlink_to(path, target_is_directory=True)
    with pytest.raises(RuntimeError, match="real directory"):
        qualify_setup.private_dir(link)
    not_dir = tmp_path / "file"
    not_dir.write_text("x")
    with pytest.raises(RuntimeError, match="real directory"):
        qualify_setup.private_dir(not_dir)


def test_private_dir_rejects_a_shared_directory_it_does_not_own(tmp_path: Path) -> None:
    shared = tmp_path / "shared"
    shared.mkdir(mode=0o770)
    before = shared.stat().st_mode & 0o777
    assert before & 0o077
    with pytest.raises(RuntimeError, match="not private"):
        qualify_setup.private_dir(shared)
    # The directory is never modified, only verified.
    assert (shared.stat().st_mode & 0o777) == before


def test_private_dir_tightens_only_inside_the_driver_roots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    shared = tmp_path / "shared"
    shared.mkdir(mode=0o770)
    assert shared.stat().st_mode & 0o077
    with pytest.raises(RuntimeError, match="not private"):
        qualify_setup.private_dir(shared, tighten=False)
    # Explicit tighten (granted by the caller for driver-owned roots) fixes the mode.
    assert qualify_setup.private_dir(shared, tighten=True) == shared
    assert (shared.stat().st_mode & 0o777) == 0o700
    # driver_owned marks paths inside the monkeypatched default roots.
    monkeypatch.setattr(qualify_setup, "default_tmp_root", lambda: tmp_path / "tmp-root")
    assert qualify_setup.driver_owned(tmp_path / "tmp-root" / "w" / "1")
    assert not qualify_setup.driver_owned(tmp_path / "elsewhere")
    nested = tmp_path / "tmp-root" / "nested"
    monkeypatch.setattr(qualify_setup, "DEFAULT_CACHE_ROOT", tmp_path / "cache-root")
    assert qualify_setup.driver_owned(nested)
    nested.mkdir(mode=0o755, parents=True)
    tighten = qualify_setup.driver_owned(nested)
    assert qualify_setup.private_dir(nested, tighten=tighten) == nested
    assert (nested.stat().st_mode & 0o777) == 0o700


def test_mkdir_private_creates_every_missing_component_mode_700(tmp_path: Path) -> None:
    deep = tmp_path / "a" / "b" / "c"
    fixtures.mkdir_private(deep)
    for level in (tmp_path / "a", tmp_path / "a" / "b", deep):
        assert (level.stat().st_mode & 0o777) == 0o700


def test_work_roots_continue_past_999(tmp_path: Path) -> None:
    (tmp_path / "w").mkdir(mode=0o700)
    for name in ("997", "999", "note"):
        (tmp_path / "w" / name).mkdir(mode=0o700)
    assert qualify.attempt_work_root(tmp_path / "w").name == "1000"
    assert qualify.attempt_work_root(tmp_path / "w").name == "1001"


def test_driver_resolves_relative_roots_before_setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    _fake_setup(monkeypatch, tmp_path, [_summary([{"id": "a", "outcome": "pass"}], True)])
    args = _args(
        tmp_path,
        run_root=Path("rel-run"),
        cache_root=Path("rel-cache"),
        work_parent=Path("rel-w"),
        sdk_root=Path("sdk"),
    )
    assert qualify.main(args) == 0
    assert args.run_root.is_absolute() and args.work_parent.is_absolute()
    result = json.loads((tmp_path / "rel-run" / "qualification.json").read_text())
    assert result["run_root"] == str((tmp_path / "rel-run").resolve())
    assert result["sdk"]["root"] == str((tmp_path / "sdk").resolve())
    assert result["attempts"][0]["work_root"] == str((tmp_path / "rel-w" / "1").resolve())
