"""Tests for repository version synchronization."""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "sync_repo_version.py"
SCRIPT_SPEC = spec_from_file_location("sync_repo_version", SCRIPT_PATH)
assert SCRIPT_SPEC is not None
assert SCRIPT_SPEC.loader is not None
SYNC_REPO_VERSION = module_from_spec(SCRIPT_SPEC)
sys.modules[SCRIPT_SPEC.name] = SYNC_REPO_VERSION
SCRIPT_SPEC.loader.exec_module(SYNC_REPO_VERSION)


def _write_repo_files(tmp_path: Path, *, pyproject_version: str, module_version: str) -> None:
    (tmp_path / "src" / "codex_plugin_scanner").mkdir(parents=True)
    (tmp_path / "pyproject.toml").write_text(
        '\n'.join(
            [
                "[project]",
                'name = "hol-guard"',
                f'version = "{pyproject_version}"',
                "",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "src" / "codex_plugin_scanner" / "version.py").write_text(
        '\n'.join(
            [
                '"""Single source of truth for tool version."""',
                "",
                f'__version__ = "{module_version}"',
                "",
            ]
        ),
        encoding="utf-8",
    )


def test_sync_repo_version_updates_both_files(tmp_path: Path) -> None:
    _write_repo_files(tmp_path, pyproject_version="2.0.764", module_version="2.0.764")

    changed = SYNC_REPO_VERSION.sync_repo_version(tmp_path, "2.0.844")

    assert changed is True
    state = SYNC_REPO_VERSION.read_repo_version_state(tmp_path)
    assert state.pyproject == "2.0.844"
    assert state.module == "2.0.844"


def test_assert_repo_version_detects_mismatch(tmp_path: Path) -> None:
    _write_repo_files(tmp_path, pyproject_version="2.0.844", module_version="2.0.764")

    with pytest.raises(ValueError, match="Repository version mismatch"):
        SYNC_REPO_VERSION.assert_repo_version(tmp_path)


def test_sync_repo_version_rejects_non_semver(tmp_path: Path) -> None:
    _write_repo_files(tmp_path, pyproject_version="2.0.844", module_version="2.0.844")

    with pytest.raises(ValueError, match="Unsupported version format"):
        SYNC_REPO_VERSION.sync_repo_version(tmp_path, "2.0.845rc1")
