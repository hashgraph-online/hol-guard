"""Tests for repository version synchronization."""

import sys
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

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
    (tmp_path / "src" / "codex_plugin_scanner").mkdir(parents=True, exist_ok=True)
    (tmp_path / "pyproject.toml").write_text(
        "\n".join(
            [
                "[project]",
                'name = "hol-guard"',
                f'version = "{pyproject_version}"',
                "",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text(
        "\n".join(
            [
                "[[package]]",
                'name = "hol-guard"',
                f'version = "{pyproject_version}"',
                'source = { editable = "." }',
                "dependencies = [",
                '    { name = "cisco-ai-skill-scanner", marker = "python_full_version < \'3.14\'" },',
                "]",
                "",
                "[package.optional-dependencies]",
                "cisco = [",
                (
                    '    { name = "litellm", marker = '
                    "\"python_full_version >= '3.11' and python_full_version < '3.14'\" },"
                ),
                "]",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "src" / "codex_plugin_scanner" / "version.py").write_text(
        "\n".join(
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
    assert state.lockfile == "2.0.844"


def test_sync_repo_version_is_idempotent(tmp_path: Path) -> None:
    _write_repo_files(tmp_path, pyproject_version="2.0.844", module_version="2.0.844")

    changed = SYNC_REPO_VERSION.sync_repo_version(tmp_path, "2.0.844")

    assert changed is False
    assert SYNC_REPO_VERSION.read_repo_version_state(tmp_path) == SYNC_REPO_VERSION.RepoVersionState(
        pyproject="2.0.844",
        module="2.0.844",
        lockfile="2.0.844",
    )


def test_assert_repo_version_detects_mismatch(tmp_path: Path) -> None:
    _write_repo_files(tmp_path, pyproject_version="2.0.844", module_version="2.0.764")

    with pytest.raises(ValueError, match="Repository version mismatch"):
        SYNC_REPO_VERSION.assert_repo_version(tmp_path)


def test_sync_repo_version_accepts_prerelease_versions(tmp_path: Path) -> None:
    _write_repo_files(tmp_path, pyproject_version="2.0.844", module_version="2.0.844")

    SYNC_REPO_VERSION.sync_repo_version(tmp_path, "2.0.845rc1")

    state = SYNC_REPO_VERSION.read_repo_version_state(tmp_path)
    assert state.pyproject == "2.0.845rc1"
    assert state.module == "2.0.845rc1"


def test_sync_repo_version_accepts_epoch_and_local_versions(tmp_path: Path) -> None:
    _write_repo_files(tmp_path, pyproject_version="2.0.844", module_version="2.0.844")

    SYNC_REPO_VERSION.sync_repo_version(tmp_path, "1!2.0.845+abc")

    state = SYNC_REPO_VERSION.read_repo_version_state(tmp_path)
    assert state.pyproject == "1!2.0.845+abc"
    assert state.module == "1!2.0.845+abc"
    assert state.lockfile == "1!2.0.845+abc"


def test_sync_repo_version_rejects_invalid_version_tokens(tmp_path: Path) -> None:
    _write_repo_files(tmp_path, pyproject_version="2.0.844", module_version="2.0.844")

    with pytest.raises(ValueError, match="Unsupported version format"):
        SYNC_REPO_VERSION.sync_repo_version(tmp_path, "2.0.845 rc1")


def test_sync_repo_version_targets_project_version_only(tmp_path: Path) -> None:
    (tmp_path / "src" / "codex_plugin_scanner").mkdir(parents=True, exist_ok=True)
    (tmp_path / "pyproject.toml").write_text(
        "\n".join(
            [
                "[tool.demo]",
                'version = "0.1.0"',
                "",
                "[project]",
                'name = "hol-guard"',
                'version = "2.0.844"',
                "",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "src" / "codex_plugin_scanner" / "version.py").write_text(
        "\n".join(
            [
                '"""Single source of truth for tool version."""',
                "",
                '__version__ = "2.0.844"',
                "",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text(
        "\n".join(
            [
                "[[package]]",
                'name = "hol-guard"',
                'version = "2.0.844"',
                'source = { editable = "." }',
                "",
            ]
        ),
        encoding="utf-8",
    )

    SYNC_REPO_VERSION.sync_repo_version(tmp_path, "2.0.845")

    pyproject_text = (tmp_path / "pyproject.toml").read_text(encoding="utf-8")
    lockfile_text = (tmp_path / "uv.lock").read_text(encoding="utf-8")
    assert 'version = "0.1.0"' in pyproject_text
    assert pyproject_text.count('version = "2.0.845"') == 1
    assert lockfile_text.count('version = "2.0.845"') == 1


def test_sync_repo_version_preserves_lockfile_markers(tmp_path: Path) -> None:
    _write_repo_files(tmp_path, pyproject_version="2.0.844", module_version="2.0.844")

    SYNC_REPO_VERSION.sync_repo_version(tmp_path, "2.0.845")

    lockfile_text = (tmp_path / "uv.lock").read_text(encoding="utf-8")
    assert "marker = \"python_full_version < '3.14'\"" in lockfile_text
    assert "marker = \"python_full_version >= '3.11' and python_full_version < '3.14'\"" in lockfile_text


def test_sync_repo_version_preserves_inline_version_comments(tmp_path: Path) -> None:
    _write_repo_files(tmp_path, pyproject_version="2.0.844", module_version="2.0.844")
    (tmp_path / "pyproject.toml").write_text(
        "\n".join(
            [
                "[project]",
                'name = "hol-guard"',
                'version = "2.0.844"  # current release',
                "",
            ]
        ),
        encoding="utf-8",
    )

    SYNC_REPO_VERSION.sync_repo_version(tmp_path, "2.0.845")

    pyproject_text = (tmp_path / "pyproject.toml").read_text(encoding="utf-8")
    assert 'version = "2.0.845"  # current release' in pyproject_text


def test_sync_repo_version_handles_multiline_arrays_before_version(tmp_path: Path) -> None:
    _write_repo_files(tmp_path, pyproject_version="2.0.844", module_version="2.0.844")
    (tmp_path / "pyproject.toml").write_text(
        "\n".join(
            [
                "[project]",
                'name = "hol-guard"',
                "authors = [",
                '  { name = "HOL", email = "support@hol.org" },',
                "]",
                'version = "2.0.844"',
                "",
            ]
        ),
        encoding="utf-8",
    )

    SYNC_REPO_VERSION.sync_repo_version(tmp_path, "2.0.845")

    pyproject_text = (tmp_path / "pyproject.toml").read_text(encoding="utf-8")
    assert 'version = "2.0.845"' in pyproject_text


def test_sync_repo_version_avoids_partial_writes_when_lockfile_is_invalid(tmp_path: Path) -> None:
    _write_repo_files(tmp_path, pyproject_version="2.0.844", module_version="2.0.844")
    (tmp_path / "uv.lock").write_text(
        "\n".join(
            [
                "[[package]]",
                'name = "hol-guard"',
                'version = "2.0.844"',
                'source = { editable = "./elsewhere" }',
                "",
            ]
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Could not find editable hol-guard package version"):
        SYNC_REPO_VERSION.sync_repo_version(tmp_path, "2.0.845")

    assert 'version = "2.0.844"' in (tmp_path / "pyproject.toml").read_text(encoding="utf-8")
    assert '__version__ = "2.0.844"' in (tmp_path / "src" / "codex_plugin_scanner" / "version.py").read_text(
        encoding="utf-8"
    )
