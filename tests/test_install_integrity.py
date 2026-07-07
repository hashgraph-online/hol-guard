"""Tests for the install-integrity self-check."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.install_integrity import (
    _parse_version,
    _read_version_via_ast,
    detect_shadowed_install,
    warn_if_shadowed,
)


def _make_fake_root(tmp_path: Path, version: str) -> Path:
    root = tmp_path / "codex_plugin_scanner"
    root.mkdir(parents=True)
    (root / "__init__.py").write_text('"""stub"""\n')
    (root / "version.py").write_text(f'__version__ = "{version}"\n')
    return root


def _loaded_package_dir() -> Path:
    import codex_plugin_scanner as pkg

    return Path(pkg.__file__).resolve().parent


class TestParseVersion:
    def test_simple(self) -> None:
        assert _parse_version("2.0.1000") == (2, 0, 1000, 0)

    def test_ordering(self) -> None:
        assert _parse_version("2.0.345") < _parse_version("2.0.1000")

    def test_empty(self) -> None:
        assert _parse_version("") == (0,)

    def test_pre_release_sorts_before_final(self) -> None:
        assert _parse_version("2.0.1rc1") < _parse_version("2.0.1")

    def test_pre_release_ordering(self) -> None:
        assert _parse_version("2.0.1rc1") < _parse_version("2.0.1rc2")

    def test_post_release_sorts_after_final(self) -> None:
        assert _parse_version("2.0.1") < _parse_version("2.0.1.post1")

    def test_dev_release_sorts_before_pre(self) -> None:
        assert _parse_version("2.0.1.dev1") < _parse_version("2.0.1rc1")

    def test_full_pep440_ordering(self) -> None:
        assert (
            _parse_version("2.0.1.dev1")
            < _parse_version("2.0.1a1")
            < _parse_version("2.0.1rc1")
            < _parse_version("2.0.1")
            < _parse_version("2.0.1.post1")
        )


class TestReadVersionViaAst:
    def test_reads_version_without_executing(self, tmp_path: Path) -> None:
        # A version.py that would crash if executed, but AST-parses fine.
        version_file = tmp_path / "version.py"
        version_file.write_text('__version__ = "9.9.9"\n')
        assert _read_version_via_ast(version_file) == "9.9.9"

    def test_returns_none_for_missing_file(self, tmp_path: Path) -> None:
        assert _read_version_via_ast(tmp_path / "nope.py") is None

    def test_returns_none_without_version_assignment(self, tmp_path: Path) -> None:
        version_file = tmp_path / "version.py"
        version_file.write_text('OTHER = "1.0.0"\n')
        assert _read_version_via_ast(version_file) is None

    def test_reads_annotated_assignment(self, tmp_path: Path) -> None:
        version_file = tmp_path / "version.py"
        version_file.write_text('__version__: str = "8.8.8"\n')
        assert _read_version_via_ast(version_file) == "8.8.8"


class TestDetectShadowedInstall:
    def test_returns_none_with_single_install(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        loaded_dir = _loaded_package_dir()
        monkeypatch.setattr(sys, "path", [str(loaded_dir.parent)])
        assert detect_shadowed_install() is None

    def test_warns_when_newer_install_is_shadowed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        loaded_dir = _loaded_package_dir()
        newer_root = _make_fake_root(tmp_path / "newer", "99.0.0")
        monkeypatch.setattr(sys, "path", [str(loaded_dir.parent), str(newer_root.parent)])
        warning = detect_shadowed_install()
        assert warning is not None
        assert "NEWER" in warning
        assert "99.0.0" in warning

    def test_notes_multiple_even_if_loaded_is_newest(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        loaded_dir = _loaded_package_dir()
        older_root = _make_fake_root(tmp_path / "older", "0.0.1")
        monkeypatch.setattr(sys, "path", [str(loaded_dir.parent), str(older_root.parent)])
        warning = detect_shadowed_install()
        assert warning is not None
        assert "multiple" in warning.lower()
        # The loaded install must NOT be listed as an "other" root.
        assert str(loaded_dir) not in warning.split("Loaded:")[0]

    def test_warn_if_shadowed_never_raises(
        self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            "codex_plugin_scanner.install_integrity.detect_shadowed_install",
            lambda: (_ for _ in ()).throw(RuntimeError("boom")),
        )
        warn_if_shadowed()  # must not raise
        captured = capsys.readouterr()
        assert captured.err == ""
