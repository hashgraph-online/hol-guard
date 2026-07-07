"""Tests for the install-integrity self-check."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.install_integrity import (
    _version_tuple,
    detect_shadowed_install,
    warn_if_shadowed,
)


def _make_fake_root(tmp_path: Path, version: str) -> Path:
    root = tmp_path / "codex_plugin_scanner"
    root.mkdir(parents=True)
    (root / "__init__.py").write_text('"""stub"""\n')
    (root / "version.py").write_text(f'__version__ = "{version}"\n')
    return root


class TestVersionTuple:
    def test_simple(self) -> None:
        assert _version_tuple("2.0.1000") == (2, 0, 1000)

    def test_with_suffix(self) -> None:
        assert _version_tuple("2.0.345") < _version_tuple("2.0.1000")

    def test_empty(self) -> None:
        assert _version_tuple("") == ()


class TestDetectShadowedInstall:
    def test_returns_none_with_single_install(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # The real package is the only reachable one — no warning.
        import codex_plugin_scanner as pkg

        loaded_root = Path(pkg.__file__).resolve().parent.parent
        monkeypatch.setattr(sys, "path", [str(loaded_root)])
        assert detect_shadowed_install() is None

    def test_warns_when_newer_install_is_shadowed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import codex_plugin_scanner as pkg

        loaded_root = Path(pkg.__file__).resolve().parent.parent
        newer_root = _make_fake_root(tmp_path / "newer", "99.0.0")
        # Put the loaded root FIRST (so it loads), and the newer root second.
        monkeypatch.setattr(sys, "path", [str(loaded_root), str(newer_root.parent)])
        warning = detect_shadowed_install()
        assert warning is not None
        assert "NEWER" in warning or "newer" in warning
        assert "99.0.0" in warning

    def test_notes_multiple_even_if_loaded_is_newest(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import codex_plugin_scanner as pkg

        loaded_root = Path(pkg.__file__).resolve().parent.parent
        older_root = _make_fake_root(tmp_path / "older", "0.0.1")
        monkeypatch.setattr(sys, "path", [str(loaded_root), str(older_root.parent)])
        warning = detect_shadowed_install()
        assert warning is not None
        assert "multiple" in warning.lower()

    def test_warn_if_shadowed_never_raises(
        self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Force a failure inside detect and ensure warn_if_shadowed swallows it.
        monkeypatch.setattr(
            "codex_plugin_scanner.install_integrity.detect_shadowed_install",
            lambda: (_ for _ in ()).throw(RuntimeError("boom")),
        )
        warn_if_shadowed()  # must not raise
        captured = capsys.readouterr()
        assert captured.err == ""
