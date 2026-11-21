"""Installed outage evidence must reject missing, partial, or source-based proof."""

from __future__ import annotations

import sys
from pathlib import Path
from types import ModuleType

import pytest

from scripts import run_installed_codex_outage as runner


def _arguments(monkeypatch: pytest.MonkeyPatch, root: Path, output: Path) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "installed-codex-outage",
            "--subject",
            str(root / "subject.json"),
            "--version",
            "3.10.0.dev1",
            "--source-sha",
            "a" * 40,
            "--repo-root",
            str(root),
            "--output",
            str(output),
        ],
    )


def test_missing_subject_cannot_run_outage_tests_or_write_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "evidence.json"
    _arguments(monkeypatch, tmp_path, output)

    def unexpected(*_args, **_kwargs):
        pytest.fail("Missing immutable proof must stop before any outage tests run")

    monkeypatch.setattr(runner.pytest, "main", unexpected)
    assert runner.main() == 1
    assert not output.exists()


def test_skipped_outage_cases_cannot_be_recorded_as_passed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "evidence.json"
    _arguments(monkeypatch, tmp_path, output)
    monkeypatch.setattr(runner, "load_subject", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(runner, "verify_install", lambda *_args: {"outside_checkout": True})

    def partial_run(_arguments, *, plugins):
        plugins[0].passed = 6
        plugins[0].skipped = 2
        return 0

    monkeypatch.setattr(runner.pytest, "main", partial_run)
    assert runner.main() == 1
    assert not output.exists()
    assert "all eight cases" in capsys.readouterr().err


def test_checkout_import_after_initial_verification_invalidates_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "evidence.json"
    _arguments(monkeypatch, tmp_path, output)
    monkeypatch.setattr(runner, "load_subject", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(runner, "verify_install", lambda *_args: {"outside_checkout": True})

    def injected_run(_arguments, *, plugins):
        plugins[0].passed = 8
        module = ModuleType("codex_plugin_scanner.fixture_source_injection")
        module.__file__ = str(tmp_path / "src" / "fixture.py")
        monkeypatch.setitem(sys.modules, module.__name__, module)
        return 0

    monkeypatch.setattr(runner.pytest, "main", injected_run)
    assert runner.main() == 1
    assert not output.exists()
    assert "imported checkout code" in capsys.readouterr().err
