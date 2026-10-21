"""Installed native-worker qualification rejects incomplete and substituted proof."""

from __future__ import annotations

import sys
from pathlib import Path
from types import ModuleType

import pytest

from scripts import run_installed_native_outage as runner


def _arguments(monkeypatch: pytest.MonkeyPatch, root: Path, output: Path) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "installed-native-outage",
            "--subject",
            str(root / "subject.json"),
            "--version",
            "3.11.0.dev1",
            "--source-sha",
            "a" * 40,
            "--repo-root",
            str(root),
            "--output",
            str(output),
        ],
    )


def test_missing_subject_stops_before_outage_tests(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    output = tmp_path / "evidence.json"
    _arguments(monkeypatch, tmp_path, output)

    def unexpected(*_args, **_kwargs):
        pytest.fail("Missing immutable proof must stop before outage tests")

    monkeypatch.setattr(runner.pytest, "main", unexpected)
    assert runner.main() == 1
    assert not output.exists()


def test_skipped_cases_cannot_produce_complete_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "evidence.json"
    _arguments(monkeypatch, tmp_path, output)
    monkeypatch.setattr(runner, "load_subject", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(runner, "verify_install", lambda *_args: {"outside_checkout": True})

    def partial_run(_arguments, *, plugins):
        plugins[0].collected = 37
        plugins[0].passed = 36
        plugins[0].skipped = 1
        return 0

    monkeypatch.setattr(runner.pytest, "main", partial_run)
    assert runner.main() == 1
    assert not output.exists()
    assert "every collected case" in capsys.readouterr().err


def test_checkout_import_invalidates_installed_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "evidence.json"
    _arguments(monkeypatch, tmp_path, output)
    monkeypatch.setattr(runner, "load_subject", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(runner, "verify_install", lambda *_args: {"outside_checkout": True})

    def injected_run(_arguments, *, plugins):
        plugins[0].collected = 45
        plugins[0].passed = 45
        module = ModuleType("codex_plugin_scanner.fixture_source_injection")
        module.__file__ = str(tmp_path / "src" / "fixture.py")
        monkeypatch.setitem(sys.modules, module.__name__, module)
        return 0

    monkeypatch.setattr(runner.pytest, "main", injected_run)
    assert runner.main() == 1
    assert not output.exists()
    assert "imported checkout code" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("collected", "passed", "status", "accepted"),
    [
        (0, 0, 0, False),
        (46, 45, 0, False),
        (46, 46, 1, False),
        (45, 45, 0, True),
        (46, 46, 0, True),
    ],
)
def test_complete_evidence_tracks_collected_cases(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    collected: int,
    passed: int,
    status: int,
    accepted: bool,
) -> None:
    output = tmp_path / "evidence.json"
    _arguments(monkeypatch, tmp_path, output)
    monkeypatch.setattr(runner, "load_subject", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(runner, "verify_install", lambda *_args: {"outside_checkout": True})

    def run(_arguments, *, plugins):
        plugins[0].collected = collected
        plugins[0].passed = passed
        return status

    monkeypatch.setattr(runner.pytest, "main", run)
    assert runner.main() == (0 if accepted else 1)
    assert output.exists() is accepted
