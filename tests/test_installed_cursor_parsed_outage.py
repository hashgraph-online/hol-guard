"""Parsed Cursor evidence rejects absent, partial, or checkout-based proof."""

from __future__ import annotations

import sys
from pathlib import Path
from types import ModuleType

import pytest

from scripts import run_installed_cursor_parsed_outage as runner


def _arguments(monkeypatch: pytest.MonkeyPatch, root: Path, output: Path) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "parsed-cursor-qualification",
            "--subject",
            str(root / "subject.json"),
            "--version",
            "3.12.0.dev1",
            "--source-sha",
            "a" * 40,
            "--repo-root",
            str(root),
            "--output",
            str(output),
        ],
    )


def test_missing_subject_stops_before_tests(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    output = tmp_path / "evidence.json"
    _arguments(monkeypatch, tmp_path, output)

    def unexpected(*_args, **_kwargs):
        pytest.fail("Missing proof must stop before qualification")

    monkeypatch.setattr(runner.pytest, "main", unexpected)
    assert runner.main() == 1
    assert not output.exists()


@pytest.mark.parametrize("invalid", ["skip", "groups", "checkout", "changed-install"])
def test_invalid_qualification_cannot_write_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, invalid: str
) -> None:
    output = tmp_path / "evidence.json"
    _arguments(monkeypatch, tmp_path, output)
    monkeypatch.setattr(runner, "load_subject", lambda *_args, **_kwargs: {})
    identities = iter([{"outside_checkout": True}, {"outside_checkout": invalid != "changed-install"}])
    monkeypatch.setattr(runner, "verify_install", lambda *_args: next(identities))

    def injected_run(_arguments, *, plugins):
        results = plugins[0]
        results.passed = 336 if invalid == "skip" else 337
        results.skipped = int(invalid == "skip")
        results.groups = {"unavailable": 120, "decisions": 200, "observations": 12, "imports_unavailable": 5}
        if invalid == "groups":
            results.groups = {"unavailable": 337, "decisions": 0, "observations": 0, "imports_unavailable": 0}
        if invalid == "checkout":
            module = ModuleType("codex_plugin_scanner.fixture_source_injection")
            module.__file__ = str(tmp_path / "src" / "fixture.py")
            monkeypatch.setitem(sys.modules, module.__name__, module)
        return 0

    monkeypatch.setattr(runner.pytest, "main", injected_run)
    assert runner.main() == 1
    assert not output.exists()
