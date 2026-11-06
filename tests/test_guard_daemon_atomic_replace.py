from __future__ import annotations

import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import atomic_replace


def _held_open(winerror: int, failures: int):
    calls = {"count": 0}
    real_replace = os.replace

    def replace(source: Path, destination: Path) -> None:
        calls["count"] += 1
        if calls["count"] <= failures:
            error = PermissionError(13, "Access is denied")
            error.winerror = winerror
            raise error
        real_replace(source, destination)

    return replace, calls


def test_a_reader_holding_the_state_file_delays_the_replace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source, destination = tmp_path / "next.json", tmp_path / "state.json"
    source.write_text("new", encoding="utf-8")
    destination.write_text("old", encoding="utf-8")
    replace, calls = _held_open(winerror=5, failures=3)
    monkeypatch.setattr(atomic_replace, "_IS_WINDOWS", True)
    monkeypatch.setattr(atomic_replace, "_REPLACE_RETRY_SECONDS", 0)
    monkeypatch.setattr(atomic_replace.os, "replace", replace)

    atomic_replace.replace_file(source, destination)

    assert calls["count"] == 4
    assert destination.read_text(encoding="utf-8") == "new"


def test_a_lasting_or_unrelated_permission_error_is_raised(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source, destination = tmp_path / "next.json", tmp_path / "state.json"
    source.write_text("new", encoding="utf-8")
    monkeypatch.setattr(atomic_replace, "_REPLACE_RETRY_SECONDS", 0)

    monkeypatch.setattr(atomic_replace, "_IS_WINDOWS", True)
    replace, calls = _held_open(winerror=32, failures=100)
    monkeypatch.setattr(atomic_replace.os, "replace", replace)
    with pytest.raises(PermissionError):
        atomic_replace.replace_file(source, destination)
    assert calls["count"] == atomic_replace._REPLACE_ATTEMPTS

    replace, calls = _held_open(winerror=1314, failures=100)
    monkeypatch.setattr(atomic_replace.os, "replace", replace)
    with pytest.raises(PermissionError):
        atomic_replace.replace_file(source, destination)
    assert calls["count"] == 1

    monkeypatch.setattr(atomic_replace, "_IS_WINDOWS", False)
    replace, calls = _held_open(winerror=5, failures=100)
    monkeypatch.setattr(atomic_replace.os, "replace", replace)
    with pytest.raises(PermissionError):
        atomic_replace.replace_file(source, destination)
    assert calls["count"] == 1
