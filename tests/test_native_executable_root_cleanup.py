"""A compiler directory Windows still holds at exit is removed, not leaked."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.extension_builder import native_executable_root as root_module

_SCRIPT = b"#!/bin/sh\necho verified\n"


@pytest.fixture(autouse=True)
def _system_temp_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(root_module, "_private_roots", [])


def _hold_the_image(monkeypatch: pytest.MonkeyPatch, attempts: int) -> list[float]:
    """Fail the next removals the way Windows does while an exited executable's image is still mapped."""
    real_rmtree = shutil.rmtree
    held = {"left": attempts}
    sleeps: list[float] = []

    def rmtree(path, *args, **kwargs):  # type: ignore[no-untyped-def]
        if held["left"] > 0:
            held["left"] -= 1
            if "onexc" in kwargs or "onerror" in kwargs:
                return None  # TemporaryDirectory(ignore_cleanup_errors=True) swallows it
            raise PermissionError(13, "The process cannot access the file", str(path))
        return real_rmtree(path, *args, **kwargs)

    monkeypatch.setattr(shutil, "rmtree", rmtree)
    monkeypatch.setattr(root_module.time, "sleep", sleeps.append)
    return sleeps


def test_a_directory_held_briefly_after_the_compiler_exits_is_still_removed(monkeypatch: pytest.MonkeyPatch) -> None:
    sleeps = _hold_the_image(monkeypatch, attempts=3)
    with root_module.verified_executable(_SCRIPT) as path:
        assert path.exists()
    root_module.release_copies()
    assert not path.parent.exists()
    assert sleeps == [0.05, 0.1]


def test_a_directory_that_stays_held_is_given_up_after_a_bounded_wait_and_reported(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    real_rmtree = shutil.rmtree
    sleeps = _hold_the_image(monkeypatch, attempts=100)
    with root_module.verified_executable(_SCRIPT) as path:
        pass
    root_module.release_copies()
    leaked = Path(path.parent)
    assert leaked.exists()
    assert sleeps == list(root_module._REMOVAL_BACKOFF)
    assert "could not remove the source compiler directory" in caplog.text
    real_rmtree(leaked)
