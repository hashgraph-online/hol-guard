"""The Windows CI capture helper must return when its deadline expires."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from tests.support.bounded_subprocess import run_bounded


def test_bounded_run_returns_both_streams(tmp_path: Path) -> None:
    completed = run_bounded(
        [sys.executable, "-c", "import sys; sys.stdout.write('out'); sys.stderr.write('err')"],
        cwd=tmp_path,
        env=os.environ,
        timeout=10,
        text=True,
    )

    assert completed.returncode == 0
    assert completed.stdout == "out"
    assert completed.stderr == "err"


def test_bounded_run_timeout_returns_without_waiting_out_a_descendant(tmp_path: Path) -> None:
    """A grandchild holding the parent's stdout must not keep the wait open.

    ``capture_output=True`` on Windows drains pipes again after kill, with no
    deadline. This child exits immediately after spawning that grandchild.
    """

    script = """
import subprocess, sys, time
# Inherit stdout and outlive the parent. A pipe capture would stay open.
subprocess.Popen([sys.executable, "-c", "import time; time.sleep(8)"])
time.sleep(30)
"""
    started = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        run_bounded(
            [sys.executable, "-c", script],
            cwd=tmp_path,
            env=os.environ,
            timeout=1,
        )

    assert time.monotonic() - started < 10


def test_cleanup_permission_error_does_not_mask_timeout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A descendant holding the output files must not replace ``TimeoutExpired``."""

    real_rmtree = shutil.rmtree
    temp_root = Path(tempfile.gettempdir())
    before = set(temp_root.glob("bounded-stdio-*"))
    held = True

    def held_rmtree(path: str | Path, *args: object, **kwargs: object) -> None:
        if held:
            raise PermissionError(13, "Access is denied")
        real_rmtree(path, *args, **kwargs)

    monkeypatch.setattr(shutil, "rmtree", held_rmtree)
    started = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        run_bounded(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            cwd=tmp_path,
            env=os.environ,
            timeout=0.3,
        )

    assert time.monotonic() - started < 5
    created = set(temp_root.glob("bounded-stdio-*")) - before
    assert len(created) == 1
    held = False
    directory = created.pop()
    deadline = time.monotonic() + 3
    while directory.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not directory.exists()


def test_cleanup_permission_error_keeps_successful_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real_rmtree = shutil.rmtree
    released = False

    def fail_once(path: object, *args: object, **kwargs: object) -> None:
        nonlocal released
        if not released:
            released = True
            raise PermissionError(32, "The process cannot access the file")
        real_rmtree(path, *args, **kwargs)

    monkeypatch.setattr(shutil, "rmtree", fail_once)
    completed = run_bounded(
        [sys.executable, "-c", "import sys; sys.stdout.write('out'); sys.stderr.write('err')"],
        cwd=tmp_path,
        env=os.environ,
        timeout=10,
        text=True,
    )

    assert completed.returncode == 0
    assert completed.stdout == "out"
    assert completed.stderr == "err"
