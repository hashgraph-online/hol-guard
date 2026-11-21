"""Capture a child without a timed-out wait that can block forever.

On Windows, ``subprocess.run(..., capture_output=True, timeout=...)`` kills
the direct child and then drains its pipes with no second deadline. A
detached descendant that inherited those pipes never closes them, so the
caller never returns. Writing the child to files means the wait ends when
the direct child dies.

Those files live in a temporary directory. A descendant can still hold them
open, and Windows refuses to delete an open file. Cleanup must not turn that
into a ``PermissionError`` that replaces ``TimeoutExpired`` or fails a
successful run. Removal is retried in the background until the holder exits.
"""

from __future__ import annotations

import atexit
import shutil
import subprocess
import tempfile
import threading
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Literal, overload

_OUTPUT_DIR_LOCK = threading.Lock()
_OUTPUT_DIRS: list[Path] = []
_OUTPUT_DIR_RETRY_SECONDS = 30.0


@overload
def run_bounded(
    argv: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout: float,
    input: bytes | None = None,
    stdin: int | None = None,
    text: Literal[False] = False,
) -> subprocess.CompletedProcess[bytes]: ...


@overload
def run_bounded(
    argv: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout: float,
    input: bytes | None = None,
    stdin: int | None = None,
    text: Literal[True],
) -> subprocess.CompletedProcess[str]: ...


def run_bounded(
    argv: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout: float,
    input: bytes | None = None,
    stdin: int | None = None,
    text: bool = False,
) -> subprocess.CompletedProcess[str] | subprocess.CompletedProcess[bytes]:
    """Run ``argv`` and return its output. ``timeout`` is a hard deadline."""

    if input is not None and stdin is not None:
        raise ValueError("input and stdin are mutually exclusive")
    command = list(argv)
    root = Path(tempfile.mkdtemp(prefix="bounded-stdio-"))
    try:
        stdout_path = root / "stdout"
        stderr_path = root / "stderr"
        with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
            kwargs: dict[str, object] = {
                "env": dict(env),
                "cwd": cwd,
                "stdout": stdout,
                "stderr": stderr,
                "timeout": timeout,
                "check": False,
            }
            if input is not None:
                kwargs["input"] = input
            elif stdin is not None:
                kwargs["stdin"] = stdin
            completed = subprocess.run(command, **kwargs)
        captured_out = stdout_path.read_bytes()
        captured_err = stderr_path.read_bytes()
        if text:
            return subprocess.CompletedProcess(
                command,
                completed.returncode,
                captured_out.decode("utf-8", errors="replace"),
                captured_err.decode("utf-8", errors="replace"),
            )
        return subprocess.CompletedProcess(command, completed.returncode, captured_out, captured_err)
    finally:
        _release_output_directory(root)


def _release_output_directory(root: Path) -> None:
    """Delete ``root``. A holder still using a file must not fail the caller."""

    try:
        shutil.rmtree(root)
    except OSError:
        if root.exists():
            _defer_output_directory(root)


def _defer_output_directory(root: Path) -> None:
    with _OUTPUT_DIR_LOCK:
        _OUTPUT_DIRS.append(root)
    threading.Thread(
        target=_retry_output_directory,
        args=(root,),
        name="bounded-stdio-cleanup",
        daemon=True,
    ).start()


def _retry_output_directory(root: Path) -> None:
    deadline = time.monotonic() + _OUTPUT_DIR_RETRY_SECONDS
    while True:
        try:
            shutil.rmtree(root)
        except OSError:
            if not root.exists() or time.monotonic() >= deadline:
                return
            time.sleep(0.25)
            continue
        return


def _release_leftover_output_directories() -> None:
    with _OUTPUT_DIR_LOCK:
        leftovers = list(_OUTPUT_DIRS)
    for root in leftovers:
        shutil.rmtree(root, ignore_errors=True)


atexit.register(_release_leftover_output_directories)
