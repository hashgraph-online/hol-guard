"""Isolated, resource-bounded subprocesses for managed Codex hooks."""

from __future__ import annotations

import os
import signal
import stat
import subprocess
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

_HOOK_SUBPROCESS_OUTPUT_LIMIT = 1_000_000
_HOOK_ENVIRONMENT_KEYS = frozenset(
    {
        "CODEX_HOME",
        "COMSPEC",
        "HOME",
        "LANG",
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "USERPROFILE",
        "WINDIR",
    }
)


@dataclass(frozen=True, slots=True)
class BoundedHookProcessResult:
    """One bounded child result without inherited process context."""

    returncode: int | None
    stdout: str
    output_limit_exceeded: bool
    timed_out: bool


def isolated_guard_cli_command(
    python_executable: str,
    package_root: Path,
    guard_args: Sequence[str],
) -> tuple[str, ...]:
    """Build the exact isolated fallback contract pinned to one package root."""

    bootstrap = (
        "import sys;"
        f"sys.path.insert(0, {str(package_root.resolve())!r});"
        "from codex_plugin_scanner.cli import main;"
        "raise SystemExit(main(sys.argv[1:]))"
    )
    return (python_executable, "-I", "-c", bootstrap, *guard_args)


def isolated_daemon_start_command(
    python_executable: str,
    package_root: Path,
    guard_home: Path,
) -> tuple[str, ...]:
    """Build the exact isolated daemon-start contract."""

    bootstrap = (
        "import sys;"
        f"sys.path.insert(0, {str(package_root.resolve())!r});"
        "from pathlib import Path;"
        "from codex_plugin_scanner.guard.daemon import ensure_guard_daemon;"
        f"ensure_guard_daemon(Path({str(guard_home)!r}))"
    )
    return (python_executable, "-I", "-c", bootstrap)


def isolated_hook_environment(environment: Mapping[str, str] | None = None) -> dict[str, str]:
    """Keep only OS, user-home, locale, temp, PATH, and Codex state."""

    source = os.environ if environment is None else environment
    return {
        name: value
        for name, value in source.items()
        if name.upper() in _HOOK_ENVIRONMENT_KEYS or name.upper().startswith("LC_")
    }


def private_hook_runtime_cwd(manifest_path: Path) -> Path:
    """Return the authenticated manifest's private Guard-owned directory."""

    parent = manifest_path.parent
    try:
        parent_metadata = parent.lstat()
        resolved = parent.resolve(strict=True)
        resolved_metadata = resolved.lstat()
    except (OSError, RuntimeError) as exc:
        raise ValueError("managed Codex hook runtime directory is unavailable") from exc
    if stat.S_ISLNK(parent_metadata.st_mode) or not stat.S_ISDIR(parent_metadata.st_mode):
        raise ValueError("managed Codex hook runtime directory is not a regular directory")
    if (parent_metadata.st_dev, parent_metadata.st_ino) != (resolved_metadata.st_dev, resolved_metadata.st_ino):
        raise ValueError("managed Codex hook runtime directory changed during validation")
    if os.name != "nt":
        current_uid = os.getuid() if hasattr(os, "getuid") else None
        if current_uid is not None and parent_metadata.st_uid != current_uid:
            raise ValueError("managed Codex hook runtime directory has an unexpected owner")
        if stat.S_IMODE(parent_metadata.st_mode) & 0o077:
            raise ValueError("managed Codex hook runtime directory is not owner-only")
    return resolved


def run_isolated_hook_process(
    command: Sequence[str],
    *,
    input_text: str,
    cwd: Path,
    environment: Mapping[str, str],
    timeout_seconds: float,
    output_limit: int = _HOOK_SUBPROCESS_OUTPUT_LIMIT,
) -> BoundedHookProcessResult:
    """Run one child with bounded input lifetime and combined output bytes."""

    try:
        if os.name == "nt":
            process = subprocess.Popen(
                list(command),
                cwd=cwd,
                env=dict(environment),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
            )
        else:
            process = subprocess.Popen(
                list(command),
                cwd=cwd,
                env=dict(environment),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
    except OSError:
        return BoundedHookProcessResult(None, "", False, False)

    stdout_bytes = bytearray()
    output_bytes = 0
    output_lock = threading.Lock()
    output_limit_exceeded = threading.Event()

    def drain(stream: BinaryIO, *, capture: bool) -> None:
        nonlocal output_bytes
        while chunk := stream.read(64 * 1024):
            with output_lock:
                remaining = max(0, output_limit - output_bytes)
                accepted = chunk[:remaining]
                output_bytes += len(chunk)
                if capture and accepted:
                    stdout_bytes.extend(accepted)
                if output_bytes > output_limit:
                    output_limit_exceeded.set()

    def write_input() -> None:
        if process.stdin is None:
            return
        try:
            process.stdin.write(input_text.encode("utf-8"))
            process.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
        finally:
            process.stdin.close()

    readers = [
        threading.Thread(target=drain, args=(process.stdout,), kwargs={"capture": True}, daemon=True),
        threading.Thread(target=drain, args=(process.stderr,), kwargs={"capture": False}, daemon=True),
    ]
    writer = threading.Thread(target=write_input, daemon=True)
    for thread in readers:
        thread.start()
    writer.start()

    deadline = time.monotonic() + max(0.0, timeout_seconds)
    timed_out = False
    while process.poll() is None:
        if output_limit_exceeded.is_set():
            _kill_hook_process(process)
            break
        if time.monotonic() >= deadline:
            timed_out = True
            _kill_hook_process(process)
            break
        time.sleep(0.01)
    try:
        returncode = process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        _kill_hook_process(process)
        returncode = process.wait()
    writer.join(timeout=1)
    for thread in readers:
        thread.join(timeout=0.05)
    if any(thread.is_alive() for thread in readers):
        _kill_hook_process_group(process)
        for thread in readers:
            thread.join(timeout=1)
    with output_lock:
        stdout_decoded = stdout_bytes.decode("utf-8", errors="replace")
    return BoundedHookProcessResult(
        returncode=returncode,
        stdout=stdout_decoded,
        output_limit_exceeded=output_limit_exceeded.is_set(),
        timed_out=timed_out,
    )


def _kill_hook_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name != "nt":
            _kill_hook_process_group(process)
        else:
            process.kill()
    except (OSError, ProcessLookupError):
        process.kill()


def _kill_hook_process_group(process: subprocess.Popen[bytes]) -> None:
    if os.name == "nt":
        if process.poll() is None:
            process.kill()
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        if process.poll() is None:
            process.kill()


__all__ = [
    "BoundedHookProcessResult",
    "isolated_daemon_start_command",
    "isolated_guard_cli_command",
    "isolated_hook_environment",
    "private_hook_runtime_cwd",
    "run_isolated_hook_process",
]
