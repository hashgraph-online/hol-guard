"""Client for the native hook launcher.

The native runtime owns isolated hook process launch: the process group or
Windows Job Object, resource limits, the output bound, the deadline, the
quarantine retry, the command contracts and the environment allowlist. This
module only starts the native ``hook-launch`` op, holds its stdin open for the
run (closing it is the stop signal), and renders the one JSON answer.

Python is the only process that exists before the launcher does, so starting
the launcher, pumping its stdin and stdout, and bounding the wait on it are the
one thing that cannot move into Rust.
"""

from __future__ import annotations

import functools
import json
import math
import os
import subprocess
import threading
import time
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from .native_process_stop_scope import scoped_native_stop_event

_HOOK_SUBPROCESS_OUTPUT_LIMIT = 1_000_000
LAUNCHER_ARGS = ("hook-launch", "--stdin")
# The launcher enforces the deadline itself and needs a moment to reap and
# settle; past this the launcher is the thing that is stuck.
_ANSWER_GRACE_SECONDS = 5.0
_SHORT_OP_TIMEOUT_SECONDS = 10.0
_STOP_POLL_SECONDS = 0.02
_CREATE_NO_WINDOW = 0x08000000

# Set when a launch reported a survivor the launcher could not settle; cleared
# by the next launch that contained its child.
_HOOK_PROCESS_CONTAINMENT_FAILED = threading.Event()


@dataclass(frozen=True, slots=True)
class BoundedHookProcessResult:
    """One bounded child result without inherited process context."""

    returncode: int | None
    stdout: str
    output_limit_exceeded: bool
    timed_out: bool
    containment_failed: bool = False
    stderr: str = ""
    capture_incomplete: bool = False


def hook_processes_contained(*, deadline_monotonic: float | None = None) -> bool:
    """Whether no launch left a survivor the native launcher could not settle."""
    del deadline_monotonic
    return not _HOOK_PROCESS_CONTAINMENT_FAILED.is_set()


def native_launcher_path(launcher: str | os.PathLike[str] | None = None) -> str | None:
    """The validated native runtime that serves ``hook-launch``, or ``None``."""
    if launcher is not None:
        return os.fspath(launcher)
    from .native_runtime import native_runtime_status

    status = native_runtime_status()
    if not status.available or not status.compatible or status.identity is None:
        return None
    return status.identity.path


def launcher_popen_options() -> dict[str, object]:
    """Process-creation options of a launcher: detached from our console and session."""
    if os.name == "nt":
        return {"creationflags": _CREATE_NO_WINDOW}
    return {"start_new_session": True}


def _launcher_environment() -> dict[str, str]:
    from .native_runtime import _isolated_environment

    return _isolated_environment()


def native_launcher_call(
    request: Mapping[str, object],
    *,
    launcher: str | os.PathLike[str] | None = None,
) -> dict[str, object] | None:
    """Run one short launcher op and return its answer object, or ``None``."""
    path = native_launcher_path(launcher)
    if path is None:
        return None
    try:
        completed = subprocess.run(
            [path, *LAUNCHER_ARGS],
            input=json.dumps(request).encode("utf-8") + b"\n",
            capture_output=True,
            timeout=_SHORT_OP_TIMEOUT_SECONDS,
            env=_launcher_environment(),
            check=False,
            **launcher_popen_options(),  # type: ignore[arg-type]
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    return _decode_answer(completed.stdout)


def _decode_answer(payload: bytes) -> dict[str, object] | None:
    try:
        answer = json.loads(payload)
    except ValueError:
        return None
    return answer if isinstance(answer, dict) else None


def _command_answer(request: Mapping[str, object]) -> tuple[str, ...]:
    answer = native_launcher_call(request)
    command = None if answer is None else answer.get("command")
    if not isinstance(command, list) or not all(isinstance(part, str) for part in command):
        raise RuntimeError("the native runtime is unavailable to build the isolated command")
    return tuple(command)


@functools.lru_cache(maxsize=64)
def _guard_cli_command(python_executable: str, package_root: str, guard_args: tuple[str, ...]) -> tuple[str, ...]:
    return _command_answer(
        {
            "op": "guard_cli_command",
            "python": python_executable,
            "package_root": package_root,
            "guard_args": list(guard_args),
        }
    )


def isolated_guard_cli_command(
    python_executable: str,
    package_root: Path,
    guard_args: Sequence[str],
) -> tuple[str, ...]:
    """Build the exact isolated fallback contract pinned to one package root."""
    return _guard_cli_command(python_executable, str(package_root), tuple(guard_args))


@functools.lru_cache(maxsize=64)
def _daemon_start_command(
    python_executable: str,
    package_root: str,
    guard_home: str,
    home_dir: str,
) -> tuple[str, ...]:
    return _command_answer(
        {
            "op": "daemon_start_command",
            "python": python_executable,
            "package_root": package_root,
            "guard_home": guard_home,
            "home_dir": home_dir,
        }
    )


def isolated_daemon_start_command(
    python_executable: str,
    package_root: Path,
    guard_home: Path,
    home_dir: Path | None = None,
) -> tuple[str, ...]:
    """Build the exact isolated daemon-start contract.

    ``home_dir`` remains optional for callers using the pre-2.1 signature.
    Managed manifests always bind the authenticated canonical home explicitly.
    """
    resolved_home_dir = Path.home() if home_dir is None else home_dir
    return _daemon_start_command(python_executable, str(package_root), str(guard_home), str(resolved_home_dir))


@functools.lru_cache(maxsize=16)
def _hook_environment(source: tuple[tuple[str, str], ...]) -> tuple[tuple[str, str], ...]:
    answer = native_launcher_call({"op": "hook_environment", "source": dict(source)})
    environment = None if answer is None else answer.get("environment")
    if not isinstance(environment, dict):
        return ()
    return tuple((str(name), str(value)) for name, value in environment.items())


def isolated_hook_environment(environment: Mapping[str, str] | None = None) -> dict[str, str]:
    """Keep OS, user-home, locale, temp, PATH, Codex, native, and signed proxy state."""
    source = os.environ if environment is None else environment
    return dict(_hook_environment(tuple(sorted(source.items()))))


def private_hook_runtime_cwd(manifest_path: Path) -> Path:
    """Return the authenticated manifest's private Guard-owned directory."""
    answer = native_launcher_call({"op": "private_runtime_cwd", "manifest_path": str(manifest_path)})
    if answer is None:
        raise ValueError("managed Codex hook runtime directory is unavailable")
    message = answer.get("error")
    if isinstance(message, str):
        raise ValueError(message)
    path = answer.get("path")
    if not isinstance(path, str):
        raise ValueError("managed Codex hook runtime directory is unavailable")
    return Path(path)


def windows_system_executable_path(filename: str) -> str:
    """Resolve a system executable without trusting PATH or environment variables."""
    if os.name != "nt":
        raise OSError("Windows system APIs are unavailable")
    answer = native_launcher_call({"op": "system_executable", "filename": filename})
    if answer is None:
        raise OSError("Windows system APIs are unavailable")
    message = answer.get("error")
    if isinstance(message, str):
        if "filename" in message:
            raise ValueError(message)
        raise OSError(message)
    path = answer.get("path")
    if not isinstance(path, str):
        raise OSError("Windows system APIs are unavailable")
    return path


def _close_stdin(process: subprocess.Popen[bytes]) -> None:
    if process.stdin is not None:
        with suppress(OSError, ValueError):
            process.stdin.close()


def _reap_launcher(process: subprocess.Popen[bytes], *, graceful_seconds: float) -> None:
    """End the launcher after its stdin closed; kill it only once it will not leave."""
    _close_stdin(process)
    try:
        _ = process.wait(timeout=graceful_seconds)
    except subprocess.TimeoutExpired:
        with suppress(OSError):
            process.kill()
        with suppress(subprocess.TimeoutExpired):
            _ = process.wait(timeout=1.0)
    if process.stdout is not None:
        with suppress(OSError, ValueError):
            process.stdout.close()


def _result_from_answer(answer: Mapping[str, object] | None) -> tuple[BoundedHookProcessResult, bool]:
    """The launch result and whether the launcher settled its quarantine."""
    failed = BoundedHookProcessResult(None, "", False, False)
    if answer is None:
        return failed, True
    returncode = answer.get("returncode")
    stdout = answer.get("stdout")
    stderr = answer.get("stderr")
    flags = [answer.get(name) for name in ("output_limit_exceeded", "timed_out", "containment_failed")]
    if (
        (returncode is not None and (not isinstance(returncode, int) or isinstance(returncode, bool)))
        or not isinstance(stdout, str)
        or not isinstance(stderr, str)
        or not all(isinstance(flag, bool) for flag in flags)
    ):
        return failed, True
    return (
        BoundedHookProcessResult(
            returncode=returncode,
            stdout=stdout,
            output_limit_exceeded=bool(flags[0]),
            timed_out=bool(flags[1]),
            containment_failed=bool(flags[2]),
            stderr=stderr,
            capture_incomplete=answer.get("capture_incomplete") is True,
        ),
        answer.get("quarantine_settled") is not False,
    )


def _exchange(
    launcher: str,
    request: Mapping[str, object],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    deadline: float,
    stop_event: threading.Event | None,
) -> dict[str, object] | None:
    """Run one ``launch`` request and return the answer; ``None`` when none came."""
    try:
        process = subprocess.Popen(
            [launcher, *LAUNCHER_ARGS],
            cwd=cwd,
            env=dict(environment),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            **launcher_popen_options(),  # type: ignore[arg-type]
        )
    except OSError:
        return None
    chunks: list[bytes] = []
    answered = threading.Event()

    def read_answer() -> None:
        try:
            if process.stdout is not None:
                chunks.append(process.stdout.read())
        except (OSError, ValueError):
            pass
        finally:
            answered.set()

    reader = threading.Thread(target=read_answer, daemon=True)
    reader.start()
    try:
        body = dict(request)
        body["timeout_millis"] = max(0, math.ceil((deadline - time.monotonic()) * 1000))
        if process.stdin is None:
            raise OSError("hook launcher stdin is unavailable")
        process.stdin.write(json.dumps(body).encode("utf-8") + b"\n")
        process.stdin.flush()
        hard_deadline = deadline + _ANSWER_GRACE_SECONDS
        while not answered.wait(_STOP_POLL_SECONDS):
            if stop_event is not None and stop_event.is_set():
                # EOF is the stop signal; the launcher still owes the answer.
                _close_stdin(process)
                stop_event = None
            if time.monotonic() >= hard_deadline:
                break
    except OSError:
        pass
    except BaseException:
        # An interrupt must not leave the child running with nobody enforcing
        # its deadline: end the launcher through its own stop path.
        _reap_launcher(process, graceful_seconds=2.0)
        raise
    got_answer = answered.is_set()
    _reap_launcher(process, graceful_seconds=1.0 if got_answer else 0.0)
    reader.join(timeout=1.0)
    if not got_answer or process.returncode != 0 or not chunks:
        return None
    return _decode_answer(chunks[0])


def run_isolated_hook_process(
    command: Sequence[str],
    *,
    input_text: str,
    cwd: Path,
    environment: Mapping[str, str],
    timeout_seconds: float | None = None,
    output_limit: int = _HOOK_SUBPROCESS_OUTPUT_LIMIT,
    allow_windows_breakaway: bool = False,
    windows_kill_on_job_close: bool = True,
    windows_job_memory_limit_bytes: int | None = None,
    windows_active_process_limit: int | None = None,
    stop_event: threading.Event | None = None,
    parent_liveness: bool = False,
    deadline_monotonic: float | None = None,
    launcher: str | os.PathLike[str] | None = None,
) -> BoundedHookProcessResult:
    """Run one child through the native launcher with bounded input lifetime and output bytes.

    ``stop_event`` lets a long-lived reviewed helper terminate through the same
    process-group / Windows Job containment path used for deadlines. Without
    one, the stop event bound by ``native_process_stop_scope`` applies, and
    once it is set no child starts.

    When ``deadline_monotonic`` is supplied it is authoritative: startup and
    stream cleanup consume the caller's existing budget instead of receiving a
    new minimum timeout. ``launcher`` names the native runtime when the caller
    already holds its validated path; otherwise the current runtime serves.
    """
    if stop_event is None:
        stop_event = scoped_native_stop_event()
    if stop_event is not None and stop_event.is_set():
        return BoundedHookProcessResult(None, "", False, False)
    if deadline_monotonic is None:
        if timeout_seconds is None:
            return BoundedHookProcessResult(None, "", False, False)
        deadline = time.monotonic() + max(0.0, timeout_seconds)
    else:
        deadline = deadline_monotonic
    if time.monotonic() >= deadline:
        return BoundedHookProcessResult(
            None, "", False, True, containment_failed=_HOOK_PROCESS_CONTAINMENT_FAILED.is_set()
        )
    path = native_launcher_path(launcher)
    if path is None:
        return BoundedHookProcessResult(None, "", False, False)
    answer = _exchange(
        path,
        {
            "op": "launch",
            "command": list(command),
            "input_text": input_text,
            "cwd": str(cwd),
            "environment": dict(environment),
            "output_limit": output_limit,
            "parent_liveness": parent_liveness,
            "allow_breakaway": allow_windows_breakaway,
            "kill_on_close": windows_kill_on_job_close,
            "job_memory_limit_bytes": windows_job_memory_limit_bytes,
            "active_process_limit": windows_active_process_limit,
        },
        cwd=cwd,
        environment=environment,
        deadline=deadline,
        stop_event=stop_event,
    )
    if answer is None and time.monotonic() >= deadline + _ANSWER_GRACE_SECONDS:
        # The launcher itself stopped answering: nothing vouches for its child.
        _HOOK_PROCESS_CONTAINMENT_FAILED.set()
        return BoundedHookProcessResult(None, "", False, True, containment_failed=True)
    result, settled = _result_from_answer(answer)
    if result.containment_failed and not settled:
        _HOOK_PROCESS_CONTAINMENT_FAILED.set()
    elif not result.containment_failed and answer is not None:
        _HOOK_PROCESS_CONTAINMENT_FAILED.clear()
    return result


__all__ = [
    "LAUNCHER_ARGS",
    "BoundedHookProcessResult",
    "hook_processes_contained",
    "isolated_daemon_start_command",
    "isolated_guard_cli_command",
    "isolated_hook_environment",
    "launcher_popen_options",
    "native_launcher_call",
    "native_launcher_path",
    "private_hook_runtime_cwd",
    "run_isolated_hook_process",
    "windows_system_executable_path",
]
