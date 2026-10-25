"""Packaged Windows Core coverage for the authenticated daemon launch gate."""

from __future__ import annotations

import json
import os
import re
import subprocess
import threading
import time
from collections import deque
from contextlib import suppress
from datetime import datetime, timezone
from itertools import islice
from pathlib import Path

import pytest


def _require(condition: bool, detail: object = "") -> None:
    if not condition:
        pytest.fail(repr(detail) if detail != "" else "requirement failed", pytrace=False)


def _run_core(executable: Path, args: list[str], *, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [str(executable), *args],
        env=env,
        capture_output=True,
        check=False,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        print(f"Packaged daemon failure diagnostics: {_diagnostics(env)}")
    return result


def _json_result(result: subprocess.CompletedProcess[str]) -> dict[str, object]:
    assert result.returncode == 0, f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
    payload = json.loads(result.stdout)
    assert isinstance(payload, dict), result.stdout
    return payload


def _assert_windows_process_stopped(pid: object) -> None:
    assert type(pid) is int and pid > 0, pid
    deadline = time.monotonic() + 5.0
    while True:
        result = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
            capture_output=True,
            check=False,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, result.stderr
        if f'"{pid}"' not in result.stdout:
            return
        if time.monotonic() >= deadline:
            pytest.fail(f"packaged daemon PID {pid} did not exit: {result.stdout!r}")
        time.sleep(0.1)


def _diagnostics(env: dict[str, str]) -> str:
    guard_home = Path(env["HOL_GUARD_HOME"])
    lines = []
    journal = guard_home / "daemon-lifecycle"
    if journal.is_dir():
        for entry in sorted(journal.iterdir()):
            try:
                event = json.loads(entry.read_text())
                lines.append(
                    f"{event.get('recorded_at_ns')}:{event.get('event')}:{event.get('pid')}:{event.get('reason', '')}"
                )
            except (OSError, ValueError):
                lines.append("unreadable")
    logs = guard_home / "logs"
    if logs.is_dir():
        for entry in sorted(logs.rglob("*"))[-6:]:
            if entry.is_file():
                lines.append(f"{entry.name}={_safe_read(entry)[-300:]!r}")
    for entry in guard_home.rglob("managed-resident-phases.v1.log"):
        text = _safe_read(entry)
        if text.startswith("<"):
            # The resident may hold the file without read sharing; say so instead of dropping the evidence.
            lines.append(f"{entry.name}={text}")
            continue
        phases = [line for line in text.splitlines() if line.startswith(_DIAGNOSTIC_PREFIXES)]
        lines.extend(phases[-96:])
    return " | ".join(lines)


def _process_and_listener_snapshot(guard_home: Path) -> str:
    """Name the live Guard processes, loopback listeners and resident state files for a failed step.

    A resident that is listed in state but never answers authentication leaves no phase evidence of its
    own, so record whether it is alive, what it listens on and whether its phase file exists.
    """

    lines = ["--- process and listener snapshot ---"]
    for command in (
        ["tasklist", "/FI", "IMAGENAME eq hol-guard*", "/FO", "CSV", "/NH"],
        ["tasklist", "/FI", "IMAGENAME eq guard-runtime*", "/FO", "CSV", "/NH"],
        ["netstat", "-ano", "-p", "TCP"],
    ):
        try:
            result = subprocess.run(command, capture_output=True, check=False, text=True, timeout=10)
        except (OSError, subprocess.SubprocessError) as error:
            lines.append(f"{command[0]}: {error!r}")
            continue
        output = result.stdout
        if command[0] == "netstat":
            output = "\n".join(line for line in output.splitlines() if "127.0.0.1" in line and "LISTENING" in line)
        lines.append(output.strip())
    runtime_dir = guard_home / "native-runtime"
    if runtime_dir.is_dir():
        for entry in sorted(runtime_dir.rglob("*")):
            try:
                size = entry.stat().st_size if entry.is_file() else "dir"
            except OSError as error:
                size = repr(error)
            lines.append(f"{entry.relative_to(runtime_dir)} size={size}")
    return "\n".join(lines)


def _start_timeline(env: dict[str, str]) -> str:
    """Bounded daemon startup events and phase timings, printed even when the test passes."""

    daemon_log = Path(env["HOL_GUARD_HOME"]) / "logs" / "daemon.log"
    lines = []
    for raw in _safe_read(daemon_log).splitlines():
        try:
            record = json.loads(raw)
        except ValueError:
            continue
        event = str(record.get("event", ""))
        if event in _TIMELINE_EVENTS or event == "startup_phase":
            lines.append(f"{record.get('timestamp', '')[11:23]} {event} {record.get('detail', '')}".rstrip())
    for entry in Path(env["HOL_GUARD_HOME"]).rglob("managed-resident-phases.v1.log"):
        phases = [line for line in _safe_read(entry).splitlines() if line.startswith(_DIAGNOSTIC_PREFIXES)]
        lines.extend(phases[-64:])
    return "\n".join(lines[-300:])


_DIAGNOSTIC_PREFIXES = ("native_resident_phase ", "native_resident_note ")

_TIMELINE_EVENTS = frozenset(
    {
        "daemon_listen_ready",
        "daemon_ready",
        "runtime_artifact_reconciliation_completed",
        "onefile_extraction_reclaimed",
    }
)


def _full_diagnostics(env: dict[str, str]) -> str:
    """Complete daemon journal records and complete log files for a failed packaged step."""

    guard_home = Path(env["HOL_GUARD_HOME"])
    sections = [_diagnostics(env), _process_and_listener_snapshot(guard_home)]
    journal = guard_home / "daemon-lifecycle"
    if journal.is_dir():
        for entry in sorted(journal.iterdir()):
            if entry.is_file():
                sections.append(f"--- journal {entry.name} ---\n{_safe_read(entry)}")
    logs = guard_home / "logs"
    if logs.is_dir():
        for entry in sorted(logs.rglob("*")):
            if entry.is_file():
                sections.append(f"--- {entry.name} ---\n{_safe_read(entry)}")
    try:
        sections.extend(_resident_state_diagnostics(guard_home))
    except Exception as error:  # evidence collection must never replace the original failure
        sections.append(f"resident state diagnostics failed: {error!r}")
    return "\n".join(sections)


# Resident state fields that locate a resident without exposing its token or MAC.
_STATE_FIELDS = ("generation", "process_id", "owner_process_id", "transport", "endpoint", "created_ms")
_RUNTIME_PROCESS_QUERY = (
    "Get-CimInstance Win32_Process -Filter \"Name like 'hol-guard%'\" | "
    "Select-Object ProcessId,ParentProcessId,CreationDate,Name,CommandLine | ConvertTo-Json -Compress"
)


def _utc_clock(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime("%H:%M:%S.%f")[:-3]


def _long_path(path: Path) -> str:
    """The Win32 long form of ``path``, so an 8.3 alias in the state base is visible."""

    if os.name != "nt":
        return str(path)
    import ctypes

    buffer = ctypes.create_unicode_buffer(32768)
    length = ctypes.windll.kernel32.GetLongPathNameW(str(path), buffer, len(buffer))
    return buffer.value if 0 < length < len(buffer) else f"<GetLongPathNameW failed for {path}>"


def _state_summary(path: Path) -> str:
    try:
        state = json.loads(path.read_text())
    except (OSError, ValueError) as error:
        return f"<unreadable {error!r}>"
    if not isinstance(state, dict):
        return "<not an object>"
    fields = [f"{key}={state.get(key)!r}" for key in _STATE_FIELDS]
    digest = state.get("runtime_sha256")
    fields.append(f"runtime_sha256_prefix={digest[:16] if isinstance(digest, str) else None!r}")
    fields.append(f"keys={sorted(state)}")
    return " ".join(fields)


def _runtime_tree(guard_home: Path) -> list[str]:
    """Every native-runtime entry with size and mtime; generation files also name their resident."""

    runtime_dir = guard_home / "native-runtime"
    lines = []
    if not runtime_dir.is_dir():
        return [f"{runtime_dir} missing"]
    try:
        entries = sorted(runtime_dir.rglob("*"))
    except OSError as error:
        return [f"{runtime_dir} walk={error!r}"]
    for entry in entries:
        relative = entry.relative_to(runtime_dir)
        try:
            stat = entry.stat()
        except OSError as error:
            lines.append(f"{relative} stat={error!r}")
            continue
        kind = "dir" if entry.is_dir() else f"size={stat.st_size}"
        line = f"{relative} {kind} mtime={_utc_clock(stat.st_mtime)}"
        if entry.is_file() and entry.name.startswith("generation-") and entry.suffix == ".json":
            line += f" state: {_state_summary(entry)}"
        lines.append(line)
    return lines


def _resident_state_diagnostics(guard_home: Path) -> list[str]:
    """Full resident phase history, resident stderr, state tree and the state base each process ran with."""

    runtime_dir = guard_home / "native-runtime"
    sections = [
        "--- resident state base ---\n"
        f"guard_home={guard_home}\nlong_guard_home={_long_path(guard_home)}\n"
        f"realpath_guard_home={os.path.realpath(guard_home)}\nruntime_dir={runtime_dir}",
        "--- native-runtime tree ---\n" + "\n".join(_runtime_tree(guard_home)),
    ]
    for entry in sorted(guard_home.rglob("managed-resident-phases.v1.log")):
        sections.append(f"--- full {entry.relative_to(guard_home)} ---\n{_safe_read(entry)}")
    for entry in sorted(guard_home.rglob("resident-stderr*.log")):
        sections.append(f"--- {entry.relative_to(guard_home)} ---\n{_safe_read(entry)}")
    if os.name == "nt":
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", _RUNTIME_PROCESS_QUERY],
                capture_output=True,
                check=False,
                text=True,
                timeout=30,
            )
            processes = result.stdout.strip() or result.stderr.strip()
        except (OSError, subprocess.SubprocessError) as error:
            processes = repr(error)
        # Runtime command lines carry --state-dir, generation, owner PID and digest; tokens go over stdin.
        sections.append(f"--- Guard process command lines ---\n{processes}")
    return sections


class _StateDirSampler:
    """Record when resident state entries appear, change and vanish while a packaged step runs.

    The client that times out is killed before the post-failure snapshot, so the snapshot alone
    cannot show whether a generation file existed during its spawn wait.
    """

    _INTERVAL_SECONDS = 0.2
    _MAX_EVENTS = 600

    def __init__(self, guard_home: Path) -> None:
        self._runtime_dir = guard_home / "native-runtime"
        self._events: deque[str] = deque(maxlen=self._MAX_EVENTS)
        self._dropped = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="resident-state-sampler", daemon=True)

    def __enter__(self) -> _StateDirSampler:
        self._thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self._stop.set()
        self._thread.join(timeout=5)

    def _snapshot(self) -> dict[str, tuple[int, int]]:
        entries: dict[str, tuple[int, int]] = {}
        if not self._runtime_dir.is_dir():
            return entries
        try:
            paths = list(self._runtime_dir.rglob("*"))
        except OSError:
            return entries
        for entry in paths:
            try:
                stat = entry.stat()
            except OSError:
                continue
            size = -1 if entry.is_dir() else stat.st_size
            entries[str(entry.relative_to(self._runtime_dir))] = (size, stat.st_mtime_ns)
        return entries

    def _record(self, line: str) -> None:
        if len(self._events) == self._MAX_EVENTS:
            self._dropped += 1  # the append below evicts the oldest event
        self._events.append(f"{_utc_clock(time.time())} {line}")

    def _run(self) -> None:
        previous: dict[str, tuple[int, int]] = {}
        while not self._stop.is_set():
            current = self._snapshot()
            for name in sorted(current.keys() - previous.keys()):
                size = current[name][0]
                self._record(f"add {name} {'dir' if size < 0 else f'size={size}'}")
            for name in sorted(previous.keys() - current.keys()):
                self._record(f"remove {name}")
            for name in sorted(current.keys() & previous.keys()):
                if current[name] != previous[name] and "phases" not in name:
                    self._record(f"change {name} size={current[name][0]}")
            previous = current
            self._stop.wait(self._INTERVAL_SECONDS)

    def report(self) -> str:
        dropped = f"({self._dropped} earlier events dropped)\n" if self._dropped else ""
        return "--- native-runtime state timeline ---\n" + dropped + "\n".join(self._events)


def _safe_read(path: Path) -> str:
    try:
        return path.read_text(errors="replace")
    except OSError as error:
        return f"<{error!r}>"


def _assert_cleanup_succeeded(
    cleanup: subprocess.CompletedProcess[str], env: dict[str, str], sampler: _StateDirSampler
) -> None:
    if cleanup.returncode != 0:
        try:
            from codex_plugin_scanner.guard.native_resident_stream import _NATIVE_DIAGNOSTIC_LINE

            lines = ["Packaged cleanup resident diagnostics:"]
            for line in sampler.report().splitlines()[-64:]:
                event = re.fullmatch(r"([0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}) (add|remove|change) .+", line)
                if event:
                    # Entry names may contain private paths; retain only time and event kind.
                    lines.append(f"resident_state {event[1]} {event[2]}")
            paths = Path(env["HOL_GUARD_HOME"]).rglob("managed-resident-phases.v1.log")
            for path in islice(paths, 4):
                try:
                    with path.open("rb") as source:
                        payload = source.read(64 * 1024)
                except OSError:
                    lines.append("resident_phases=unavailable")
                    continue
                for line in payload.splitlines()[-64:]:
                    if _NATIVE_DIAGNOSTIC_LINE.fullmatch(line):
                        lines.append(line.decode("ascii"))
            print("\n".join(lines)[:4096])
        except Exception:
            # Evidence collection must never replace the original cleanup assertion.
            with suppress(Exception):
                print("Packaged cleanup resident diagnostics: unavailable")
    assert cleanup.returncode == 0, f"stdout={cleanup.stdout!r}\nstderr={cleanup.stderr!r}"


def _stop_and_assert_process_stopped(
    executable: Path,
    stop_args: list[str],
    *,
    env: dict[str, str],
    pid: object,
) -> dict[str, object]:
    stopped = _json_result(_run_core(executable, stop_args, env=env))
    assert stopped["running"] is False, stopped
    assert stopped["stopped"] is True, (stopped, _diagnostics(env))
    assert stopped["pid"] == pid, stopped
    _assert_windows_process_stopped(pid)
    return stopped


@pytest.mark.skipif(os.name != "nt", reason="exercises the packaged Windows frozen runtime")
@pytest.mark.parametrize("native_diagnostics", ["0", "1"])
def test_packaged_windows_core_bootstrap_retry_and_repair(tmp_path: Path, native_diagnostics: str) -> None:
    executable_value = os.environ.get("HOL_GUARD_FROZEN_TEST_EXECUTABLE")
    if not executable_value:
        pytest.fail("HOL_GUARD_FROZEN_TEST_EXECUTABLE must point to the PyInstaller binary")
    executable = Path(executable_value).resolve(strict=True)
    home_dir = tmp_path / "home"
    guard_home = tmp_path / "guard-home"
    appdata = tmp_path / "appdata"
    local_appdata = tmp_path / "local-appdata"
    for directory in (home_dir, guard_home, appdata, local_appdata):
        directory.mkdir()

    env = {
        key: value
        for key, value in os.environ.items()
        if key.upper() not in {"PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV"}
    }
    env.update(
        {
            "HOME": str(home_dir),
            "USERPROFILE": str(home_dir),
            "APPDATA": str(appdata),
            "LOCALAPPDATA": str(local_appdata),
            "HOL_GUARD_HOME": str(guard_home),
            "HOL_GUARD_DESKTOP": "1",
            "HOL_GUARD_NATIVE_DIAGNOSTIC": native_diagnostics,
            # The guard home lives under pytest's tmp path, which opts the daemon into
            # a 5 s idle shutdown. Each packaged CLI step here takes longer than that
            # on a cold runner, so keep the daemon up between steps.
            "GUARD_DAEMON_IDLE_TIMEOUT_SECONDS": "600",
        }
    )

    bootstrap_args = [
        "desktop",
        "bootstrap",
        "--guard-home",
        str(guard_home),
        "--home",
        str(home_dir),
        "--json",
    ]
    status_args = ["daemon", "status", "--guard-home", str(guard_home), "--json"]
    stop_args = ["daemon", "stop", "--guard-home", str(guard_home), "--json"]
    repair_args = ["daemon", "repair", "--guard-home", str(guard_home), "--json"]

    sampler = _StateDirSampler(guard_home)
    sampler.__enter__()
    try:
        bootstrap = _json_result(_run_core(executable, bootstrap_args, env=env))
        _require(bootstrap["schema"] == "guard-desktop-bootstrap.v1")
        first_status = _json_result(_run_core(executable, status_args, env=env))
        _require(first_status["running"] is True, (first_status, bootstrap, _diagnostics(env)))
        first_pid = first_status["pid"]

        _stop_and_assert_process_stopped(
            executable,
            stop_args,
            env=env,
            pid=first_pid,
        )

        retry_bootstrap = _json_result(_run_core(executable, bootstrap_args, env=env))
        _require(retry_bootstrap["schema"] == "guard-desktop-bootstrap.v1")
        retry_status = _json_result(_run_core(executable, status_args, env=env))
        _require(retry_status["running"] is True, (retry_status, retry_bootstrap, _diagnostics(env)))
        retry_pid = retry_status["pid"]
        _stop_and_assert_process_stopped(
            executable,
            stop_args,
            env=env,
            pid=retry_pid,
        )

        repaired = _json_result(_run_core(executable, repair_args, env=env))
        _require(repaired["runtime_status"] == "restarted")
        repaired_status = _json_result(_run_core(executable, status_args, env=env))
        _require(repaired_status["running"] is True)
    except (Exception, pytest.fail.Exception) as error:
        sampler.__exit__()
        pytest.fail(f"{error!r}\n{_full_diagnostics(env)}\n{sampler.report()}", pytrace=False)
    finally:
        sampler.__exit__()
        print(f"Packaged daemon start timeline:\n{_start_timeline(env)}")
        cleanup = _run_core(executable, stop_args, env=env)
        _assert_cleanup_succeeded(cleanup, env, sampler)
        cleanup_payload = _json_result(cleanup)
        if isinstance(cleanup_payload.get("pid"), int):
            _assert_windows_process_stopped(cleanup_payload["pid"])
