"""Host process environment and bounded execution for live Gauntlet cases."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from contextlib import suppress
from pathlib import Path

from .evidence import TRANSCRIPT_LIMIT

# Set by a ``--jobs`` case worker so its parent can reap agent sessions that the
# worker could not reap itself (for example after a forced kill).
group_ledger: Path | None = None


def _record_group(event: str, pgid: int) -> None:
    if group_ledger is not None:
        with group_ledger.open("a", encoding="utf-8") as ledger:
            ledger.write(f"{event} {pgid}\n")


def live_ledger_groups(ledger: Path) -> list[int]:
    """Process groups a worker started and did not record as reaped."""
    live: dict[int, None] = {}
    with suppress(OSError):
        for line in ledger.read_text(encoding="utf-8").splitlines():
            event, _, value = line.partition(" ")
            if not value.isdigit():
                continue
            if event == "start":
                live[int(value)] = None
            elif event == "end":
                live.pop(int(value), None)
    return list(live)


def clean_environment(home: Path, agent_dir: Path, canary: str) -> dict[str, str]:
    """The model/host receives no inherited provider, cloud or GitHub credential."""
    environment = {key: os.environ[key] for key in ("PATH", "SYSTEMROOT", "WINDIR") if key in os.environ}
    environment["PATH"] = str(Path(sys.executable).parent) + os.pathsep + environment.get("PATH", "")
    if os.name == "nt":
        environment.update(_windows_environment(home))
    environment.update(
        HOME=str(home),
        USERPROFILE=str(home),
        PI_CODING_AGENT_DIR=str(agent_dir),
        GAUNTLET_SECRET_TOKEN=canary,
        LANG="C.UTF-8",
        TERM="dumb",
        NO_COLOR="1",
        GIT_CONFIG_NOSYSTEM="1",
    )
    return environment


def _windows_environment(home: Path) -> dict[str, str]:
    """Process-launch essentials, with per-user state directories inside the fixture HOME."""
    environment = {
        key: os.environ[key]
        for key in (
            "COMSPEC",
            "PATHEXT",
            "PROGRAMFILES",
            "PROGRAMFILES(X86)",
            "PROGRAMW6432",
            "PROGRAMDATA",
            "PROCESSOR_ARCHITECTURE",
            "NUMBER_OF_PROCESSORS",
            "OS",
        )
        if key in os.environ
    }
    roaming, local = home / "AppData" / "Roaming", home / "AppData" / "Local"
    temporary = local / "Temp"
    for path in (roaming, temporary):
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    # POSIX tools from Git for Windows, such as sort, read TMPDIR rather than TEMP.
    environment.update(
        APPDATA=str(roaming),
        LOCALAPPDATA=str(local),
        TEMP=str(temporary),
        TMP=str(temporary),
        TMPDIR=str(temporary),
    )
    return environment


def run_process(
    command: list[str], *, cwd: Path, env: dict[str, str], output: Path, error_output: Path, timeout: float
) -> tuple[int, bool]:
    """Bound the actual host process and its transcript, not just a model flag."""
    if os.name == "nt":
        return _run_windows_process(
            command, cwd=cwd, env=env, output=output, error_output=error_output, timeout=timeout
        )
    if os.name != "posix":
        raise RuntimeError("Gauntlet requires a POSIX or Windows runner for process-tree containment")
    started = time.monotonic()
    timed_out = False
    with output.open("wb") as out, error_output.open("wb") as err:
        process = subprocess.Popen(command, cwd=cwd, env=env, stdout=out, stderr=err, start_new_session=True)
        try:
            _record_group("start", process.pid)
            timed_out = _await_bounded(
                process, started=started, output=output, error_output=error_output, timeout=timeout
            )
        finally:
            # The session belongs to this run, including when the operator interrupts it.
            previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT})
            try:
                with suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
                finally:
                    # Reaping the leader does not prove that its descendants exited.
                    with suppress(ProcessLookupError):
                        os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
                    _record_group("end", process.pid)
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
    return process.returncode, timed_out


def _await_bounded(
    process: subprocess.Popen[bytes], *, started: float, output: Path, error_output: Path, timeout: float
) -> bool:
    while process.poll() is None:
        if (
            time.monotonic() - started > timeout
            or output.stat().st_size > TRANSCRIPT_LIMIT
            or error_output.stat().st_size > TRANSCRIPT_LIMIT
        ):
            return True
        time.sleep(0.1)
    return False


def _run_windows_process(
    command: list[str], *, cwd: Path, env: dict[str, str], output: Path, error_output: Path, timeout: float
) -> tuple[int, bool]:
    """Contain the host and every descendant in a kill-on-close Job Object."""
    from . import windows_job

    started = time.monotonic()
    timed_out = False
    with output.open("wb") as out, error_output.open("wb") as err, windows_job.KillOnCloseJob() as job:
        # Start suspended so no descendant can be created before job assignment.
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=env,
            stdout=out,
            stderr=err,
            stdin=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | windows_job.CREATE_SUSPENDED,
        )
        try:
            job.assign_and_resume(process)
            timed_out = _await_bounded(
                process, started=started, output=output, error_output=error_output, timeout=timeout
            )
        finally:
            # The job belongs to this run, including when the operator interrupts it.
            job.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
    return process.returncode, timed_out
