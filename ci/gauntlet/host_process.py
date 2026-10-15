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


# Mirrors the contained Python runner's trusted interpreter roots; others (Conda, pyenv) it refuses.
TRUSTED_PYTHON_ROOTS = tuple(
    Path(root) for root in ("/bin", "/opt/homebrew", "/opt/hostedtoolcache/Python", "/System", "/usr/bin", "/usr/local")
)


def python_shim(directory: Path, search_path: str) -> str | None:
    """Expose the developer's own ``python3`` ahead of the candidate virtualenv.

    The candidate venv must stay on PATH so ``hol-guard`` resolves to the build under test, but a
    developer shell does not resolve ``python3`` to a tool's private interpreter. Link ``python3``
    and ``python`` to the first ``python3`` on PATH outside any virtualenv whose real path lies in a
    root Guard's contained runner trusts; without one, add nothing.
    """
    if os.name != "posix":
        return None
    candidate_bin = Path(sys.executable).parent
    for entry in search_path.split(os.pathsep):
        folder = Path(entry)
        if not folder.is_absolute() or folder == candidate_bin or (folder.parent / "pyvenv.cfg").exists():
            continue
        interpreter = folder / "python3"
        if (
            interpreter.is_file()
            and os.access(interpreter, os.X_OK)
            and any(interpreter.resolve().is_relative_to(root) for root in TRUSTED_PYTHON_ROOTS)
        ):
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            for name in ("python3", "python"):
                (directory / name).unlink(missing_ok=True)
                (directory / name).symlink_to(interpreter)
            return str(directory)
    return None


def clean_environment(home: Path, agent_dir: Path, canary: str) -> dict[str, str]:
    """The model/host receives no inherited provider, cloud or GitHub credential."""
    environment = {key: os.environ[key] for key in ("PATH", "SYSTEMROOT", "WINDIR") if key in os.environ}
    environment["PATH"] = str(Path(sys.executable).parent) + os.pathsep + environment.get("PATH", "")
    if shim := python_shim(agent_dir.parent / "python-bin", environment["PATH"]):
        environment["PATH"] = shim + os.pathsep + environment["PATH"]
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


def realistic_environment(environment: dict[str, str], home: Path) -> dict[str, str]:
    """Overlay the variables a developer shell carries that a bare environment lacks.

    On Linux and macOS the loader path points at an empty directory, so it is set but inert.
    Together with the fixture's global git config (LFS filter, gpg program, hooks path) it
    reproduces the shapes that made ordinary shell commands look unusual to Guard.
    """
    environment = dict(environment)
    environment.update(
        {
            "SHELL": "/bin/sh",
            "USER": "developer",
            "LOGNAME": "developer",
            "EDITOR": "true",
            "PAGER": "cat",
            "GIT_PAGER": "cat",
            "XDG_CONFIG_HOME": str(home / ".config"),
            "XDG_CACHE_HOME": str(home / ".cache"),
            "CARGO_HOME": str(home / ".cargo"),
            "npm_config_cache": str(home / ".npm"),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    # Developer shells put per-user CLIs such as doctl in ~/.local/bin ahead of the system PATH.
    local_bin = home / ".local/bin"
    if "PATH" in environment and local_bin.is_dir():
        environment["PATH"] = str(local_bin) + os.pathsep + environment["PATH"]
    # Windows resolves DLLs through PATH, so a Windows developer shell carries no loader path.
    if os.name != "nt":
        libraries = home / ".local/lib"
        libraries.mkdir(parents=True, exist_ok=True)
        environment["LD_LIBRARY_PATH"] = str(libraries)
        if sys.platform == "darwin":
            environment["DYLD_LIBRARY_PATH"] = str(libraries)
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
