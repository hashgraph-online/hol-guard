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


def clean_environment(home: Path, agent_dir: Path, canary: str) -> dict[str, str]:
    """The model/host receives no inherited provider, cloud or GitHub credential."""
    environment = {key: os.environ[key] for key in ("PATH", "SYSTEMROOT", "WINDIR") if key in os.environ}
    environment["PATH"] = str(Path(sys.executable).parent) + os.pathsep + environment.get("PATH", "")
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


def run_process(
    command: list[str], *, cwd: Path, env: dict[str, str], output: Path, error_output: Path, timeout: float
) -> tuple[int, bool]:
    """Bound the actual host process and its transcript, not just a model flag."""
    if os.name != "posix":
        raise RuntimeError("Gauntlet currently requires a POSIX runner for process-group containment")
    started = time.monotonic()
    timed_out = False
    with output.open("wb") as out, error_output.open("wb") as err:
        process = subprocess.Popen(command, cwd=cwd, env=env, stdout=out, stderr=err, start_new_session=True)
        try:
            while process.poll() is None:
                if (
                    time.monotonic() - started > timeout
                    or output.stat().st_size > TRANSCRIPT_LIMIT
                    or error_output.stat().st_size > TRANSCRIPT_LIMIT
                ):
                    timed_out = True
                    break
                time.sleep(0.1)
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
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
    return process.returncode, timed_out
