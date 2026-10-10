"""Per-case worker process for ``--jobs N``: one scenario, one private process.

Each case needs an in-process Guard daemon and native resident client, which carry
process-global state. A separate interpreter per case keeps that state, the relay,
the collector and the agent process group private to the case.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading
import time
from contextlib import suppress
from pathlib import Path
from typing import Any

from .host_process import live_ledger_groups

REPO = Path(__file__).resolve().parents[2]


def _result_path(workdir: Path, scenario_id: str) -> Path:
    return workdir / f"{scenario_id}.result.json"


def _kill_group(pgid: int) -> None:
    with suppress(ProcessLookupError, PermissionError):
        os.killpg(pgid, signal.SIGKILL)


class SubprocessCaseWorker:
    """Parent-side handle for one case running in its own session."""

    def __init__(
        self,
        scenario_id: str,
        spec: dict[str, Any],
        workdir: Path,
        command: list[str] | None = None,
        pass_fds: tuple[int, ...] = (),
    ):
        self.scenario_id = scenario_id
        self._result = _result_path(workdir, scenario_id)
        self._groups = workdir / f"{scenario_id}.groups"
        out = (workdir / f"{scenario_id}.stdout.txt").open("wb")
        err = (workdir / f"{scenario_id}.stderr.txt").open("wb")
        self._files = (out, err)
        try:
            self.process = subprocess.Popen(
                command or [sys.executable, "-m", "ci.gauntlet.case_worker"],
                cwd=REPO,
                stdin=subprocess.PIPE,
                stdout=out,
                stderr=err,
                # The slot lease fd survives here; the worker's own subprocesses use
                # the close_fds default so its agent children do not inherit it.
                pass_fds=pass_fds,
                # On Windows the worker's kill-on-close job contains the agent instead.
                start_new_session=os.name == "posix",
            )
        except BaseException:
            self._close()
            raise
        try:
            assert self.process.stdin is not None
            self.process.stdin.write(
                json.dumps(
                    {**spec, "parent_pid": os.getpid(), "result": str(self._result), "groups": str(self._groups)}
                ).encode()
            )
            self.process.stdin.close()
        except BaseException:
            self.kill()
            raise

    def _close(self) -> None:
        for stream in self._files:
            with suppress(OSError):
                stream.close()

    def poll(self) -> int | None:
        return self.process.poll()

    def collect(self) -> dict[str, Any]:
        returncode = self.process.wait()
        self._reap_group()
        self._close()
        if returncode != 0 or not self._result.is_file():
            raise RuntimeError(f"case worker for {self.scenario_id} failed before producing a result")
        return json.loads(self._result.read_text(encoding="utf-8"))

    def terminate(self) -> None:
        # Only the worker leader: it unwinds its own agent group, daemon and resident.
        with suppress(ProcessLookupError):
            os.kill(self.process.pid, signal.SIGTERM)

    def _reap_group(self) -> None:
        if os.name != "posix":
            # Killing the worker closes its job handle, which ends the agent tree.
            with suppress(OSError):
                self.process.kill()
            return
        _kill_group(self.process.pid)
        # The agent runs in its own session; reap any the worker left behind.
        for pgid in live_ledger_groups(self._groups):
            _kill_group(pgid)

    def kill(self) -> None:
        self._reap_group()
        with suppress(Exception):
            self.process.wait(timeout=5)
        self._close()


def _watch_parent(parent_pid: int) -> None:
    """Unwind if the runner disappears without cleanup (SIGKILL, crash)."""
    if os.name == "nt":
        # A venv python.exe is a launcher that runs the interpreter as its child, so
        # getppid() names the worker's own launcher. Wait on the runner itself.
        from .windows_job import wait_for_process_exit

        wait_for_process_exit(parent_pid)
        os.kill(os.getpid(), signal.SIGTERM)
        return
    while True:
        if os.getppid() != parent_pid:
            os.kill(os.getpid(), signal.SIGTERM)
            return
        time.sleep(1.0)


def restore_signal_delivery() -> None:
    """Unblock interrupts inherited from the scheduler's spawn-time signal mask.

    The scheduler spawns workers with interrupts blocked and an exec'd child keeps that
    mask, which would leave cancellation pending until the force-kill.
    """
    if hasattr(signal, "pthread_sigmask"):
        names = [getattr(signal, name) for name in ("SIGINT", "SIGTERM", "SIGHUP") if hasattr(signal, name)]
        signal.pthread_sigmask(signal.SIG_UNBLOCK, names)


def main() -> int:
    """Run one catalog case from a JSON spec on stdin and write its private result file."""
    spec = json.loads(sys.stdin.read())

    def _exit(number: int, _frame: Any) -> None:
        raise SystemExit(128 + number)

    for name in ("SIGTERM", "SIGHUP"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), _exit)
    restore_signal_delivery()
    threading.Thread(target=_watch_parent, args=(int(spec["parent_pid"]),), daemon=True).start()

    from ci.native_runtime import probe_installed_pi_output as probe

    from . import host_process
    from .catalog import load_catalog
    from .runner import run_case

    _, identity, capabilities = probe._probe_native_identity()
    if identity.sha256 != spec["identity_sha256"] or capabilities.build_sha != spec["build_sha"]:
        raise RuntimeError("installed Guard changed between runner and case worker")
    host_process.group_ledger = Path(spec["groups"])
    scenario = next(s for s in load_catalog() if s.id == spec["scenario_id"])
    if spec.get("harness", "omp") != "omp":
        from .harness_case import run_harness_case

        case = run_harness_case(
            scenario,
            harness=spec["harness"],
            root=Path(spec["root"]),
            public=Path(spec["public"]),
            executable=spec["executable"],
            identity=identity,
            timeout=float(spec["timeout"]),
            model=spec.get("harness_model"),
        )
        case.setdefault("guard_observations", [])
    else:
        case = run_case(
            scenario,
            root=Path(spec["root"]),
            public=Path(spec["public"]),
            executable=spec["executable"],
            identity=identity,
            provider=spec["provider"],
            timeout=float(spec["timeout"]),
        )
    result = Path(spec["result"])
    temporary = result.with_suffix(".tmp")
    temporary.write_text(
        json.dumps({"assessment": case["assessment"], "guard_observations": case["guard_observations"]}),
        encoding="utf-8",
    )
    os.replace(temporary, result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
