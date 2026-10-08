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

REPO = Path(__file__).resolve().parents[2]


def _result_path(workdir: Path, scenario_id: str) -> Path:
    return workdir / f"{scenario_id}.result.json"


class SubprocessCaseWorker:
    """Parent-side handle for one case running in its own session."""

    def __init__(self, scenario_id: str, spec: dict[str, Any], workdir: Path, command: list[str] | None = None):
        self.scenario_id = scenario_id
        self._result = _result_path(workdir, scenario_id)
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
                start_new_session=True,
            )
        except BaseException:
            self._close()
            raise
        try:
            assert self.process.stdin is not None
            self.process.stdin.write(
                json.dumps({**spec, "parent_pid": os.getpid(), "result": str(self._result)}).encode()
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
        with suppress(ProcessLookupError, PermissionError):
            os.killpg(self.process.pid, signal.SIGKILL)

    def kill(self) -> None:
        self._reap_group()
        with suppress(Exception):
            self.process.wait(timeout=5)
        self._close()


def _watch_parent(parent_pid: int) -> None:
    """Unwind if the runner disappears without cleanup (SIGKILL, crash)."""
    while True:
        if os.getppid() != parent_pid:
            os.kill(os.getpid(), signal.SIGTERM)
            return
        time.sleep(1.0)


def main() -> int:
    """Run one catalog case from a JSON spec on stdin and write its private result file."""
    spec = json.loads(sys.stdin.read())

    def _exit(number: int, _frame: Any) -> None:
        raise SystemExit(128 + number)

    for name in ("SIGTERM", "SIGHUP"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), _exit)
    threading.Thread(target=_watch_parent, args=(int(spec["parent_pid"]),), daemon=True).start()

    from ci.native_runtime import probe_installed_pi_output as probe

    from .catalog import load_catalog
    from .runner import run_case

    _, identity, capabilities = probe._probe_native_identity()
    if identity.sha256 != spec["identity_sha256"] or capabilities.build_sha != spec["build_sha"]:
        raise RuntimeError("installed Guard changed between runner and case worker")
    scenario = next(s for s in load_catalog() if s.id == spec["scenario_id"])
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
