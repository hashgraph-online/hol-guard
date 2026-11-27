"""Runs the production daemon (``hol-guard-runtime daemon-serve``) for a test.

The daemon answers the routes it owns itself and replays the rest through the
Guard CLI, exactly as an installed Guard does. A test that drives a route the
native daemon owns drives it here, not through the in-process handler harness,
so it proves what users run. Patches made inside the test process do not reach
the daemon or its replays.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
from collections.abc import Mapping
from pathlib import Path
from typing import IO

from codex_plugin_scanner.guard.store import GuardStore

_START_TIMEOUT_SECONDS = 30.0
# The daemon gives its start-time hook warm-up this long.
_HOOK_WARM_TIMEOUT_SECONDS = 60.0
# Ask the kernel: tests patch ``sys.platform`` while a daemon starts.
_HOST_IS_LINUX = hasattr(os, "uname") and os.uname().sysname == "Linux"


def _runtime_binary(guard_home: Path) -> Path:
    from codex_plugin_scanner.guard.cli.daemon_serve import native_serve_executable

    configured = os.environ.get("HOL_GUARD_NATIVE_BINARY", "").strip()
    if configured:
        return Path(configured)
    executable = native_serve_executable(guard_home)
    if executable is None:
        raise RuntimeError("The native daemon needs HOL Guard's native runtime (set HOL_GUARD_NATIVE_BINARY).")
    return executable


def _stop_with_parent() -> None:
    """Have Linux stop the daemon if the test process dies before stop()."""

    import ctypes
    import signal

    pr_set_pdeathsig = 1
    ctypes.CDLL(None, use_errno=True).prctl(pr_set_pdeathsig, signal.SIGTERM)


class HookWorkerWarmTimeoutError(RuntimeError):
    """The daemon recorded no end to its hook warm-up before the wait ran out."""


class NativeGuardDaemon:
    """Starts and stops ``daemon-serve`` for one Guard home on a free port."""

    def __init__(
        self,
        store: GuardStore,
        host: str = "127.0.0.1",
        port: int = 0,
        *,
        home_dir: Path | None = None,
        workers: bool = False,
        environment: Mapping[str, str] | None = None,
        cli_command: list[str] | None = None,
    ) -> None:
        # The daemon binds loopback, on a free port unless one is named; the
        # arguments mirror ``GuardDaemonServer`` so a test can swap one for the
        # other.
        if host != "127.0.0.1" or not 0 <= port <= 65535:
            raise ValueError("The native daemon harness serves 127.0.0.1.")
        self.store = store
        self.home_dir = home_dir
        self.workers = workers
        self.environment = dict(environment or {})
        self.cli_command = cli_command
        self.port = port
        self.pid = 0
        self._process: subprocess.Popen[bytes] | None = None
        self._log: IO[bytes] | None = None

    @property
    def auth_token(self) -> str:
        from codex_plugin_scanner.guard.native_daemon_manage import load_guard_daemon_auth_token

        loaded = load_guard_daemon_auth_token(self.store.guard_home)
        if not loaded:
            raise RuntimeError("The native daemon published no auth credential.")
        return loaded

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> None:
        from codex_plugin_scanner.guard.cli.daemon_serve import launch_configuration

        if self._process is not None:
            return
        guard_home = self.store.guard_home
        config = launch_configuration(guard_home, self.port, user_home=self.home_dir)
        config["workers"] = self.workers
        if self.cli_command is not None:
            config["cli_command"] = self.cli_command
        if os.name == "nt":
            # As on an installed Windows Guard, the daemon names its launcher
            # as its pid and stops when the launcher's standard input closes.
            config["launcher_pid"] = os.getpid()
        line = json.dumps(config, separators=(",", ":")).encode("utf-8") + b"\n"
        argv = [
            str(_runtime_binary(guard_home)),
            "daemon-serve",
            "--guard-home",
            str(config["guard_home"]),
            "--port",
            str(self.port),
        ]
        environment = dict(os.environ)
        environment.update(self.environment)
        if self.home_dir is not None:
            # The daemon runs as the user whose home it serves; the resident
            # binds its direct lane to that home.
            home = str(Path(self.home_dir).expanduser().resolve(strict=False))
            environment["HOME"] = home
            environment["USERPROFILE"] = home
        # Nothing reads the daemon's diagnostics while it runs, so they go to a
        # file: a full pipe would stall every request that logs.
        self._log = tempfile.TemporaryFile()  # noqa: SIM115 -- closed in stop()
        process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self._log,
            env=environment,
            preexec_fn=_stop_with_parent if _HOST_IS_LINUX else None,
        )
        self._process = process
        assert process.stdin is not None and process.stdout is not None
        process.stdin.write(line)
        process.stdin.flush()
        deadline = time.monotonic() + _START_TIMEOUT_SECONDS
        announced = process.stdout.readline()
        if not announced or time.monotonic() > deadline:
            self.stop()
            raise RuntimeError("The native daemon did not start.")
        facts = json.loads(announced)
        self.port = int(facts["port"])
        self.pid = int(facts["pid"])

    def wait_for_hook_worker(self, timeout_seconds: float = _HOOK_WARM_TIMEOUT_SECONDS) -> bool:
        """Wait for the daemon's start-time hook warm-up; True when it built the worker.

        The daemon builds the resident's hook worker in the background after it
        reports ready. A hook that arrives first waits behind that build, and a
        client that keeps its own short deadline gives up on it. An installed
        daemon has long finished warming when an agent starts, so a launcher
        that starts an agent right away waits here first.

        Returns False when the warm-up recorded that it could not build the
        worker, or when the daemon exited. Raises ``HookWorkerWarmTimeoutError``
        when no end of the warm-up was recorded before the wait ran out, or
        when the warm-up recorded that its call timed out: that call may still
        be running in the resident, so the worker is neither built nor known
        to be missing.
        """

        process = self._process
        # Lifecycle records carry the daemon's own process ID. On Windows the
        # daemon announces its launcher's ID instead, so match either.
        pids = {self.pid}
        native_pid = getattr(process, "pid", None)
        if isinstance(native_pid, int):
            pids.add(native_pid)
        directory = Path(self.store.guard_home) / "daemon-lifecycle"
        deadline = time.monotonic() + timeout_seconds
        while True:
            for pid in sorted(pids):
                for path in sorted(directory.glob(f"*-{pid:010d}-*.json")):
                    try:
                        record = json.loads(path.read_text(encoding="utf-8"))
                    except (OSError, ValueError):
                        continue
                    if isinstance(record, dict) and record.get("event") == "hook_worker_warmed":
                        if record.get("reason") == "timeout":
                            raise HookWorkerWarmTimeoutError(
                                "The native daemon's hook worker warm-up timed out and may still be running."
                            )
                        return record.get("reason") == "ok"
            if process is None or process.poll() is not None:
                return False
            if time.monotonic() >= deadline:
                # No record means the warm-up may still be running; starting
                # the agent now would put its first hook behind it.
                raise HookWorkerWarmTimeoutError(
                    f"The native daemon's hook worker did not finish warming within {timeout_seconds:g} s."
                )
            time.sleep(0.05)

    def stop(self) -> None:
        process = self._process
        if process is None:
            return
        self._process = None
        if process.stdin is not None:
            process.stdin.close()
        if os.name != "nt":
            # Elsewhere the daemon is its own process, stopped as `daemon
            # stop` stops it.
            process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        if process.stdout is not None:
            process.stdout.close()
        log = self._log
        self._log = None
        if log is not None:
            log.close()

    def __enter__(self) -> NativeGuardDaemon:
        self.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop()


__all__ = ["NativeGuardDaemon"]
