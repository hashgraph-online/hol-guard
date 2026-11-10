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
import sys
import tempfile
import time
from pathlib import Path
from typing import IO

from codex_plugin_scanner.guard.store import GuardStore

_START_TIMEOUT_SECONDS = 30.0


def _runtime_binary(guard_home: Path) -> Path:
    from codex_plugin_scanner.guard.daemon.native_serve import native_serve_executable

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
    ) -> None:
        # The daemon binds loopback on a port it picks; the arguments mirror
        # ``GuardDaemonServer`` so a test can swap one for the other.
        if host != "127.0.0.1" or port != 0:
            raise ValueError("The native daemon harness serves 127.0.0.1 on a free port.")
        self.store = store
        self.home_dir = home_dir
        self.workers = workers
        self.port = 0
        self.pid = 0
        self._process: subprocess.Popen[bytes] | None = None
        self._log: IO[bytes] | None = None

    @property
    def auth_token(self) -> str:
        from codex_plugin_scanner.guard.daemon.auth_token import load_guard_daemon_auth_token

        loaded = load_guard_daemon_auth_token(self.store.guard_home)
        if not loaded:
            raise RuntimeError("The native daemon published no auth credential.")
        return loaded

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> None:
        from codex_plugin_scanner.guard.daemon.native_serve import launch_configuration

        if self._process is not None:
            return
        guard_home = self.store.guard_home
        config = launch_configuration(guard_home, 0, user_home=self.home_dir)
        config["workers"] = self.workers
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
            "0",
        ]
        environment = dict(os.environ)
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
            preexec_fn=_stop_with_parent if sys.platform == "linux" else None,
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
