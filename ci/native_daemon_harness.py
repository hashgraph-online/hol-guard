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
import time
from pathlib import Path

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


class NativeGuardDaemon:
    """Starts and stops ``daemon-serve`` for one Guard home on a free port."""

    def __init__(self, store: GuardStore, *, home_dir: Path | None = None, workers: bool = False) -> None:
        self.store = store
        self.home_dir = home_dir
        self.workers = workers
        self.port = 0
        self.pid = 0
        self._process: subprocess.Popen[bytes] | None = None

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
        # The daemon names this process as its launcher and stops when its
        # standard input closes, so a test that dies cannot leak it.
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
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                stream.close()

    def __enter__(self) -> NativeGuardDaemon:
        self.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop()


__all__ = ["NativeGuardDaemon"]
