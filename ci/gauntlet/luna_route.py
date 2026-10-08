"""Run the pinned Oh My Pi ChatGPT Luna lane as a loopback Chat Completions transport.

Oh My Pi's ``openai-codex`` Luna lane speaks the Responses API through the user's
existing ChatGPT login. The Gauntlet relay speaks streaming Chat Completions. The
adapter in ``luna_adapter.ts`` translates between them and nothing else: it never
executes a tool, so every model-selected call still runs in the Gauntlet agent
through the installed Guard extension. Credentials are resolved inside the adapter
process by Oh My Pi's normal auth storage and are never passed through this module.
"""

from __future__ import annotations

import json
import os
import queue
import secrets
import shutil
import signal
import subprocess
import threading
from contextlib import suppress
from pathlib import Path
from typing import Any

ADAPTER = Path(__file__).with_name("luna_adapter.ts")
PINNED_PACKAGE = Path(__file__).resolve().parents[1] / "pi-exact-continuation" / "package.json"
ADAPTER_ID = "pinned-omp-native-luna-stream-v2"
REQUEST_MODEL = "native-luna-high"
BACKEND = ("openai-codex", "gpt-5.6-luna")
IDENTITY = f"{BACKEND[0]}/{BACKEND[1]}/high via {ADAPTER_ID} (loopback Chat Completions to Responses)"
STARTUP_SECONDS = 60.0
STOP_SECONDS = 5.0
# Only what Bun and Oh My Pi's auth discovery need. Provider keys are not forwarded.
_ENVIRONMENT_KEYS = ("PATH", "HOME", "USER", "LOGNAME", "TMPDIR", "LANG", "XDG_CONFIG_HOME", "XDG_DATA_HOME")


def sdk_root_for(omp: str | None, override: Path | None = None) -> Path:
    """Locate the dependency tree that holds the exact pinned Oh My Pi packages."""
    if override is not None:
        root = override.resolve()
    else:
        executable = omp or shutil.which("omp")
        if not executable:
            raise RuntimeError("install the repository-pinned Oh My Pi CLI or pass --sdk-root")
        # <root>/node_modules/.bin/omp
        root = Path(executable).absolute().parents[2]
    package = root / "node_modules" / "@oh-my-pi" / "pi-coding-agent" / "package.json"
    if not (root / "node_modules" / "@oh-my-pi" / "pi-agent-core").is_dir() or not package.is_file():
        raise RuntimeError("the SDK root does not contain the pinned Oh My Pi packages; pass --sdk-root")
    pinned = json.loads(PINNED_PACKAGE.read_text())["dependencies"]["@oh-my-pi/pi-coding-agent"]
    if json.loads(package.read_text()).get("version") != pinned:
        raise RuntimeError("the SDK root is not the repository-pinned Oh My Pi version")
    return root


def validate_ready(line: str) -> dict[str, Any]:
    """Accept only the adapter's own loopback readiness record for the expected backend."""
    try:
        ready = json.loads(line)
    except ValueError as exc:
        raise RuntimeError("Luna adapter did not report readiness") from exc
    if not isinstance(ready, dict):
        raise RuntimeError("Luna adapter did not report readiness")
    if isinstance(ready.get("error"), str):
        raise RuntimeError("Luna adapter failed to start: " + ready["error"][:200])
    port = ready.get("port")
    if (
        ready.get("adapter") != ADAPTER_ID
        or (ready.get("provider"), ready.get("model")) != BACKEND
        or ready.get("thinking") != "high"
        or type(port) is not int
        or not 1024 <= port <= 65535
    ):
        raise RuntimeError("Luna adapter reported an unexpected backend identity")
    return ready


class NativeLunaRoute:
    """Own one adapter process in its own process group and always reap it."""

    def __init__(self, *, omp: str | None = None, sdk_root: Path | None = None):
        """Resolve the SDK root and the Bun executable without starting anything."""
        self.sdk_root = sdk_root_for(omp, sdk_root)
        found = shutil.which("bun")
        if not found:
            raise RuntimeError("Gauntlet prerequisite is missing: bun")
        self.bun = Path(found).absolute()
        self._token = secrets.token_urlsafe(32)
        self.process: subprocess.Popen[str] | None = None
        self.port = 0

    def provider(self, *, max_rounds: int, timeout: float) -> dict[str, Any]:
        """Relay settings for run_suite; the identity names both the adapter and the backend."""
        return {
            "base_url": f"http://127.0.0.1:{self.port}/v1",
            "model": REQUEST_MODEL,
            "api_key": self._token,
            "identity": IDENTITY,
            "allow_loopback": True,
            "max_rounds": max_rounds,
            "timeout": timeout,
            "reasoning_effort": "high",
        }

    def __enter__(self) -> NativeLunaRoute:
        """Start the adapter and wait for its loopback readiness record."""
        environment = {key: os.environ[key] for key in _ENVIRONMENT_KEYS if key in os.environ}
        environment["GUARD_GAUNTLET_ROUTE_TOKEN"] = self._token
        self.process = subprocess.Popen(
            [str(self.bun), "run", str(ADAPTER), str(self.sdk_root)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=environment,
            cwd=self.sdk_root,
            text=True,
            start_new_session=True,
        )
        try:
            lines: queue.Queue[str] = queue.Queue()
            assert self.process.stdout is not None
            threading.Thread(target=lambda: lines.put(self.process.stdout.readline()), daemon=True).start()
            try:
                line = lines.get(timeout=STARTUP_SECONDS)
            except queue.Empty as exc:
                raise RuntimeError("Luna adapter did not start in time") from exc
            if not line:
                raise RuntimeError("Luna adapter exited before it was ready; check the Oh My Pi ChatGPT login")
            self.port = validate_ready(line)["port"]
        except BaseException:
            self.stop()
            raise
        return self

    def __exit__(self, *_args: object) -> None:
        """Stop the adapter even after a failed or cancelled run."""
        self.stop()

    def stop(self) -> None:
        """Terminate the owned process group, escalate only if it survives, and reap it."""
        process, self.process = self.process, None
        if process is None:
            return
        group = process.pid
        if process.stdin is not None:
            with suppress(OSError):
                process.stdin.close()
        with suppress(ProcessLookupError, PermissionError):
            os.killpg(group, signal.SIGTERM)
        try:
            process.wait(timeout=STOP_SECONDS)
        except subprocess.TimeoutExpired:
            with suppress(ProcessLookupError, PermissionError):
                os.killpg(group, signal.SIGKILL)
            process.wait(timeout=STOP_SECONDS)
        for stream in (process.stdin, process.stdout):
            if stream is not None:
                with suppress(OSError):
                    stream.close()
