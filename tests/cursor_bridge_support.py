"""Run a managed Cursor hook as Cursor does: behind the native bridge, with a live daemon."""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path

from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore


@contextmanager
def live_cursor_daemon(guard_home: Path) -> Iterator[None]:
    """Serve the loopback daemon the bridge asks when no resident answers."""

    daemon = GuardDaemonServer(GuardStore(guard_home), host="127.0.0.1", port=0)
    daemon.start()
    try:
        yield
    finally:
        daemon.stop()


def run_cursor_hook(
    runtime: Path,
    hook_script: Path,
    payload: Mapping[str, object],
    *,
    env: Mapping[str, str],
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run ``hook_script`` behind the native bridge for the payload's hook event."""

    event = str(payload.get("hook_event_name") or "")
    return subprocess.run(
        [str(runtime), "cursor-hook-bridge", sys.executable, "-I", str(hook_script), "--cursor-hook-event", event],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        cwd=cwd,
        env=dict(env),
        timeout=60,
        check=False,
    )
