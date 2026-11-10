"""The handshake that lets the daemon's native edge answer store reads.

The daemon sends this line on the edge's liveness socket. It names the auth
token and store the edge needs to answer token-authenticated reads, and the
edge reports each burst of answered requests back so the daemon's idle timer
and runtime heartbeat still count them.
"""

from __future__ import annotations

import json
import os
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..config_mutation import notify_native_policy_mutation
from ..native_approval_gate import session_signals
from ..sqlite_tuning import sqlite_connect_timeout_seconds
from .dashboard_bundle import dashboard_build_id
from .server_common import _now

HANDSHAKE_SCHEMA = "guard-daemon-edge-handshake.v1"
_MAX_BUSY_TIMEOUT_MS = 60_000


def edge_handshake(
    *,
    auth_token: str,
    guard_home: Path,
    store_path: Path,
    source: str,
    busy_timeout_seconds: float,
    dashboard_build: str | None,
    user_home: str | None = None,
    session_signals: list[str] | None = None,
    daemon_fingerprint: str | None = None,
    cli_command: list[str] | None = None,
    dashboard_dir: Path | None = None,
) -> bytes:
    """The line that lets the edge answer token-authenticated store reads."""

    payload: dict[str, object] = {
        "schema": HANDSHAKE_SCHEMA,
        "auth_token": auth_token,
        "guard_home": os.path.abspath(guard_home),
        "store_path": os.path.abspath(store_path),
        "source": source,
        "busy_timeout_ms": max(1, min(_MAX_BUSY_TIMEOUT_MS, int(busy_timeout_seconds * 1000))),
        # Store reads resolve a relative config path from the daemon's working
        # directory; the edge runs from its own.
        "cwd": os.getcwd(),
    }
    if dashboard_build is not None:
        payload["dashboard_build"] = dashboard_build
    if dashboard_dir is not None:
        # The edge serves the dashboard shell and bundled files from here.
        payload["dashboard_dir"] = str(Path(dashboard_dir).resolve())
    if user_home is not None:
        # Evidence reads shorten this home to ``~`` as ``redact_local_path`` does.
        payload["user_home"] = user_home
    if session_signals:
        # The edge runs in a session of its own; approval-gate checks it sends
        # must carry the daemon's session, as the daemon's own checks do.
        payload["session_signals"] = session_signals
    if daemon_fingerprint is not None:
        # Containment health evidence is bound to the daemon's runtime identity.
        payload["daemon_fingerprint"] = daemon_fingerprint
    if cli_command:
        # Answers that depend on how Guard was installed come from this CLI.
        payload["cli_command"] = cli_command
    return json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n"


def daemon_edge_callbacks(server: Any, static_dir: Path) -> tuple[Callable[[], bytes], Callable[[bytes], None]]:
    """The handshake builder and activity callback for ``server``'s edge."""

    def handshake() -> bytes:
        store = server.store
        return edge_handshake(
            auth_token=server.auth_token,
            guard_home=store.guard_home,
            store_path=store.path,
            source=store.guard_source,
            busy_timeout_seconds=sqlite_connect_timeout_seconds(),
            dashboard_build=dashboard_build_id(static_dir),
            user_home=_user_home(),
            session_signals=session_signals(),
            daemon_fingerprint=_daemon_fingerprint(),
            cli_command=guard_cli_command(),
            dashboard_dir=static_dir,
        )

    def on_activity(kinds: bytes = b"a") -> None:
        # The edge answered a request itself; count it as the request handler
        # would have.
        server.last_activity_monotonic = time.monotonic()
        server.runtime_heartbeat.touch(_now())
        if b"p" in kinds:
            # An edge write changed Guard's policy inputs; republish the
            # native policy snapshot as the daemon's own writes do.
            notify_native_policy_mutation(server.store.guard_home)

    return handshake, on_activity


def guard_cli_command() -> list[str]:
    """The argv prefix that runs this Guard's own CLI."""

    if getattr(sys, "frozen", False):
        return [sys.executable]
    from ..codex_hook_launch_runtime import isolated_guard_cli_command

    package_root = Path(__file__).resolve().parents[3]
    return list(isolated_guard_cli_command(sys.executable, package_root, ("guard",)))


def _user_home() -> str | None:
    try:
        return str(Path.home())
    except RuntimeError:
        return None


__all__ = ["HANDSHAKE_SCHEMA", "daemon_edge_callbacks", "edge_handshake"]


def _daemon_fingerprint() -> str | None:
    """The daemon's runtime identity, or ``None`` when the runtime cannot name it.

    Without it the edge leaves containment health to the daemon.
    """

    from .manager import current_guard_daemon_runtime_fingerprint

    try:
        return current_guard_daemon_runtime_fingerprint()
    except RuntimeError:
        return None
