"""The daemon's cross-request server state, loaded for one library call.

The native daemon owns every control route: the socket, the caller check, the
body read, the decisions and the replies. The library steps those routes run
(``connect_calls``, ``supply_chain_calls``, ``headless_calls``) read and write
state the daemon keeps on disk (the Cloud connect flow, the hook scheduler's
counters, the local CLI list); ``control_server`` loads it from the Guard home.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from ..store import GuardStore


@contextmanager
def control_server(store: GuardStore, args: Mapping[str, Any]) -> Iterator[Any]:
    """The daemon's cross-request state, loaded from the Guard home for one call."""

    from ..native_daemon_manage import load_guard_daemon_auth_token
    from .request_host import _replay_server_class

    port = args.get("port")
    home_dir = args.get("home_dir")
    server = _replay_server_class()(
        store,
        port if isinstance(port, int) else 0,
        "127.0.0.1",
        Path(home_dir) if isinstance(home_dir, str) and home_dir else Path.home(),
        load_guard_daemon_auth_token(store.guard_home) or "",
        args.get("daemon_pid") if isinstance(args.get("daemon_pid"), int) else None,
        False,
    )
    try:
        yield server
    finally:
        server.server_close()
