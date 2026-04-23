"""Guard daemon helpers."""

from __future__ import annotations

from .manager import ensure_guard_daemon, guard_daemon_url_for_home, load_guard_daemon_auth_token, load_guard_daemon_url

__all__ = [
    "GuardDaemonServer",
    "GuardSurfaceDaemonClient",
    "ensure_guard_daemon",
    "guard_daemon_url_for_home",
    "load_guard_daemon_auth_token",
    "load_guard_daemon_url",
    "load_guard_surface_daemon_client",
]


def __getattr__(name: str):
    if name == "GuardDaemonServer":
        from .server import GuardDaemonServer

        return GuardDaemonServer
    if name in {"GuardSurfaceDaemonClient", "load_guard_surface_daemon_client"}:
        from .client import GuardSurfaceDaemonClient, load_guard_surface_daemon_client

        return {
            "GuardSurfaceDaemonClient": GuardSurfaceDaemonClient,
            "load_guard_surface_daemon_client": load_guard_surface_daemon_client,
        }[name]
    raise AttributeError(name)
