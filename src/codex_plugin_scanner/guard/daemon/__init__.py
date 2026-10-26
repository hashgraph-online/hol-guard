"""Guard daemon helpers."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .runtime_repair import repair_guard_daemon_runtime

__all__ = [
    "GuardDaemonServer",
    "GuardSurfaceDaemonClient",
    "ensure_guard_daemon",
    "guard_daemon_url_for_home",
    "load_guard_daemon_auth_token",
    "load_guard_daemon_url",
    "load_guard_surface_daemon_client",
    "recover_guard_daemon_after_hook_failure",
    "repair_approval_center_locator",
    "repair_guard_daemon_runtime",
    "schedule_guard_daemon_recovery",
]


def __getattr__(name: str) -> Any:
    if name == "repair_guard_daemon_runtime":
        from .runtime_repair import repair_guard_daemon_runtime

        globals()[name] = repair_guard_daemon_runtime
        return repair_guard_daemon_runtime
    if name == "GuardDaemonServer":
        from .server import GuardDaemonServer

        return GuardDaemonServer
    if name in {"GuardSurfaceDaemonClient", "load_guard_surface_daemon_client"}:
        from .client import GuardSurfaceDaemonClient, load_guard_surface_daemon_client

        return {
            "GuardSurfaceDaemonClient": GuardSurfaceDaemonClient,
            "load_guard_surface_daemon_client": load_guard_surface_daemon_client,
        }[name]
    if name in __all__:
        value = getattr(import_module(".manager", __name__), name)
        globals()[name] = value
        return value
    raise AttributeError(name)
