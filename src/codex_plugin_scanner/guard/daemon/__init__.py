"""Guard daemon helpers."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .manager import (
        ensure_guard_daemon,
        guard_daemon_url_for_home,
        load_guard_daemon_auth_token,
        load_guard_daemon_url,
        recover_guard_daemon_after_hook_failure,
        repair_approval_center_locator,
        schedule_guard_daemon_recovery,
    )
    from .runtime_repair import repair_guard_daemon_runtime

_MANAGER_EXPORTS = frozenset(
    {
        "ensure_guard_daemon",
        "guard_daemon_url_for_home",
        "load_guard_daemon_auth_token",
        "load_guard_daemon_url",
        "recover_guard_daemon_after_hook_failure",
        "repair_approval_center_locator",
        "schedule_guard_daemon_recovery",
    }
)

# Reload used to rebind these eager imports, including any patched export.
for _name in _MANAGER_EXPORTS:
    globals().pop(_name, None)
globals().pop("_name", None)

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


def __getattr__(name: str):
    if name in _MANAGER_EXPORTS:
        from . import manager

        value = getattr(manager, name)
        globals()[name] = value
        return value
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
    raise AttributeError(name)


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
