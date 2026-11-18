"""Move bounded hooks that still run a managed client script onto the native runtime."""

from __future__ import annotations

import json
import sqlite3

from ..harness.base import HarnessContext
from ..harness.native_harness import ask
from ..store import GuardStore


def refresh_bounded_hook_clients(
    *,
    context: HarnessContext,
    store: GuardStore,
    workspace: str | None,
    now: str,
) -> tuple[list[dict[str, object]], list[str]]:
    """Reinstall active hooks that still name a client script; return reinstalled installs and warnings.

    The native runtime names the harnesses whose old client is still a regular
    file and removes each client once its install has moved.
    """

    from .install_commands import apply_managed_install
    from .managed_install_context import managed_install_context

    refreshed: list[dict[str, object]] = []
    warnings: list[str] = []
    try:
        scripts = ask("bounded_hook_scripts", context)["scripts"]
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as error:
        # An unavailable, old or slow resident must not stop the repairs after this one.
        return refreshed, [f"Could not check bounded hook clients for the native runtime during update: {error}"]
    for script in scripts:
        harness = str(script["harness"])
        display_name = str(script["display_name"])
        try:
            managed_install = store.get_managed_install(harness)
        except (json.JSONDecodeError, sqlite3.Error):
            continue
        if managed_install is None or not bool(managed_install.get("active")):
            continue
        try:
            repair_context, repair_workspace = managed_install_context(context, managed_install)
            payload = apply_managed_install(
                "install", harness, False, repair_context, store, repair_workspace or workspace, now
            )
            ask("remove_bounded_hook_script", context, harness=harness)
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError, sqlite3.Error) as error:
            warnings.append(f"Could not move {display_name} hooks to the native runtime during update: {error}")
            continue
        repaired = payload.get("managed_install")
        refreshed.append(dict(repaired) if isinstance(repaired, dict) else dict(managed_install))
    return refreshed, warnings


__all__ = ["refresh_bounded_hook_clients"]
