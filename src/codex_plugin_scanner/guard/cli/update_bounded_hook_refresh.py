"""Move bounded hooks that still run a managed client script onto the native runtime."""

from __future__ import annotations

from ..harness_context import HarnessContext
from ..store import GuardStore
from .native_managed_update import native_update_repair


def refresh_bounded_hook_clients(
    *,
    context: HarnessContext,
    store: GuardStore,
    workspace: str | None,
    now: str,
) -> tuple[list[dict[str, object]], list[str]]:
    """Reinstall active hooks that still name a client script; return reinstalled installs and warnings.

    The native runtime names the harnesses whose old client is still a regular file, reinstalls each active one
    under its own installation transaction and removes each client once its install has moved.
    """

    return native_update_repair("bounded", context=context, store=store, workspace=workspace, now=now)


__all__ = ["refresh_bounded_hook_clients"]
