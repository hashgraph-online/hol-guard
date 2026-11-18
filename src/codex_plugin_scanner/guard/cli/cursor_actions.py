"""Cursor local action payloads.

The native ``harness_adapter`` cursor ops own which surfaces exist, which are
detected, which Guard protects and the payload that reports them. These helpers
only name the context and pass the store's home and managed-install rows in.
"""

from __future__ import annotations

from typing import Any

from ..harness_context import HarnessContext
from ..native_harness_client import ask
from ..store import GuardStore


def _cursor_ask(op: str, context: HarnessContext, **fields: Any) -> dict[str, Any]:
    return ask(op, context, harness="cursor", **fields)


def _surfaces(answer: dict[str, Any]) -> tuple[str, ...]:
    surfaces = answer.get("surfaces")
    if not isinstance(surfaces, list) or not all(isinstance(surface, str) for surface in surfaces):
        raise ValueError("Harness adapter answer is malformed")
    return tuple(surfaces)


def cursor_local_action_payload(
    *,
    action: str,
    surface: str | None,
    context: HarnessContext,
    protected: bool | None = None,
    protected_surfaces: tuple[str, ...] = (),
) -> dict[str, object]:
    return _cursor_ask(
        "local_action",
        context,
        action=action,
        surface=surface,
        protected=protected,
        protected_surfaces=list(protected_surfaces),
    )


def cursor_install_surface(surface: str | None, context: HarnessContext) -> str:
    return str(_cursor_ask("install_surface", context, surface=surface)["surface"])


def cursor_protected_surfaces(
    managed_installs: list[dict[str, object]],
    context: HarnessContext,
) -> tuple[str, ...]:
    return _surfaces(_cursor_ask("protected_surfaces", context, managed_installs=managed_installs))


def cursor_protected_surfaces_from_store(
    store: GuardStore | None,
    detection: dict[str, object],
    context: HarnessContext,
) -> tuple[str, ...]:
    """The surfaces Guard protects; the runtime reads Cursor's record from the caller's store itself."""
    return _surfaces(
        _cursor_ask(
            "protected_surfaces_from_store",
            context,
            installed=bool(detection["installed"]),
            store_home=None if store is None else str(store.guard_home),
        )
    )
