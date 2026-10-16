"""Selection of the native runtime as a hook launcher."""

from __future__ import annotations

import sys
from pathlib import Path


def native_hook_bridge_executable(feature: str, *, guard_home: Path | None = None) -> Path | None:
    """The validated native runtime when it advertises ``feature``.

    A native hook bridge lets the harness start the compiled runtime instead
    of a Python interpreter for each hook call. A frozen build's bundled
    runtime can live in a per-launch extraction directory, so a frozen build
    names the verified copy under ``guard_home`` instead, and keeps its own
    launcher when no Guard home is given or the copy cannot be published.
    """

    frozen = bool(getattr(sys, "frozen", False))
    if frozen and guard_home is None:
        return None
    from ..native_runtime import native_runtime_status

    status = native_runtime_status()
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or feature not in status.capabilities.features
    ):
        return None
    if not frozen:
        return status.identity.path
    if guard_home is None:
        return None
    from ..native_runtime_durable import durable_hook_runtime

    return durable_hook_runtime(status.identity, guard_home)


__all__ = ["native_hook_bridge_executable"]
