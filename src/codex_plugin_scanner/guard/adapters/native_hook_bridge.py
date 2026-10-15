"""Selection of the native runtime as a hook launcher."""

from __future__ import annotations

import sys
from pathlib import Path


def native_hook_bridge_executable(feature: str) -> Path | None:
    """The validated native runtime when it advertises ``feature``.

    A native hook bridge lets the harness start the compiled runtime instead
    of a Python interpreter for each hook call. Frozen builds keep their
    Python launchers.
    """

    if getattr(sys, "frozen", False):
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
    return status.identity.path


__all__ = ["native_hook_bridge_executable"]
