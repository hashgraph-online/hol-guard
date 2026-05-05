"""Guard runtime helpers."""

from __future__ import annotations

from importlib import import_module

__all__ = [
    "GuardSyncNotAvailableError",
    "GuardSyncNotConfiguredError",
    "guard_run",
    "sync_guard_events",
    "sync_receipts",
    "sync_runtime_session",
]


def __getattr__(name: str) -> object:
    if name not in __all__:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    runner = import_module(".runner", __name__)
    value = getattr(runner, name)
    globals()[name] = value
    return value
