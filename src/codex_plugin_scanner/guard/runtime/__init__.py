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
    module_name = ".wrapper_run" if name == "guard_run" else ".runner"
    owner = import_module(module_name, __name__)
    if not hasattr(owner, name):
        raise AttributeError(f"module {__name__!r} exports {name!r}, but {module_name[1:]} does not define it")
    value = getattr(owner, name)
    globals()[name] = value
    return value
