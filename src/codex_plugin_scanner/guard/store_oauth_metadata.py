"""Non-secret OAuth metadata projection helpers."""

from __future__ import annotations

_OAUTH_BINDING_KEYS = (
    "grant_id",
    "machine_id",
    "device_id",
    "workspace_id",
    "runtime_id",
    "runtime_label",
)


def copy_oauth_binding_metadata(source: dict[str, object], target: dict[str, object]) -> None:
    for key in _OAUTH_BINDING_KEYS:
        value = source.get(key)
        if isinstance(value, str) and value:
            target[key] = value


__all__ = ["copy_oauth_binding_metadata"]
