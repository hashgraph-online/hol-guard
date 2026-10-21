"""Constants and helpers shared by the daemon server and its control-plane modules."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import TypeGuard

_LOGGER = logging.getLogger("codex_plugin_scanner.guard.daemon.server")


_SUPPLY_CHAIN_CONNECT_POLL_AFTER_MS = 1_500


class _ServerProxy:
    """Late-bound view of ``server`` that avoids an import cycle.

    Collaborators stay owned by ``server`` so existing patches keep working.
    """

    def __getattr__(self, name: str):
        from . import server

        return getattr(server, name)


def _is_string_object_dict(value: object) -> TypeGuard[dict[str, object]]:
    return isinstance(value, dict) and all(isinstance(key, str) for key in value)


_NATIVE_HANDLER_UNAVAILABLE: tuple[int, dict[str, object]] = (503, {"error": "native_handler_policy_unavailable"})


def _build_local_url(host: str, port: int, path: str) -> str:
    host_part = f"[{host}]" if ":" in host else host
    return f"http://{host_part}:{port}{path}"


def _settings_response_payload(guard_home: Path, settings: dict[str, object]) -> dict[str, object]:
    from ..protection_capabilities import protection_capability_payloads

    return {
        "guard_home": str(guard_home),
        "config_path": str(guard_home / "config.toml"),
        "settings": settings,
        "protection_capabilities": protection_capability_payloads(),
    }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _settings_export_payload(config: object) -> dict[str, object]:
    from ..config import editable_guard_settings

    return {
        "schema_version": 1,
        "privacy_warning": "Exports include local Guard preferences but not secrets or receipt evidence.",
        "settings": editable_guard_settings(config),  # pyright: ignore[reportArgumentType]
    }
