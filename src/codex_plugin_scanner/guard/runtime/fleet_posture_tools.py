"""Machine, client and AI-tool sections of ``fleet-posture/v1``."""

from __future__ import annotations

import logging
import platform
from collections.abc import Mapping
from datetime import datetime
from typing import TYPE_CHECKING, Any

from ...version import __version__
from ..harness_tool_version import tool_version_from_artifacts
from .fleet_posture_common import DIAGNOSTICS_STATE_KEY, clip, iso, keyed_digest, parse_timestamp

if TYPE_CHECKING:
    from ..config import GuardConfig
    from ..store import GuardStore

AUTO_UPDATE_STATE_KEY = "guard_auto_update_state"
DIAGNOSTICS_TTL_SECONDS = 600

_LOGGER = logging.getLogger(__name__)

_SETUP_STATUSES = frozenset({"active", "broken", "partial", "not_found"})


def _os_name() -> str:
    return {"darwin": "macos", "linux": "linux", "windows": "windows"}.get(platform.system().lower(), "unknown")


def _os_version(os_name: str) -> str | None:
    version: str | None = None
    if os_name == "macos":
        version = platform.mac_ver()[0] or None
    elif os_name == "linux":
        try:
            with open("/etc/os-release", encoding="utf-8") as handle:
                for line in handle:
                    if line.startswith("VERSION_ID="):
                        version = line.split("=", 1)[1].strip().strip("\"'") or None
                        break
        except OSError:
            version = None
    elif os_name == "windows":
        version = platform.version() or None
    return clip(version, 32) if version else None


def _arch() -> str:
    machine = platform.machine().lower()
    if machine in {"arm64", "aarch64"}:
        return "arm64"
    if machine in {"x86_64", "amd64", "x64"}:
        return "x86_64"
    return "unknown"


def device_display_name(store: GuardStore, label: str) -> str:
    """The machine name Guard Cloud shows; see ``GuardStore.device_display_name``."""

    return store.device_display_name(label)


def machine_section(*, include_os_version: bool, hash_key: bytes) -> dict[str, object]:
    os_name = _os_name()
    hostname = platform.node().strip().lower()
    return {
        "osName": os_name,
        "osVersion": _os_version(os_name) if include_os_version else None,
        "arch": _arch(),
        "hostnameHash": keyed_digest(hash_key, hostname) if hostname else None,
    }


def client_facts(store: GuardStore, runtime: str) -> dict[str, object]:
    """What the native build turns into the client section: version, runtime and auto-update state."""

    return {
        "version": __version__,
        "runtime": runtime,
        "autoUpdateState": store.get_sync_payload(AUTO_UPDATE_STATE_KEY),
    }


# --------------------------------------------------------------------------- AI tools


def _effectively_paused(config: GuardConfig | None, harness: str) -> bool:
    if config is None:
        return False
    from ..harness_posture import effective_harness_posture

    try:
        return effective_harness_posture(config, harness) == "watch"
    except (AttributeError, TypeError):  # pragma: no cover - config shape is owned elsewhere
        return False


def _latest_activity(store: GuardStore, harness: str) -> str | None:
    try:
        rows = store.list_receipts(limit=1, harness=harness)
    except Exception:
        _LOGGER.debug("fleet posture: receipt lookup failed for %s", harness, exc_info=True)
        return None
    timestamp = rows[0].get("timestamp") if rows else None
    return timestamp if isinstance(timestamp, str) else None


def _coverage(adapter: Any) -> dict[str, object]:
    try:
        coverage = adapter.setup_contract().coverage
    except Exception:
        return {}
    return {
        "nativeHooks": bool(getattr(coverage, "native_hooks", False)),
        "browserFallback": bool(getattr(coverage, "browser_fallback", False)),
        "mcpProxy": bool(getattr(coverage, "mcp_proxy", False)),
        "promptHooks": bool(getattr(coverage, "prompt_hooks", False)),
        "blindSpots": [str(item) for item in getattr(coverage, "blind_spots", ()) if str(item).strip()],
    }


def tool_row(
    *,
    adapter: Any,
    diagnostics: Mapping[str, object],
    store: GuardStore,
    config: GuardConfig | None,
) -> dict[str, object]:
    """One AI tool's collected facts; the native build derives its protection state and shapes its row."""
    harness = str(adapter.harness)
    override: str | None = None
    if config is not None:
        from ..harness_posture import harness_posture_override

        override = harness_posture_override(config, harness)
    return {
        "harness": harness,
        "setupStatus": str(diagnostics.get("setup_status")),
        "hasConfigPaths": diagnostics.get("has_config_paths") is True,
        "toolVersion": diagnostics.get("tool_version"),
        "coverage": _coverage(adapter),
        "lastActivityAt": _latest_activity(store, harness),
        "paused": _effectively_paused(config, harness),
        "configured": config is not None,
        "override": override,
    }


# --------------------------------------------------------------------------- diagnostics cache


def _summarize_diagnostics(diagnostics: Mapping[str, object]) -> dict[str, object] | None:
    status = diagnostics.get("setup_status")
    if status not in _SETUP_STATUSES:
        return None
    artifacts = diagnostics.get("artifacts")
    return {
        "setup_status": status,
        "has_config_paths": bool(diagnostics.get("config_paths")),
        "tool_version": tool_version_from_artifacts(artifacts if isinstance(artifacts, list) else ()),
    }


class DiagnosticsCache:
    """Short-lived cache of per-tool diagnostics.

    ``adapter.diagnostics`` can launch the tool's CLI to probe it, which is too slow
    to repeat on every receipt sync (and again on the policy follow-up).
    """

    def __init__(self, store: GuardStore, *, now: datetime, ttl_seconds: int = DIAGNOSTICS_TTL_SECONDS) -> None:
        self._store = store
        self._now = now
        self._ttl = ttl_seconds
        raw = store.get_sync_payload(DIAGNOSTICS_STATE_KEY) if ttl_seconds > 0 else None
        self._entries: dict[str, Any] = dict(raw) if isinstance(raw, dict) else {}
        self._dirty = False

    def lookup(self, adapter: Any, context: Any) -> dict[str, object] | None:
        harness = str(adapter.harness)
        entry = self._entries.get(harness)
        if isinstance(entry, dict) and isinstance(entry.get("diagnostics"), dict):
            fetched = parse_timestamp(entry.get("at"))
            if fetched is not None and 0 <= (self._now - fetched).total_seconds() < self._ttl:
                return entry["diagnostics"]
        try:
            diagnostics = adapter.diagnostics(context)
        except Exception:
            _LOGGER.debug("fleet posture: diagnostics failed for %s", harness, exc_info=True)
            return None
        summary = _summarize_diagnostics(diagnostics) if isinstance(diagnostics, Mapping) else None
        if summary is not None and self._ttl > 0:
            self._entries[harness] = {"at": iso(self._now), "diagnostics": summary}
            self._dirty = True
        return summary

    def save(self) -> None:
        if not self._dirty:
            return
        try:
            self._store.set_sync_payload(DIAGNOSTICS_STATE_KEY, self._entries, iso(self._now))
        except Exception:
            _LOGGER.debug("fleet posture: diagnostics cache could not be saved", exc_info=True)
