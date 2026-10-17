"""Machine, client and AI-tool sections of ``fleet-posture/v1``."""

from __future__ import annotations

import logging
import platform
import re
from collections.abc import Mapping
from datetime import datetime
from typing import TYPE_CHECKING, Any

from ...version import __version__
from ..harness_tool_version import tool_version_from_artifacts
from .fleet_posture_common import (
    DIAGNOSTICS_STATE_KEY,
    MAX_BLIND_SPOT_LENGTH,
    MAX_BLIND_SPOTS,
    STALE_AFTER,
    clip,
    iso,
    keyed_digest,
    normalized_timestamp,
    parse_timestamp,
)
from .fleet_posture_inventory import item_digest

if TYPE_CHECKING:
    from ..config import GuardConfig
    from ..store import GuardStore

AUTO_UPDATE_STATE_KEY = "guard_auto_update_state"
DIAGNOSTICS_TTL_SECONDS = 600

_LOGGER = logging.getLogger(__name__)

_SETUP_STATUSES = frozenset({"active", "broken", "partial", "not_found"})
_VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z.+-]*$")
_PRERELEASE_PATTERN = re.compile(r"[0-9](a|b|rc|dev|alpha|beta)[0-9]*", re.IGNORECASE)


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


def machine_section(*, include_os_version: bool, hash_key: bytes) -> dict[str, object]:
    os_name = _os_name()
    hostname = platform.node().strip().lower()
    return {
        "osName": os_name,
        "osVersion": _os_version(os_name) if include_os_version else None,
        "arch": _arch(),
        "hostnameHash": keyed_digest(hash_key, hostname) if hostname else None,
    }


def _auto_update_state(store: GuardStore) -> tuple[dict[str, object], str | None]:
    raw = store.get_sync_payload(AUTO_UPDATE_STATE_KEY)
    state: dict[str, Any] = raw if isinstance(raw, dict) else {}
    last_status = state.get("last_status")
    status: dict[str, Any] = last_status if isinstance(last_status, dict) else {}
    channel = status.get("release_channel")
    last_checked = normalized_timestamp(state.get("last_check_at"))
    result: str | None = None
    if status:
        last_update_at = parse_timestamp(state.get("last_update_at"))
        checked_at = parse_timestamp(state.get("last_check_at"))
        # An update is only attempted when the check found one and nothing blocked it.
        attempted = (
            status.get("update_available") is True
            and bool(status.get("auto_updatable"))
            and not status.get("blocked_reason")
        )
        ran_this_cycle = last_update_at is not None and checked_at is not None and last_update_at >= checked_at
        if attempted and ran_this_cycle and state.get("last_update_exit_code") == 0:
            result = "updated"
        elif attempted and (
            (ran_this_cycle and state.get("last_update_exit_code") != 0)
            or (not ran_this_cycle and state.get("last_update_error") is True)
        ):
            result = "failed"
        elif status.get("update_available") is True:
            result = "update_available"
        else:
            result = "up_to_date"
    elif state.get("last_check_error") is True or state.get("last_update_error") is True:
        result = "failed"
    section: dict[str, object] = {
        "enabled": bool(status.get("auto_updatable")) if status else False,
        "lastCheckedAt": last_checked,
        "lastResult": result,
    }
    return section, channel if channel in {"stable", "alpha"} else None


def client_section(store: GuardStore, runtime: str) -> dict[str, object]:
    auto_update, stored_channel = _auto_update_state(store)
    channel = stored_channel or ("alpha" if _PRERELEASE_PATTERN.search(__version__) else "stable")
    version = __version__ if _VERSION_PATTERN.match(__version__) else "0.0.0"
    return {
        "version": clip(version, 32),
        "channel": channel,
        "runtime": runtime if runtime in {"python", "native"} else "python",
        "autoUpdate": auto_update,
    }


# --------------------------------------------------------------------------- AI tools


def _posture_override(config: GuardConfig | None, harness: str) -> str | None:
    """Map Guard's per-app posture to the contract's override vocabulary.

    Guard's "watch" posture records but never blocks, which is protection off, so
    it is reported as ``off``. ``observe`` is reserved and never emitted.
    """

    if config is None:
        return None
    from ..harness_posture import harness_posture_override

    override = harness_posture_override(config, harness)
    if override is None:
        return "default"
    return "off" if override == "watch" else "enforce"


def _effectively_paused(config: GuardConfig | None, harness: str) -> bool:
    if config is None:
        return False
    from ..harness_posture import effective_harness_posture

    try:
        return effective_harness_posture(config, harness) == "watch"
    except Exception:  # pragma: no cover - defensive, config shape is owned elsewhere
        return False


def derive_protection_state(
    *,
    setup_status: str,
    has_config_paths: bool,
    paused: bool,
    last_activity_at: datetime | None,
    now: datetime,
) -> str:
    """Per-tool protection state (see docs/guard/fleet-posture.md)."""

    if setup_status == "not_found":
        return "needs_setup" if has_config_paths else "not_detected"
    if setup_status == "partial":
        # Adapters report ``partial`` for a tool that is installed but not managed by Guard.
        return "needs_setup"
    if setup_status == "broken":
        return "broken"
    if paused:
        return "paused"
    # A freshly protected tool has no receipts yet; only old activity is stale.
    if last_activity_at is not None and now - last_activity_at > STALE_AFTER:
        return "stale"
    return "protected"


def _latest_activity(store: GuardStore, harness: str) -> datetime | None:
    try:
        rows = store.list_receipts(limit=1, harness=harness)
    except Exception:
        _LOGGER.debug("fleet posture: receipt lookup failed for %s", harness, exc_info=True)
        return None
    if not rows:
        return None
    return parse_timestamp(rows[0].get("timestamp"))


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
    now: datetime,
    include_blind_spots: bool,
    inventory: Mapping[str, list[dict[str, object]]],
) -> dict[str, object]:
    harness = str(adapter.harness)
    setup_status = str(diagnostics.get("setup_status"))
    coverage = _coverage(adapter)
    last_activity = _latest_activity(store, harness)
    items = inventory.get(harness, [])
    blind_spots: list[str] = []
    if include_blind_spots:
        raw_spots = coverage.get("blindSpots")
        spot_list = list(raw_spots) if isinstance(raw_spots, (list, tuple)) else []
        blind_spots = [clip(str(spot), MAX_BLIND_SPOT_LENGTH) for spot in spot_list[:MAX_BLIND_SPOTS]]
    version = diagnostics.get("tool_version")
    return {
        "harness": harness,
        "toolVersion": version if isinstance(version, str) else None,
        "setupStatus": setup_status,
        "protectionState": derive_protection_state(
            setup_status=setup_status,
            has_config_paths=diagnostics.get("has_config_paths") is True,
            paused=_effectively_paused(config, harness),
            last_activity_at=last_activity,
            now=now,
        ),
        "hooks": {
            "nativeHooks": bool(coverage.get("nativeHooks", False)),
            "browserFallback": bool(coverage.get("browserFallback", False)),
            "mcpProxy": bool(coverage.get("mcpProxy", False)),
            "promptHooks": bool(coverage.get("promptHooks", False)),
        },
        "blindSpots": blind_spots,
        "postureOverride": _posture_override(config, harness),
        "artifactCount": min(len(items), 100000),
        "lastActivityAt": iso(last_activity) if last_activity is not None else None,
        "inventoryDigest": item_digest(items),
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
