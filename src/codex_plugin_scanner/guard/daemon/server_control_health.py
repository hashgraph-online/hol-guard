"""Capability, health and catalog route handlers for the daemon control plane."""

# pyright: reportAttributeAccessIssue=false, reportUnknownMemberType=false

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import TYPE_CHECKING
from urllib.parse import parse_qs

from .manager import (
    current_guard_daemon_runtime_fingerprint,
)
from .server_common import (
    _build_local_url,
)

if TYPE_CHECKING:
    from .server import _GuardDaemonHTTPServer as _GuardDaemonHttpServer


_HEADLESS_OPERATIONS = ("install", "repair", "remove", "status", "scan", "policy_sync")


def _headless_safe_failure_reasons() -> dict[str, str]:
    return {
        "offline": "Local Guard daemon is unavailable.",
        "timeout": "Local Guard daemon did not answer before the browser timeout.",
        "unauthorized": "Dashboard session is missing or stale.",
        "unsupported": "Harness is not supported by this daemon.",
        "confirmation_required": "Remove actions need the harness confirmation phrase.",
    }


_CONTAINMENT_HEALTH_CACHE_SECONDS = 10.0


def cached_containment_health(
    server: _GuardDaemonHttpServer,
    *,
    force_refresh: bool,
    probe: Callable[[], dict[str, object]],
) -> dict[str, object] | None:
    """Return containment health without holding the cache lock across the probe.

    A fresh cache is shared. When the cache is due, one caller runs the probe
    and everyone else keeps the previous payload. Callers only wait together
    when no payload exists yet.
    """

    arrived_generation: int | None = None
    probe_generation = 0
    while True:
        with server.containment_health_cache_lock:
            if arrived_generation is None:
                arrived_generation = server.containment_health_generation
            cached = server.containment_health_cache
            age = time.monotonic() - server.containment_health_cache_monotonic
            if cached is not None and age <= _CONTAINMENT_HEALTH_CACHE_SECONDS and not force_refresh:
                return dict(cached)
            if server.containment_health_refreshing:
                if cached is not None and not force_refresh:
                    return dict(cached)
                event = server.containment_health_refresh_event
                run_probe = False
            else:
                event = threading.Event()
                server.containment_health_refresh_event = event
                server.containment_health_refreshing = True
                server.containment_health_generation += 1
                probe_generation = server.containment_health_generation
                run_probe = True
        if not run_probe:
            event.wait()
            with server.containment_health_cache_lock:
                done = server.containment_health_completed_generation
                if force_refresh and arrived_generation is not None and done <= arrived_generation:
                    continue
                return None if server.containment_health_cache is None else dict(server.containment_health_cache)
        break
    payload: dict[str, object] | None = None
    failed = False
    try:
        payload = probe()
    except (OSError, RuntimeError, TypeError, ValueError):
        payload = None
        failed = True
    except BaseException:
        failed = True
        raise
    finally:
        with server.containment_health_cache_lock:
            if failed or payload is not None:
                server.containment_health_cache = None if payload is None else dict(payload)
                server.containment_health_cache_monotonic = time.monotonic()
            server.containment_health_refreshing = False
            server.containment_health_completed_generation = probe_generation
            event.set()
    return None if payload is None else dict(payload)


class _ControlHealthRoutes:
    """Handler methods for control-plane routes."""

    def _local_queue_url(self) -> str:
        host = self._daemon_server().daemon_host()
        port = self._daemon_server().daemon_port()
        return _build_local_url(host, port, "/#/inbox")

    @staticmethod
    def _optional_bool(value: object, *, default: bool) -> bool:
        if value is None:
            return default
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"true", "1", "yes", "on"}:
                return True
            if normalized in {"false", "0", "no", "off", ""}:
                return False
        raise ValueError("invalid boolean value")

    @staticmethod
    def _optional_int(value: object) -> int | None:
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.strip():
            try:
                return int(value.strip())
            except ValueError:
                return None
        return None

    def _containment_health_payload(self, *, force_refresh: bool = False) -> dict[str, object] | None:
        from ..runtime.containment_health import probe_containment_health

        daemon_server = self._daemon_server()

        def probe() -> dict[str, object]:
            return probe_containment_health(
                daemon_fingerprint=current_guard_daemon_runtime_fingerprint(),
                guard_home=daemon_server.store.guard_home,
            ).to_dict()

        return cached_containment_health(daemon_server, force_refresh=force_refresh, probe=probe)

    def _coalesce_string(self, mapping: dict[str, object], *keys: str) -> str | None:
        for key in keys:
            value = self._optional_string(mapping.get(key))
            if value is not None:
                return value
        return None

    @staticmethod
    def _query_string(query_string: str, key: str) -> str | None:
        value = parse_qs(query_string).get(key, [None])[-1]
        if isinstance(value, str) and value.strip():
            return value.strip()
        return None

    @staticmethod
    def _query_bool(query_string: str, key: str, *, default: bool) -> bool:
        value = parse_qs(query_string).get(key, [None])[-1]
        if not isinstance(value, str):
            return default
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
        return default

    def write_catalog_v2_body(self, body: bytes, *, status: int, headers: dict[str, str]) -> None:
        self._write_json_bytes(body, status=status, extra_headers=headers)

    def write_catalog_v2_empty(self, *, status: int, headers: dict[str, str]) -> None:
        cors_headers = self._cors_headers_for_request(allow_methods="GET, POST, OPTIONS") or {}
        self._write_empty(status=status, extra_headers={**cors_headers, **headers})

    def write_catalog_v2_error(self, error_code: str, *, status: int) -> None:
        self._write_json({"error": error_code}, status=status, extra_headers={"Cache-Control": "no-store"})
