"""HTTP helpers for custom-extension listing."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Protocol
from urllib.parse import parse_qs

from .background_diagnostics import failure_detail, record_background_event
from .local_cli_api import LocalCliApiError

_IDENTITY_HASH = re.compile(r"[0-9a-f]{64}")

_RECOGNIZE_SOCKET_TIMEOUT_SECONDS = 30.0


class _LocalCliPostApi(Protocol):
    def apply(self, payload: dict[str, object]) -> dict[str, object]: ...
    def discover_items(self) -> dict[str, object]: ...
    def forget(self, payload: dict[str, object]) -> dict[str, object]: ...
    def preview(self, payload: dict[str, object]) -> dict[str, object]: ...
    def recognize(self, payload: dict[str, object]) -> dict[str, object]: ...
    def provider_actions(self, payload: dict[str, object]) -> dict[str, object]: ...
    def provider_workflows(self, payload: dict[str, object]) -> dict[str, object]: ...
    def registry_search(self, payload: dict[str, object]) -> dict[str, object]: ...
    def registry_setup(self, payload: dict[str, object]) -> dict[str, object]: ...
    def refresh_job(self, payload: dict[str, object]) -> dict[str, object]: ...
    def skills(self, payload: dict[str, object]) -> dict[str, object]: ...
    def mcp_skills(self, payload: dict[str, object]) -> dict[str, object]: ...


def dispatch_local_cli_post(api: _LocalCliPostApi, path: str, payload: dict[str, object]) -> dict[str, object]:
    if path.endswith("/preview"):
        return api.preview(payload)
    if path.endswith("/recognize"):
        return api.recognize(payload)
    if path.endswith("/discover"):
        return api.discover_items()
    if path.endswith("/forget"):
        return api.forget(payload)
    if path.endswith("/provider-actions"):
        return api.provider_actions(payload)
    if path.endswith("/provider-workflows"):
        return api.provider_workflows(payload)
    if path.endswith("/registry-search"):
        return api.registry_search(payload)
    if path.endswith("/registry-setup"):
        return api.registry_setup(payload)
    if path.endswith("/refresh-job"):
        return api.refresh_job(payload)
    if path.endswith("/mcp-skills"):
        return api.mcp_skills(payload)
    if path.endswith("/skills"):
        return api.skills(payload)
    return api.apply(payload)


def handle_local_cli_post(handler: object, path: str, payload: dict[str, object]) -> None:
    daemon_server = getattr(handler, "_daemon_server", None)
    write_json = getattr(handler, "_write_json", None)
    if not callable(daemon_server) or not callable(write_json):
        return
    if path.endswith("/recognize"):
        settimeout = getattr(getattr(handler, "connection", None), "settimeout", None)
        if callable(settimeout):
            settimeout(_RECOGNIZE_SOCKET_TIMEOUT_SECONDS)
    daemon = daemon_server()
    api = getattr(daemon, "local_cli_api", None)
    if api is None:
        _write_unavailable(write_json)
        return
    try:
        response = dispatch_local_cli_post(api, path, payload)
    except LocalCliApiError as error:
        write_json(error.to_payload(), status=error.status)
        return
    except Exception as error:
        # An unhandled failure here used to abandon the request, so the page
        # saw a dropped connection and daemon.log held nothing. Name the route
        # and the exception class, then answer a reply the page can explain.
        record_background_event(
            "local_cli_post_failed",
            f"route={path.rsplit('/', 1)[-1]} {failure_detail(error)}",
        )
        _write_unavailable(write_json)
        return
    if isinstance(response, dict):
        write_json(response, extra_headers={"Cache-Control": "no-store"})
        return
    _write_unavailable(write_json)


def _identity_filter(query: str) -> tuple[bool, str | None]:
    """``(valid, identity_hash)`` for an optional ``?identity=<64 hex>`` filter."""

    values = parse_qs(query, keep_blank_values=True).get("identity")
    if values is None:
        return True, None
    if len(values) != 1 or not _IDENTITY_HASH.fullmatch(values[0]):
        return False, None
    return True, values[0]


def handle_local_cli_list(handler: object, query: str = "") -> None:
    daemon_server = getattr(handler, "_daemon_server", None)
    write_json = getattr(handler, "_write_json", None)
    if not callable(daemon_server) or not callable(write_json):
        return
    valid, identity_hash = _identity_filter(query)
    if not valid:
        write_json(
            {"error": "invalid_identity", "message": "Use a 64-character connector identity."},
            status=400,
            extra_headers={"Cache-Control": "no-store"},
        )
        return
    daemon = daemon_server()
    list_items = getattr(getattr(daemon, "local_cli_api", None), "list_items", None)
    if not callable(list_items):
        return
    try:
        payload = list_items() if identity_hash is None else list_items(identity_hash=identity_hash)
    except Exception as error:
        record_exception = getattr(getattr(daemon, "diagnostics", None), "record_exception", None)
        if callable(record_exception):
            record_exception("local_cli_list_failed", detail=type(error).__name__)
        _write_unavailable(write_json)
        return
    if isinstance(payload, dict):
        write_json(payload, extra_headers={"Cache-Control": "no-store"})
        return
    _write_unavailable(write_json)


def _write_unavailable(write_json: Callable[..., object]) -> None:
    write_json(
        {
            "error": "local_cli_unavailable",
            "message": "Guard could not load custom extensions.",
        },
        status=500,
        extra_headers={"Cache-Control": "no-store"},
    )
