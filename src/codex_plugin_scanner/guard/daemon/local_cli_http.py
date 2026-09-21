"""HTTP helpers for custom-extension listing."""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from .local_cli_api import LocalCliApiError

_RECOGNIZE_SOCKET_TIMEOUT_SECONDS = 30.0


class _LocalCliPostApi(Protocol):
    def apply(self, payload: dict[str, object]) -> dict[str, object]: ...
    def discover_items(self) -> dict[str, object]: ...
    def preview(self, payload: dict[str, object]) -> dict[str, object]: ...
    def recognize(self, payload: dict[str, object]) -> dict[str, object]: ...


def dispatch_local_cli_post(api: _LocalCliPostApi, path: str, payload: dict[str, object]) -> dict[str, object]:
    if path.endswith("/preview"):
        return api.preview(payload)
    if path.endswith("/recognize"):
        return api.recognize(payload)
    if path.endswith("/discover"):
        return api.discover_items()
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
    if isinstance(response, dict):
        write_json(response, extra_headers={"Cache-Control": "no-store"})
        return
    _write_unavailable(write_json)


def handle_local_cli_list(handler: object) -> None:
    daemon_server = getattr(handler, "_daemon_server", None)
    write_json = getattr(handler, "_write_json", None)
    if not callable(daemon_server) or not callable(write_json):
        return
    daemon = daemon_server()
    list_items = getattr(getattr(daemon, "local_cli_api", None), "list_items", None)
    if not callable(list_items):
        return
    try:
        payload = list_items()
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
