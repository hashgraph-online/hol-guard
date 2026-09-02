"""HTTP helpers for custom-extension listing."""

from __future__ import annotations

from collections.abc import Callable


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
