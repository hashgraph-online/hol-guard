"""Dashboard routes for plugin update prompts.

The dashboard's CSP keeps it off hol.org, so the daemon downloads the two
public indexes for it and the native runtime compares them with the plugins
installed on this machine, exactly as ``hol-guard plugin updates`` does. The
check runs only when the reader asks for it, and nothing about the installed
plugins leaves the device.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..plugin_telemetry.report import PluginTelemetryError
from ..plugin_telemetry.updates import check_updates, dismiss_update

_NO_STORE = {"Cache-Control": "no-store, max-age=0"}
# Match the native runtime's dismissal checks so a bad request is a 400 here
# rather than a 503 from the runtime.
_SLUG_BYTES = 256
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}")


def _guard_home(handler: object) -> Path:
    server = getattr(handler, "server", None)
    return Path(getattr(getattr(server, "store", None), "guard_home", ""))


def _writer(handler: object) -> Callable[..., Any]:
    write_json = getattr(handler, "_write_json", None)
    if not callable(write_json):
        raise TypeError("daemon handler cannot write JSON")
    return write_json


def handle_plugin_updates_read(handler: object) -> None:
    try:
        payload = check_updates(_guard_home(handler))
    except PluginTelemetryError as error:
        _writer(handler)(
            {"error": "plugin_updates_unavailable", "message": str(error)},
            status=503,
            extra_headers=_NO_STORE,
        )
        return
    _writer(handler)(payload, extra_headers=_NO_STORE)


def _text(payload: dict[str, object], name: str) -> str | None:
    value = payload.get(name)
    if not isinstance(value, str):
        return None
    return value.strip() or None


def _slug(payload: dict[str, object]) -> str | None:
    slug = _text(payload, "slug")
    return slug if slug is not None and len(slug.encode("utf-8")) <= _SLUG_BYTES else None


def _version(payload: dict[str, object]) -> str | None:
    version = _text(payload, "version")
    return version if version is not None and _VERSION.fullmatch(version) else None


def handle_plugin_updates_dismiss(handler: object, payload: dict[str, object]) -> None:
    slug = _slug(payload)
    version = _version(payload)
    if slug is None or version is None:
        _writer(handler)(
            {"error": "invalid_plugin_update", "message": "Name the listing slug and the version to dismiss."},
            status=400,
            extra_headers=_NO_STORE,
        )
        return
    try:
        result = dismiss_update(_guard_home(handler), slug, version)
    except PluginTelemetryError as error:
        _writer(handler)(
            {"error": "plugin_updates_unavailable", "message": str(error)},
            status=503,
            extra_headers=_NO_STORE,
        )
        return
    _writer(handler)(result, extra_headers=_NO_STORE)
