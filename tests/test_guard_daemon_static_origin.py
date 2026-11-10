"""Bundled dashboard files load even when the origin check cannot answer."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_daemon_route as route
from codex_plugin_scanner.guard.routes import request_handler as daemon_server
from tests.daemon_handler_support import GuardDaemonHandler as _GuardDaemonHandler


def _unanswered(*_args: object, **_kwargs: object) -> None:
    raise route.NativeDaemonRouteError("native_daemon_route_unavailable")


def _get(home: Path, path: str) -> list[object]:
    handler = object.__new__(_GuardDaemonHandler)
    handler.command = "GET"
    handler.path = path
    handler.headers = {"Origin": "http://127.0.0.1:4781"}  # type: ignore[assignment]
    handler.server = SimpleNamespace(store=SimpleNamespace(guard_home=home))  # type: ignore[assignment]
    written: list[object] = []
    handler._touch_runtime_heartbeat = lambda _path: None  # type: ignore[method-assign]
    handler._write_static_asset = written.append  # type: ignore[method-assign]
    handler._write_json = lambda payload, status=200: written.append((status, payload))  # type: ignore[method-assign]
    handler.do_GET()
    return written


def test_bundled_files_skip_the_origin_check_and_api_routes_keep_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # The dashboard imports a few dozen script chunks at once; on a slow machine
    # the origin check ran out of time for some of them and the page failed to open.
    monkeypatch.setattr(daemon_server, "native_origin_decision", _unanswered)

    assert _get(tmp_path, "/assets/chunks/confirm-dialog.js") == ["assets/chunks/confirm-dialog.js"]
    assert _get(tmp_path, "/brand/logo.svg") == ["brand/logo.svg"]
    assert _get(tmp_path, "/favicon.ico") == ["favicon.ico"]
    assert _get(tmp_path, "/v1/runtime") == [(403, {"error": "forbidden_origin"})]
    assert _get(tmp_path, "/healthz") == [(403, {"error": "forbidden_origin"})]
