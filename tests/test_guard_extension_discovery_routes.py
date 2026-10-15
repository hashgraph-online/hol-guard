"""Local discovery routes stay on /v1 and still require the daemon token."""

from __future__ import annotations

from types import SimpleNamespace

from codex_plugin_scanner.guard.daemon import server as daemon_server_module
from codex_plugin_scanner.guard.daemon.extension_discovery_read import (
    DISCOVERY_EVENTS_PATH,
    DISCOVERY_PLACEMENTS_PATH,
)


def _handler(path: str) -> daemon_server_module._GuardDaemonHandler:
    handler = object.__new__(daemon_server_module._GuardDaemonHandler)
    handler.path = path
    handler.headers = {"Content-Length": "2"}
    handler.server = SimpleNamespace(store=SimpleNamespace(guard_home="/tmp/guard-home"))
    handler._touch_runtime_heartbeat = lambda _path: None
    handler._origin_is_allowed_for_request = lambda _path: True
    handler._route_home = lambda: "/tmp/guard-home"
    handler._query_has_guard_token = lambda _query: False
    handler._record_query_token_rejection = lambda: None
    handler._cors_headers_for_request = lambda: {}
    return handler


def test_local_placements_route_is_not_the_cloud_path(monkeypatch) -> None:
    handler = _handler("/v1/discovery/extensions/placements")
    handler._header_token_is_valid = lambda: True
    written: list[bytes] = []
    rejected: list[object] = []
    handler._write_discovery_body = written.append
    handler._write_json = lambda payload, status=200: rejected.append((status, payload))
    monkeypatch.setattr(daemon_server_module, "discovery_rollout_enabled", lambda: True)
    monkeypatch.setattr(daemon_server_module, "sponsored_discovery_allowed", lambda _store: True)
    monkeypatch.setattr(
        daemon_server_module,
        "discovery_placement_projection",
        lambda **_kwargs: SimpleNamespace(body=b"{}", error_code=None, status=200),
    )

    handler.do_GET()

    assert written == [b"{}"]
    assert rejected == []
    assert DISCOVERY_PLACEMENTS_PATH != "/v1/discovery/extensions/placements"


def test_measurement_post_requires_the_header_token_and_relays_the_cloud_path(monkeypatch) -> None:
    relayed: list[str] = []

    def relay(*, path: str, payload: bytes) -> tuple[int, bytes]:
        relayed.append(path)
        assert payload
        return 200, b"{}"

    monkeypatch.setattr(
        daemon_server_module, "native_route_facts", lambda *_args, **_kwargs: SimpleNamespace(route_class="none")
    )
    monkeypatch.setattr(daemon_server_module, "discovery_rollout_enabled", lambda: True)
    monkeypatch.setattr(daemon_server_module, "sponsored_discovery_measurement_allowed", lambda _store: True)
    monkeypatch.setattr(daemon_server_module, "relay_discovery_measurement", relay)

    denied = _handler("/v1/discovery/extensions/renders")
    denied._header_token_is_valid = lambda: False
    unauthorized: list[object] = []
    denied._write_unauthorized = lambda **_kwargs: unauthorized.append("denied")
    denied._load_request_body = lambda: ({"event": "render"}, None)
    denied.do_POST()
    assert unauthorized == ["denied"]
    assert relayed == []

    allowed = _handler("/v1/discovery/extensions/events")
    allowed._header_token_is_valid = lambda: True
    allowed._load_request_body = lambda: ({"event": "view"}, None)
    allowed._write_json_bytes = lambda *_args, **_kwargs: None
    allowed.do_POST()
    assert relayed == [DISCOVERY_EVENTS_PATH]
