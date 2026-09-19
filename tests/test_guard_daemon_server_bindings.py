from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.daemon import server


def test_server_namespace_keeps_resource_and_class_anchors() -> None:
    assert server._GuardDaemonHttpServer is server._GuardDaemonHTTPServer
    assert Path(server.__file__).with_name("static") == server._STATIC_DIR
    assert server._LOGGER.name == "codex_plugin_scanner.guard.daemon.server"


def test_moved_helper_reads_current_facade_constant(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server, "_RUNTIME_HOOK_ADMISSION_TIMEOUT_SECONDS", 0.123)
    assert server._runtime_hook_remaining_hint({}) == 0.123


def test_moved_instance_method_reads_current_dependency(monkeypatch: pytest.MonkeyPatch) -> None:
    handler = server._GuardDaemonHandler.__new__(server._GuardDaemonHandler)
    monkeypatch.setattr(handler, "server", SimpleNamespace(auth_token="expected"), raising=False)
    calls: list[tuple[bytes, bytes]] = []

    def compare(provided: bytes, expected: bytes) -> bool:
        calls.append((provided, expected))
        return True

    monkeypatch.setattr(server, "secrets", SimpleNamespace(compare_digest=compare))
    assert handler._tokens_match("provided") is True
    assert calls == [(b"provided", b"expected")]


def test_local_url_builder_rejects_non_loopback_hosts() -> None:
    assert server._build_local_url("127.0.0.1", 42, "/healthz") == "http://127.0.0.1:42/healthz"
    assert server._build_local_url("::1", 42, "/healthz") == "http://[::1]:42/healthz"
    for host in ("0.0.0.0", "::", "192.0.2.1", "localhost"):
        with pytest.raises(ValueError, match="loopback host"):
            server._build_local_url(host, 42, "/healthz")


def test_static_method_keeps_descriptor_semantics() -> None:
    descriptor = vars(server._GuardDaemonHandler)["_normalize_origin"]
    assert isinstance(descriptor, staticmethod)
    handler = server._GuardDaemonHandler.__new__(server._GuardDaemonHandler)
    assert handler._normalize_origin("http://127.0.0.1:42/") == "http://127.0.0.1:42"
    assert server._GuardDaemonHandler._normalize_origin("http://127.0.0.1:42/") == "http://127.0.0.1:42"


def test_class_method_binds_actual_subclass(monkeypatch: pytest.MonkeyPatch) -> None:
    class Handler(server._GuardDaemonHandler):
        pass

    descriptor = vars(server._GuardDaemonHandler)["_strict_loopback_origin"]
    assert isinstance(descriptor, classmethod)
    calls: list[object] = []

    def normalize(value: object) -> str:
        calls.append(value)
        return "http://127.0.0.1:42"

    monkeypatch.setattr(Handler, "_normalize_origin", staticmethod(normalize))
    assert Handler._strict_loopback_origin("http://127.0.0.1:42") == "http://127.0.0.1:42"
    assert calls == ["http://127.0.0.1:42"]


def test_http_close_retains_real_super_owner(monkeypatch: pytest.MonkeyPatch) -> None:
    http = server._GuardDaemonHTTPServer.__new__(server._GuardDaemonHTTPServer)
    calls: list[object] = []
    monkeypatch.setattr(http, "_stop_request_executors", lambda: True)
    monkeypatch.setattr(server.BoundedThreadingHTTPServer, "server_close", lambda owner: calls.append(owner))
    http.server_close()
    assert calls == [http]


@pytest.mark.parametrize(("parsed", "capacity"), [(False, True), (True, False), (True, True)])
def test_parse_request_retains_super_and_admission_order(
    monkeypatch: pytest.MonkeyPatch, parsed: bool, capacity: bool
) -> None:
    handler = server._GuardDaemonHandler.__new__(server._GuardDaemonHandler)
    calls: list[object] = []
    monkeypatch.setattr(handler, "request", object(), raising=False)
    monkeypatch.setattr(handler, "path", "/healthz", raising=False)
    monkeypatch.setattr(server.BaseHTTPRequestHandler, "parse_request", lambda owner: calls.append(owner) or parsed)
    daemon = SimpleNamespace(
        classify_connection=lambda request: calls.append(("classify", request)),
        claim_request_capacity=lambda request, path: calls.append(("capacity", request, path)) or capacity,
    )
    monkeypatch.setattr(handler, "_daemon_server", lambda: daemon)
    monkeypatch.setattr(handler, "send_error", lambda code, message: calls.append(("error", code, message)))
    assert handler.parse_request() is (parsed and capacity)
    assert calls[:2] == [handler, ("classify", handler.request)]
    if not parsed:
        assert len(calls) == 2
    else:
        assert calls[2] == ("capacity", handler.request, "/healthz")
        assert len(calls) == (3 if capacity else 4)
        if not capacity:
            assert calls[3] == ("error", 503, "Guard daemon request capacity reached")
