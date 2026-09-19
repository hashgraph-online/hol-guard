from __future__ import annotations

from http.client import HTTPMessage
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast

import pytest

from codex_plugin_scanner.guard.daemon import server as daemon_server
from codex_plugin_scanner.guard.daemon.hook_health import hook_worker_health
from codex_plugin_scanner.guard.daemon.hook_metrics import HookMetricsRecorder
from scripts.stress_guard_daemon_proof import measured_route_counts, native_routes_passed, read_route_counts

if TYPE_CHECKING:
    from codex_plugin_scanner.guard.daemon.hook_health import HookHealthSource


def test_authenticated_health_keeps_direct_and_child_routes_independent() -> None:
    metrics = HookMetricsRecorder()
    child_routes: dict[str, int] = {}
    server = cast(
        "HookHealthSource",
        cast(
            object,
            SimpleNamespace(
                hook_worker=SimpleNamespace(metrics=metrics),
                hook_process_runner=SimpleNamespace(stats=lambda: {"routes": dict(child_routes)}),
            ),
        ),
    )
    capacity: dict[str, object] = {}
    initial = hook_worker_health(server, capacity, {"active": 0})
    before = read_route_counts(initial)
    assert before is not None
    metrics.record_route("native_resident")
    child_routes["native_resident"] = 2
    observed = hook_worker_health(server, capacity, {"active": 0})
    assert initial["hook_worker_routes"] == {}
    assert observed["hook_worker_routes"] == {"native_resident": 1}
    assert observed["hook_workers"] == {"routes": {"native_resident": 2}}
    assert observed["hook_process_capacity"] is capacity
    assert observed["request_capacity"] == {"active": 0}
    assert native_routes_passed(measured_route_counts(before, observed), requests=3)
    metrics.record_route("untrusted-private-route")
    failed = hook_worker_health(server, capacity, {"active": 0})
    assert failed["hook_worker_routes"] == {"native_resident": 1, "native_fail_safe": 1}
    assert not native_routes_passed(measured_route_counts(before, failed), requests=3)


@pytest.mark.parametrize(
    "path,token,status,exposed",
    [
        ("/healthz", None, 200, False),
        ("/v1/healthz/details", None, 401, False),
        ("/v1/healthz/details", "incorrect", 401, False),
        ("/v1/healthz/details", "synthetic-token", 200, True),
    ],
)
def test_direct_route_health_keeps_the_existing_header_auth_boundary(
    path: str, token: str | None, status: int, exposed: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Exercise the actual handler and token comparison without opening a socket.
    handler = object.__new__(daemon_server._GuardDaemonHandler)  # pyright: ignore[reportPrivateUsage]
    monkeypatch.setattr(handler, "server", SimpleNamespace(store=None, auth_token="synthetic-token"), raising=False)
    handler.path = path
    handler.command = "GET"
    handler.headers = HTTPMessage()
    if token is not None:
        handler.headers["X-Guard-Token"] = token
    responses: list[tuple[int, dict[str, object]]] = []
    detailed_calls: list[bool] = []

    def details() -> dict[str, object]:
        detailed_calls.append(True)
        return {"hook_worker_routes": {"native_resident": 1}}

    def write(payload: dict[str, object], *, status: int = 200, **_kwargs: object) -> None:
        responses.append((status, payload))

    def heartbeat(_path: str) -> None:
        return None

    def origin_allowed(_path: str, _parts: list[str]) -> bool:
        return True

    monkeypatch.setattr(handler, "_touch_runtime_heartbeat", heartbeat)
    monkeypatch.setattr(handler, "_origin_is_allowed_for_request", origin_allowed)
    monkeypatch.setattr(handler, "_cors_headers_for_request", lambda: None)
    monkeypatch.setattr(handler, "_record_auth_audit_event", lambda: None)
    monkeypatch.setattr(handler, "_write_json", write)
    monkeypatch.setattr(handler, "_public_healthz_payload", lambda: {"ok": True})
    monkeypatch.setattr(handler, "_detailed_healthz_payload", details)
    handler.do_GET()
    assert len(responses) == 1
    assert responses[0][0] == status
    assert ("hook_worker_routes" in responses[0][1]) is exposed
    assert bool(detailed_calls) is exposed
