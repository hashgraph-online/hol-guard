# pyright: reportAny=false, reportPrivateUsage=false
# pyright: reportUnknownArgumentType=false, reportUnknownLambdaType=false, reportUnknownMemberType=false

"""Chaos gate for the daemon's transport (NRH-T123).

Every case here drives the real :class:`GuardDaemonServer` over a real
loopback socket. The question each one asks is the same: when the transport
is abused, does the daemon stay bounded, stay honest, and stay closed? A
request that cannot be understood, cannot be authenticated, or cannot be
scheduled must end in a refusal and a released permit, never in an allow and
never in a handler exception storm.

Volume is a knob rather than a constant. A pull request replays the same
shapes at a fraction of the count so a regression reddens the ordinary
suite; the nightly descriptor-budget job sets ``HOL_GUARD_DAEMON_CHAOS=full``
and runs the counts the hardening plan asks for.
"""

from __future__ import annotations

import json
import os
import socket
import threading
import time
import urllib.parse
import urllib.request
from collections.abc import Generator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, suppress
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import manager as daemon_manager
from codex_plugin_scanner.guard.daemon import server as daemon_server
from codex_plugin_scanner.guard.daemon.runtime_hook_scheduler_contracts import RuntimeHookAdmission
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore
from tests.coverage_ci import under_coverage_scale

_FULL_SCALE = os.environ.get("HOL_GUARD_DAEMON_CHAOS") == "full"

MALFORMED_FRAMES = 10_000 if _FULL_SCALE else 490
AUTH_FLOOD_REQUESTS = 2_000 if _FULL_SCALE else 200
CHURNED_CONNECTIONS = 2_000 if _FULL_SCALE else 300
SLOW_CLIENTS = 16
MIXED_CLIENTS = 64
SATURATED_CLIENTS = 64
WORKER_THREADS = 8

#: Request shapes the framing layer must refuse, with the status each earns.
MALFORMED_SHAPES: tuple[tuple[bytes, bytes, int], ...] = (
    (b"Content-Length: nope\r\n", b"{}", 400),
    (b"Content-Length: -1\r\n", b"", 400),
    (b"Content-Length: 1000001\r\n", b"", 413),
    (b"Content-Length: 2\r\nContent-Length: 2\r\n", b"{}", 400),
    (b"Transfer-Encoding: chunked\r\n", b"2\r\n{}\r\n0\r\n\r\n", 400),
    (b"Content-Type: application/json\r\nContent-Length: 1\r\n", b"\xff", 400),
    (b"Content-Type: application/json\r\nContent-Length: 1\r\n", b"{", 400),
)

PRETOOL_PAYLOAD: dict[str, object] = {
    "hook_event_name": "PreToolUse",
    "tool_name": "read",
    "tool_input": {},
}


@contextmanager
def _chaos_daemon(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    home: str = "guard-home",
) -> Generator[GuardDaemonServer]:
    monkeypatch.setattr(
        daemon_manager,
        "_guard_daemon_process_inventory_for_guard_home",
        lambda _guard_home: [],
    )
    daemon = _started_daemon(tmp_path / home)
    try:
        yield daemon
    finally:
        daemon.stop()


def _started_daemon(guard_home: Path) -> GuardDaemonServer:
    daemon = GuardDaemonServer(
        GuardStore(guard_home),
        host="127.0.0.1",
        port=0,
        idle_timeout_seconds=0,
    )
    daemon.start()
    return daemon


def _frame(token: str, headers: bytes, body: bytes, *, path: str = "/v1/hooks/pi") -> bytes:
    return b"".join(
        (
            f"POST {path} HTTP/1.1\r\n".encode(),
            b"Host: 127.0.0.1\r\n",
            headers,
            f"X-Guard-Token: {token}\r\n".encode(),
            b"\r\n",
            body,
        )
    )


def _exchange(port: int, request: bytes, *, timeout: float = 10.0) -> bytes:
    client = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    client.settimeout(timeout)
    try:
        client.sendall(request)
        client.shutdown(socket.SHUT_WR)
        return _receive(client)
    finally:
        client.close()


def _receive(client: socket.socket) -> bytes:
    chunks: list[bytes] = []
    while True:
        chunk = client.recv(4096)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _status_code(response: bytes) -> int:
    if not response:
        return 0
    status_line = response.split(b"\r\n", 1)[0]
    parts = status_line.split()
    if len(parts) < 2 or not parts[1].isdigit():
        return 0
    return int(parts[1])


def _healthy(port: int, *, timeout: float = 5.0) -> bool:
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=timeout) as response:
        payload = json.loads(response.read())
    return bool(payload["ok"])


def _hook_query(daemon: GuardDaemonServer, workspace: Path) -> str:
    return urllib.parse.urlencode(
        {
            "guard-home": str(daemon._server.store.guard_home),
            "workspace": str(workspace),
        }
    )


def _refuse_every_hook_permit(daemon: GuardDaemonServer, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        daemon._server.runtime_hook_scheduler,
        "acquire",
        lambda **_kwargs: RuntimeHookAdmission(permit=None, reason_code="daemon_hook_queue_capacity"),
    )


def _authenticated_hook(daemon: GuardDaemonServer, query: str, *, timeout: float = 10.0) -> dict[str, object]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{daemon.port}/v1/hooks/pi?{query}",
        data=json.dumps(PRETOOL_PAYLOAD).encode(),
        headers={
            "Content-Type": "application/json",
            "X-Guard-Token": daemon._server.auth_token,
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        decoded = json.loads(response.read())
    assert isinstance(decoded, dict)
    return decoded


def _watch_handler_errors(daemon: GuardDaemonServer, monkeypatch: pytest.MonkeyPatch) -> list[object]:
    handler_errors: list[object] = []
    monkeypatch.setattr(
        daemon._server,
        "handle_error",
        lambda _request, address: handler_errors.append(address),
    )
    return handler_errors


def _drain(daemon: GuardDaemonServer, *, deadline_seconds: float = 10.0) -> int:
    deadline = time.monotonic() + deadline_seconds
    while daemon._server.active_requests and time.monotonic() < deadline:
        time.sleep(0.01)
    return daemon._server.active_requests


def _trickle_client(port: int, token: str) -> socket.socket:
    client = socket.create_connection(("127.0.0.1", port), timeout=5)
    client.sendall(
        _frame(
            token,
            b"Content-Type: application/json\r\nContent-Length: 9999\r\n",
            b"{",
        )
    )
    return client


@pytest.mark.security_critical
def test_ten_thousand_malformed_frames_stay_bounded_and_leave_the_daemon_serving(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _chaos_daemon(tmp_path, monkeypatch) as daemon:
        handler_errors = _watch_handler_errors(daemon, monkeypatch)
        token = daemon._server.auth_token
        port = daemon.port
        requests = [(MALFORMED_SHAPES[index % len(MALFORMED_SHAPES)], index) for index in range(MALFORMED_FRAMES)]

        def answer(entry: tuple[tuple[bytes, bytes, int], int]) -> tuple[int, int]:
            (headers, body, expected), _index = entry
            return expected, _status_code(_exchange(port, _frame(token, headers, body)))

        with ThreadPoolExecutor(max_workers=WORKER_THREADS) as pool:
            outcomes = list(pool.map(answer, requests))

        remaining = _drain(daemon)
        still_serving = _healthy(port)

    unexpected = [pair for pair in outcomes if pair[0] != pair[1]]
    assert unexpected == []
    assert len(outcomes) == MALFORMED_FRAMES
    assert handler_errors == []
    assert remaining == 0
    assert still_serving


@pytest.mark.security_critical
def test_an_authentication_flood_never_admits_a_request_or_rotates_the_token(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _chaos_daemon(tmp_path, monkeypatch) as daemon:
        handler_errors = _watch_handler_errors(daemon, monkeypatch)
        issued_token = daemon._server.auth_token
        port = daemon.port
        body = json.dumps(PRETOOL_PAYLOAD).encode()
        headers = f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n".encode()

        def flood(index: int) -> int:
            forged = f"forged-{index:08d}-{'a' * 24}"
            return _status_code(_exchange(port, _frame(forged, headers, body)))

        with ThreadPoolExecutor(max_workers=WORKER_THREADS) as pool:
            statuses = list(pool.map(flood, range(AUTH_FLOOD_REQUESTS)))

        remaining = _drain(daemon)
        surviving_token = daemon._server.auth_token
        _refuse_every_hook_permit(daemon, monkeypatch)
        answer = _authenticated_hook(daemon, _hook_query(daemon, tmp_path))

    assert set(statuses) == {401}
    assert len(statuses) == AUTH_FLOOD_REQUESTS
    assert handler_errors == []
    assert remaining == 0
    assert surviving_token == issued_token
    assert answer["reason_code"] == "daemon_hook_queue_capacity"
    assert answer["decision"] == "deny"


def test_sixteen_slow_clients_cannot_delay_liveness_or_hold_capacity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(daemon_server, "_DAEMON_REQUEST_READ_TIMEOUT_SECONDS", 0.05)
    with _chaos_daemon(tmp_path, monkeypatch) as daemon:
        handler_errors = _watch_handler_errors(daemon, monkeypatch)
        token = daemon._server.auth_token
        clients = [_trickle_client(daemon.port, token) for _ in range(SLOW_CLIENTS)]
        latencies: list[float] = []
        try:
            for _ in range(12):
                started = time.monotonic()
                assert _healthy(daemon.port, timeout=2.0 * under_coverage_scale(4.0))
                latencies.append(time.monotonic() - started)
        finally:
            for client in clients:
                with suppress(OSError):
                    client.close()

        remaining = _drain(daemon)

    assert len(latencies) == 12
    assert max(latencies) < 1.0 * under_coverage_scale(4.0)
    assert handler_errors == []
    assert remaining == 0


@pytest.mark.security_critical
def test_sixty_four_mixed_clients_each_get_the_answer_their_shape_earns(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(daemon_server, "_DAEMON_REQUEST_READ_TIMEOUT_SECONDS", 0.2)
    with _chaos_daemon(tmp_path, monkeypatch) as daemon:
        handler_errors = _watch_handler_errors(daemon, monkeypatch)
        _refuse_every_hook_permit(daemon, monkeypatch)
        token = daemon._server.auth_token
        port = daemon.port
        query = _hook_query(daemon, tmp_path)
        body = json.dumps(PRETOOL_PAYLOAD).encode()
        headers = f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n".encode()

        def mixed(index: int) -> tuple[str, object]:
            shape = index % 4
            if shape == 0:
                return "hook", _authenticated_hook(daemon, query)
            if shape == 1:
                malformed_headers, malformed_body, expected = MALFORMED_SHAPES[index % len(MALFORMED_SHAPES)]
                status = _status_code(_exchange(port, _frame(token, malformed_headers, malformed_body)))
                return "malformed", (expected, status)
            if shape == 2:
                forged = f"forged-{index:08d}-{'b' * 24}"
                return "forged", _status_code(_exchange(port, _frame(forged, headers, body)))
            client = _trickle_client(port, token)
            try:
                return "trickle", _status_code(_receive(client))
            finally:
                client.close()

        with ThreadPoolExecutor(max_workers=MIXED_CLIENTS) as pool:
            outcomes = list(pool.map(mixed, range(MIXED_CLIENTS)))

        remaining = _drain(daemon)
        still_serving = _healthy(port)

    hooks = [answer for kind, answer in outcomes if kind == "hook"]
    malformed = [answer for kind, answer in outcomes if kind == "malformed"]
    forged = [answer for kind, answer in outcomes if kind == "forged"]
    trickled = [answer for kind, answer in outcomes if kind == "trickle"]

    assert len(outcomes) == MIXED_CLIENTS
    assert hooks and all(isinstance(answer, dict) and answer["decision"] == "deny" for answer in hooks)
    assert malformed and all(pair[0] == pair[1] for pair in malformed if isinstance(pair, tuple))
    assert forged and set(forged) == {401}
    assert trickled and set(trickled) <= {408}
    assert handler_errors == []
    assert remaining == 0
    assert still_serving


@pytest.mark.security_critical
def test_saturated_fallback_answers_every_hook_with_a_deny_and_never_an_allow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _chaos_daemon(tmp_path, monkeypatch) as daemon:
        handler_errors = _watch_handler_errors(daemon, monkeypatch)
        _refuse_every_hook_permit(daemon, monkeypatch)
        query = _hook_query(daemon, tmp_path)

        with ThreadPoolExecutor(max_workers=WORKER_THREADS) as pool:
            answers = list(pool.map(lambda _index: _authenticated_hook(daemon, query), range(SATURATED_CLIENTS)))

        remaining = _drain(daemon)

    assert len(answers) == SATURATED_CLIENTS
    assert {answer["decision"] for answer in answers} == {"deny"}
    assert {answer["reason_code"] for answer in answers} == {"daemon_hook_queue_capacity"}
    assert handler_errors == []
    assert remaining == 0


def _press_until_stopped(
    daemon: GuardDaemonServer,
    query: str,
    stop_now: threading.Event,
    allowed: list[object],
) -> None:
    """Hammer the hook route until the daemon stops answering or the caller says stop."""
    while not stop_now.is_set():
        try:
            answer = _authenticated_hook(daemon, query, timeout=2.0)
        except Exception:
            # A daemon killed mid-flight is allowed to break its clients. It is
            # never allowed to answer with an allow, which is what `allowed` records.
            return
        if answer.get("decision") != "deny":
            allowed.append(answer)


@pytest.mark.security_critical
def test_a_daemon_killed_under_load_leaves_a_home_a_fresh_daemon_can_serve(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        daemon_manager,
        "_guard_daemon_process_inventory_for_guard_home",
        lambda _guard_home: [],
    )
    guard_home = tmp_path / "guard-home"
    allowed: list[object] = []

    for _round in range(3):
        daemon = _started_daemon(guard_home)
        _refuse_every_hook_permit(daemon, monkeypatch)
        query = _hook_query(daemon, tmp_path)
        stop_now = threading.Event()

        with ThreadPoolExecutor(max_workers=4) as pool:
            running = [pool.submit(_press_until_stopped, daemon, query, stop_now, allowed) for _ in range(4)]
            time.sleep(0.2)
            daemon.stop()
            stop_now.set()
            for future in running:
                future.result(timeout=20)

    revived = _started_daemon(guard_home)
    try:
        assert _healthy(revived.port)
    finally:
        revived.stop()

    assert allowed == []


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX directory permission semantics")
@pytest.mark.security_critical
def test_a_read_only_guard_home_never_turns_into_an_allow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if getattr(os, "geteuid", lambda: 1)() == 0:
        pytest.skip("root ignores the directory permissions this case depends on")
    monkeypatch.setattr(
        daemon_manager,
        "_guard_daemon_process_inventory_for_guard_home",
        lambda _guard_home: [],
    )
    guard_home = tmp_path / "read-only-home"
    guard_home.mkdir()
    guard_home.chmod(0o500)
    try:
        try:
            daemon = _started_daemon(guard_home)
        except OSError:
            return
        try:
            _refuse_every_hook_permit(daemon, monkeypatch)
            answer = _authenticated_hook(daemon, _hook_query(daemon, tmp_path))
            assert answer["decision"] == "deny"
        finally:
            daemon.stop()
    finally:
        guard_home.chmod(0o700)


@pytest.mark.security_critical
def test_a_corrupt_state_file_neither_authenticates_nor_stops_the_daemon(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        daemon_manager,
        "_guard_daemon_process_inventory_for_guard_home",
        lambda _guard_home: [],
    )
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(parents=True, exist_ok=True)
    corrupt = guard_home / "daemon-state.json"
    _ = corrupt.write_text("{not json at all", encoding="utf-8")

    daemon = _started_daemon(guard_home)
    try:
        handler_errors = _watch_handler_errors(daemon, monkeypatch)
        body = json.dumps(PRETOOL_PAYLOAD).encode()
        headers = f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n".encode()
        stale = _status_code(_exchange(daemon.port, _frame("{not json at all", headers, body)))
        assert stale == 401
        assert _healthy(daemon.port)
        assert handler_errors == []
    finally:
        daemon.stop()


@pytest.mark.skipif(os.name == "nt", reason="requires a POSIX descriptor budget")
def test_the_descriptor_budget_survives_connection_churn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _chaos_daemon(tmp_path, monkeypatch) as daemon:
        handler_errors = _watch_handler_errors(daemon, monkeypatch)
        token = daemon._server.auth_token
        port = daemon.port
        headers, body, expected = MALFORMED_SHAPES[0]

        def churn(_index: int) -> int:
            return _status_code(_exchange(port, _frame(token, headers, body)))

        with ThreadPoolExecutor(max_workers=WORKER_THREADS) as pool:
            statuses = list(pool.map(churn, range(CHURNED_CONNECTIONS)))

        remaining = _drain(daemon)
        still_serving = _healthy(port)

    assert len(statuses) == CHURNED_CONNECTIONS
    assert set(statuses) == {expected}
    assert handler_errors == []
    assert remaining == 0
    assert still_serving
