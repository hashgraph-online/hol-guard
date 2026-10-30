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

import errno
import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Generator, Mapping
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import TypeVar

import pytest

from codex_plugin_scanner.guard.daemon import manager as daemon_manager
from codex_plugin_scanner.guard.daemon import server as daemon_server
from codex_plugin_scanner.guard.daemon.runtime_hook_scheduler import RuntimeHookScheduler
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.native_hook_evidence_writer import NativeHookEvidenceWriter
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


_T = TypeVar("_T")

#: How long a shape keeps asking for its own answer while the daemon is full.
OVERLOAD_RETRY_SECONDS = 10.0


def _past_overload(attempt: Callable[[], _T]) -> _T:
    """Repeat ``attempt`` while the daemon refuses it for request capacity.

    A 503 says the daemon was full, not what the request shape earns. The
    mixed-client case asks the second question, and its own load can reach
    the normal-admission limit, so a shape refused for capacity is asked
    again until it gets an answer of its own.
    """

    deadline = time.monotonic() + OVERLOAD_RETRY_SECONDS
    while True:
        try:
            result = attempt()
        except urllib.error.HTTPError as error:
            if error.code != 503 or time.monotonic() >= deadline:
                raise
            time.sleep(0.05)
            continue
        if result == 503 and time.monotonic() < deadline:
            time.sleep(0.05)
            continue
        return result


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


@contextmanager
def _saturated_hook_queue(daemon: GuardDaemonServer) -> Generator[None]:
    """Fill the real scheduler so its own code refuses, instead of stubbing it.

    Patching ``acquire`` to answer every call with a refusal proves only that
    the patch refuses. This installs a real :class:`RuntimeHookScheduler` whose
    single queue slot is held by a parked request and which admits nothing, so
    every hook the daemon then receives is turned away by the scheduler's own
    capacity check. A deny under this block is the code a saturated daemon
    runs.
    """
    scheduler = RuntimeHookScheduler(
        active_limit=0,
        per_harness_active_limit=1,
        queued_limit=1,
        per_harness_queued_limit=1,
        per_client_queued_limit=1,
    )
    original = daemon._server.runtime_hook_scheduler
    daemon._server.runtime_hook_scheduler = scheduler
    release = threading.Event()
    parked = threading.Thread(
        target=lambda: scheduler.acquire(
            harness="pi",
            client_key="chaos-parked",
            lane="decision",
            payload_bytes=1,
            deadline=time.monotonic() + 600.0,
            cancellation=release,
        ),
        daemon=True,
    )
    parked.start()
    deadline = time.monotonic() + 10.0
    while scheduler.stats()["queued"] < 1 and time.monotonic() < deadline:
        time.sleep(0.01)
    assert scheduler.stats()["queued"] == 1, "the parked request never occupied the queue"
    try:
        yield
    finally:
        release.set()
        parked.join(timeout=10.0)
        daemon._server.runtime_hook_scheduler = original


#: A daemon in its own process, so a case can end it the way a crash would.
_DAEMON_CHILD_PROGRAM = """
import json
import sys
import time
from pathlib import Path

from codex_plugin_scanner.guard.daemon import manager as daemon_manager
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore

daemon_manager._guard_daemon_process_inventory_for_guard_home = lambda _guard_home: []
daemon = GuardDaemonServer(
    GuardStore(Path(sys.argv[1])),
    host="127.0.0.1",
    port=0,
    idle_timeout_seconds=0,
)
daemon.start()
print(json.dumps({"port": daemon.port, "token": daemon._server.auth_token}), flush=True)
while True:
    time.sleep(3600)
"""


@contextmanager
def _daemon_subprocess(guard_home: Path) -> Generator[tuple[subprocess.Popen[str], int, str]]:
    """Run a real daemon in its own process so a case can kill it outright.

    ``GuardDaemonServer.stop()`` is an orderly shutdown: it drains, closes and
    returns. It says nothing about a daemon that dies with requests in flight,
    which is the failure this file is here to provoke. Only a separate process
    can be killed that way.
    """
    repository_root = Path(__file__).resolve().parents[1]
    environment = dict(os.environ)
    environment["PYTHONPATH"] = os.pathsep.join(
        part
        for part in (
            str(repository_root / "src"),
            str(repository_root),
            environment.get("PYTHONPATH", ""),
        )
        if part
    )
    process = subprocess.Popen(
        [sys.executable, "-c", _DAEMON_CHILD_PROGRAM, str(guard_home)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=environment,
    )
    watchdog = threading.Timer(120.0, process.kill)
    watchdog.start()
    try:
        assert process.stdout is not None
        announcement = process.stdout.readline()
        watchdog.cancel()
        if not announcement.strip():
            process.kill()
            _, errors = process.communicate(timeout=60)
            pytest.fail(f"the daemon child never announced itself: {errors[-2000:]}")
        decoded = json.loads(announcement)
        yield process, int(decoded["port"]), str(decoded["token"])
    finally:
        watchdog.cancel()
        if process.poll() is None:
            process.kill()
        _ = process.wait(timeout=60)
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                stream.close()


def _authenticated_hook(daemon: GuardDaemonServer, query: str, *, timeout: float = 10.0) -> dict[str, object]:
    return _authenticated_hook_at(daemon.port, daemon._server.auth_token, query, timeout=timeout)


def _authenticated_hook_at(port: int, token: str, query: str, *, timeout: float = 10.0) -> dict[str, object]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/v1/hooks/pi?{query}",
        data=json.dumps(PRETOOL_PAYLOAD).encode(),
        headers={
            "Content-Type": "application/json",
            "X-Guard-Token": token,
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
        with _saturated_hook_queue(daemon):
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
    with _chaos_daemon(tmp_path, monkeypatch) as daemon, _saturated_hook_queue(daemon):
        handler_errors = _watch_handler_errors(daemon, monkeypatch)
        token = daemon._server.auth_token
        port = daemon.port
        query = _hook_query(daemon, tmp_path)
        body = json.dumps(PRETOOL_PAYLOAD).encode()
        headers = f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n".encode()

        def mixed(index: int) -> tuple[str, object]:
            shape = index % 4
            if shape == 0:
                return "hook", _past_overload(lambda: _authenticated_hook(daemon, query))
            if shape == 1:
                malformed_headers, malformed_body, expected = MALFORMED_SHAPES[index % len(MALFORMED_SHAPES)]
                status = _past_overload(
                    lambda: _status_code(_exchange(port, _frame(token, malformed_headers, malformed_body)))
                )
                return "malformed", (expected, status)
            if shape == 2:
                forged = f"forged-{index:08d}-{'b' * 24}"
                return "forged", _past_overload(lambda: _status_code(_exchange(port, _frame(forged, headers, body))))
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
    # A trickling client earns no decision. Under load the daemon may answer
    # 408, refuse it with 503 when request capacity is reached, or drop it
    # before a status line (recorded as 0). None of those is an answer.
    assert trickled and set(trickled) <= {0, 408, 503}
    assert handler_errors == []
    assert remaining == 0
    assert still_serving


@pytest.mark.security_critical
def test_saturated_fallback_answers_every_hook_with_a_deny_and_never_an_allow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _chaos_daemon(tmp_path, monkeypatch) as daemon, _saturated_hook_queue(daemon):
        handler_errors = _watch_handler_errors(daemon, monkeypatch)
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
    port: int,
    token: str,
    query: str,
    stop_now: threading.Event,
    answers: list[dict[str, object]],
) -> None:
    """Hammer the hook route until the daemon stops answering or the caller says stop."""
    while not stop_now.is_set():
        try:
            answers.append(_authenticated_hook_at(port, token, query, timeout=2.0))
        except Exception:
            # A daemon killed mid-flight is allowed to break its clients. What
            # it may never do is answer after its death, which the refused port
            # the caller checks afterwards is what establishes.
            return


@pytest.mark.security_critical
def test_a_daemon_killed_under_load_leaves_a_home_a_fresh_daemon_can_serve(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Kill a loaded daemon outright and ask what the home and the port say afterwards.

    Nothing here is stubbed: every request is evaluated by the daemon the way
    a harness would, and the kill is a real kill of a real process. The three
    properties the case asserts are that the daemon answered while it lived,
    that its port answers nothing once it is dead, and that the home it leaves
    behind is one a fresh daemon can serve.
    """
    monkeypatch.setattr(
        daemon_manager,
        "_guard_daemon_process_inventory_for_guard_home",
        lambda _guard_home: [],
    )
    guard_home = tmp_path / "guard-home"
    answers: list[dict[str, object]] = []
    query = urllib.parse.urlencode({"guard-home": str(guard_home), "workspace": str(tmp_path)})

    for _round in range(3):
        with _daemon_subprocess(guard_home) as (process, port, token):
            # One answer before the load proves the round reached a live daemon,
            # so an empty `answers` later cannot be mistaken for a quiet kill.
            answers.append(_authenticated_hook_at(port, token, query, timeout=60.0))
            stop_now = threading.Event()
            with ThreadPoolExecutor(max_workers=4) as pool:
                running = [pool.submit(_press_until_stopped, port, token, query, stop_now, answers) for _ in range(4)]
                time.sleep(0.5)
                process.kill()
                _ = process.wait(timeout=60)
                stop_now.set()
                for future in running:
                    future.result(timeout=60)

        # The port a killed daemon held is a closed port, not a quiet one.
        with pytest.raises(OSError):
            _ = _exchange(port, _frame(token, b"Content-Length: 0\r\n", b""), timeout=2.0)

    for answer in answers:
        assert isinstance(answer.get("decision"), str), answer

    revived = _started_daemon(guard_home)
    try:
        assert _healthy(revived.port)
    finally:
        revived.stop()


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
        except OSError as error:
            # A daemon that never started has not been asked the question this
            # case exists for. Say so rather than reporting a pass.
            pytest.skip(f"the daemon refused to start against a read-only guard home: {error}")
        try:
            with _saturated_hook_queue(daemon):
                answer = _authenticated_hook(daemon, _hook_query(daemon, tmp_path))
            # A home it cannot write to is one more reason to refuse, never a
            # reason to wave the hook through because the refusal could not be
            # recorded.
            assert answer["decision"] == "deny"
            assert answer["reason_code"] == "daemon_hook_queue_capacity"
            assert _healthy(daemon.port)
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

    daemon = _started_daemon(guard_home)
    try:
        # Corrupted while the daemon is already serving. Writing it beforehand
        # would only ask whether startup copes; the daemon that has to survive
        # a truncated write is the one already answering hooks.
        corrupt = guard_home / "daemon-state.json"
        _ = corrupt.write_text("{not json at all", encoding="utf-8")
        handler_errors = _watch_handler_errors(daemon, monkeypatch)
        body = json.dumps(PRETOOL_PAYLOAD).encode()
        headers = f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n".encode()
        stale = _status_code(_exchange(daemon.port, _frame("{not json at all", headers, body)))
        assert stale == 401
        assert _healthy(daemon.port)
        assert handler_errors == []
    finally:
        daemon.stop()


@pytest.mark.security_critical
def test_a_full_disk_never_changes_a_hook_answer_or_stops_the_daemon(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exhaust the disk under the evidence writer and keep asking for decisions.

    Every write the daemon makes while answering a hook goes through the
    evidence writer, so refusing that one call with ``ENOSPC`` is a full disk
    as the hook path meets one. The hook still has to answer, the answer still
    has to be a decision, and the daemon still has to be serving afterwards:
    evidence the daemon could not record is not permission to stop recording
    decisions.
    """
    with _chaos_daemon(tmp_path, monkeypatch) as daemon:
        handler_errors = _watch_handler_errors(daemon, monkeypatch)
        attempted: list[str] = []

        def _no_space_left(
            _self: NativeHookEvidenceWriter,
            action: Mapping[str, object],
            *,
            timeout_seconds: float,
        ) -> dict[str, object]:
            _ = timeout_seconds
            attempted.append(str(action.get("action", "")))
            raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))

        query = _hook_query(daemon, tmp_path)
        # The answer this hook earns while the disk still has room. "Never
        # changes a hook answer" is a claim about this value, so read it
        # before the disk fills and compare against it afterwards; a decision
        # that is merely a string would hide a deny turning into an allow.
        baseline = _authenticated_hook(daemon, query, timeout=60.0)["decision"]
        assert isinstance(baseline, str), baseline

        # The baseline's own evidence is submitted behind its response. Let it
        # reach the real writer while the disk still has room, so every attempt
        # recorded below belongs to a hook that ran with no space left.
        dispatch = getattr(daemon._server, "runtime_hook_evidence_dispatch", None)
        if dispatch is not None:
            assert dispatch.flush(10.0), "the baseline's evidence never drained"

        monkeypatch.setattr(NativeHookEvidenceWriter, "_call", _no_space_left)

        answers = [_authenticated_hook(daemon, query, timeout=60.0) for _ in range(8)]

        # Evidence is submitted behind the response, so give the dispatch the
        # chance to reach the writer before reading what it attempted.
        if dispatch is not None:
            _ = dispatch.flush(10.0)
        deadline = time.monotonic() + 10.0
        while not attempted and time.monotonic() < deadline:
            time.sleep(0.05)

        assert attempted, "no hook ever reached the evidence writer"
        for answer in answers:
            assert answer.get("decision") == baseline, answer
        assert _healthy(daemon.port)
        assert handler_errors == []


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
