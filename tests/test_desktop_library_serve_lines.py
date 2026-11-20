"""The resident library process keeps reading calls while its workers are busy."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from codex_plugin_scanner.guard.cli import desktop_library_call


def _line(call_id: int, *, expires_in_ms: int | None = None) -> bytes:
    head = f'{{"id":{call_id},'
    if expires_in_ms is not None:
        head += f'"expires_in_ms":{expires_in_ms},'
    return (head + '"call":"test.call","args":{}}\n').encode()


def test_reading_never_waits_for_a_free_worker(monkeypatch, tmp_path: Path) -> None:
    release = threading.Event()
    started: list[bytes] = []

    def _answer(_guard_home: Path, request: bytes) -> bytes:
        started.append(request)
        release.wait(10)
        call_id = json.loads(request)["id"]
        return json.dumps({"id": call_id, "ok": None}).encode() + b"\n"

    monkeypatch.setattr(desktop_library_call, "answer_line", _answer)
    total = desktop_library_call._RESIDENT_CALL_LIMIT * 4
    lines = [_line(index) for index in range(total)]
    read = 0
    all_read = threading.Event()

    def _read_line() -> bytes:
        nonlocal read
        if read == len(lines):
            all_read.set()
            release.wait(10)
            return b""
        read += 1
        return lines[read - 1]

    written: list[bytes] = []
    serving = threading.Thread(
        target=desktop_library_call.serve_lines, args=(tmp_path, _read_line, written.append), daemon=True
    )
    serving.start()
    # Every worker is held, yet the loop has read every line.
    assert all_read.wait(5)
    assert len(started) <= desktop_library_call._RESIDENT_CALL_LIMIT
    release.set()
    serving.join(10)
    assert not serving.is_alive()
    assert sorted(json.loads(line)["id"] for line in written) == list(range(total))


def test_a_call_whose_caller_gave_up_is_dropped_unrun(monkeypatch, tmp_path: Path) -> None:
    ran: list[int] = []

    def _answer(_guard_home: Path, request: bytes) -> bytes:
        call_id = json.loads(request)["id"]
        ran.append(call_id)
        return json.dumps({"id": call_id, "ok": None}).encode() + b"\n"

    monkeypatch.setattr(desktop_library_call, "answer_line", _answer)
    monkeypatch.setattr(desktop_library_call, "_RESIDENT_CALL_LIMIT", 1)
    gate = threading.Event()
    original = desktop_library_call.answer_line

    def _first_blocks(guard_home: Path, request: bytes) -> bytes:
        if json.loads(request)["id"] == 1:
            gate.wait(10)
        return original(guard_home, request)

    monkeypatch.setattr(desktop_library_call, "answer_line", _first_blocks)
    lines = iter([_line(1), _line(2, expires_in_ms=1), _line(3, expires_in_ms=60_000), _line(4)])

    def _read_line() -> bytes:
        line = next(lines, b"")
        if not line:
            time.sleep(0.05)
            gate.set()
        return line

    written: list[bytes] = []
    assert desktop_library_call.serve_lines(tmp_path, _read_line, written.append) == 0
    assert ran == [1, 3, 4]
    assert [json.loads(line)["id"] for line in written] == [1, 3, 4]


def test_the_deadline_is_read_from_the_head_of_the_line() -> None:
    assert desktop_library_call._expires_at(_line(1, expires_in_ms=2500), 10.0) == 12.5
    assert desktop_library_call._expires_at(_line(1), 10.0) is None
    buried = b'{"id":1,"call":"x","args":{"pad":"' + b"y" * 200 + b'","expires_in_ms":5}}\n'
    assert desktop_library_call._expires_at(buried, 10.0) is None


def test_the_read_loop_waits_once_the_queue_is_full(monkeypatch, tmp_path: Path) -> None:
    release = threading.Event()

    def _answer(_guard_home: Path, request: bytes) -> bytes:
        release.wait(10)
        return json.dumps({"id": json.loads(request)["id"], "ok": None}).encode() + b"\n"

    monkeypatch.setattr(desktop_library_call, "answer_line", _answer)
    monkeypatch.setattr(desktop_library_call, "_RESIDENT_CALL_LIMIT", 1)
    line_size = len(_line(0))
    monkeypatch.setattr(desktop_library_call, "_QUEUED_LIMIT_BYTES", line_size * 2)
    lines = [_line(index) for index in range(8)]
    read = 0

    def _read_line() -> bytes:
        nonlocal read
        if read == len(lines):
            return b""
        read += 1
        return lines[read - 1]

    serving = threading.Thread(target=desktop_library_call.serve_lines, args=(tmp_path, _read_line, lambda _line: None))
    serving.start()
    time.sleep(0.3)
    # One call is running and two wait in the queue; the read loop holds the
    # fourth line until a worker takes one.
    held = read
    release.set()
    serving.join(10)
    assert not serving.is_alive()
    assert held <= 4
    assert read == len(lines)


def test_a_deeply_nested_call_line_is_answered_as_invalid(tmp_path: Path) -> None:
    request = b"[" * 100_000 + b"]" * 100_000 + b"\n"

    answer = json.loads(desktop_library_call.answer_line(tmp_path, request))

    assert answer == {"error": {"type": "LibraryCallError", "message": "invalid_request", "kind": "library_call"}}


def test_a_worker_exception_returns_a_structured_answer_and_the_pool_continues(monkeypatch, tmp_path: Path) -> None:
    calls = 0

    def _answer(_guard_home: Path, request: bytes) -> bytes:
        nonlocal calls
        calls += 1
        if json.loads(request)["id"] == 1:
            raise RuntimeError("fixture failure")
        return json.dumps({"id": json.loads(request)["id"], "ok": None}).encode() + b"\n"

    monkeypatch.setattr(desktop_library_call, "answer_line", _answer)
    written: list[bytes] = []
    lines = iter([_line(1), _line(2), b""])

    assert desktop_library_call.serve_lines(tmp_path, lambda: next(lines), written.append) == 0
    assert calls == 2
    responses = {json.loads(line)["id"]: json.loads(line) for line in written}
    assert responses[1] == {
        "id": 1,
        "error": {"type": "LibraryWorkerError", "message": "worker_failed", "kind": "library_worker"},
    }
    assert responses[2] == {"id": 2, "ok": None}
