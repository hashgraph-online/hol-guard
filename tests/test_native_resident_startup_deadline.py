from __future__ import annotations

from pathlib import Path
from queue import Queue
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_resident_stream as stream


@pytest.mark.parametrize("startup_seconds", [0.25, 1.25])
def test_cold_start_consumes_the_original_hook_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    startup_seconds: float,
) -> None:
    now = [10.0]
    deadline = 11.0
    failures: list[str] = []
    written_deadlines: list[float] = []
    closed: list[bool] = []
    responses: Queue[bytes | stream._StreamFailure] = Queue(maxsize=1)
    responses.put(b"response")
    process = SimpleNamespace(stdin=object())
    client = stream._PersistentNativeClient(
        executable=tmp_path / "runtime",
        state_dir=tmp_path / "native-runtime",
        environment={},
        failure_recorder=failures.append,
    )

    def start_snapshot():
        now[0] += startup_seconds
        return process, process.stdin, responses

    def write_frame(_stdin: object, _frame: bytes, *, deadline_monotonic: float) -> bool:
        written_deadlines.append(deadline_monotonic)
        return True

    monkeypatch.setattr(stream.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(client, "_request_snapshot", start_snapshot)
    monkeypatch.setattr(client, "_request_is_current", lambda *_args: True)
    monkeypatch.setattr(client, "_write_frame", write_frame)
    monkeypatch.setattr(client, "close", lambda: closed.append(True))

    result = client.request(b"request", deadline_monotonic=deadline)

    if startup_seconds < 1:
        assert result == b"response"
        assert written_deadlines == [deadline]
        assert failures == []
        assert closed == []
    else:
        assert result is None
        assert written_deadlines == []
        assert failures == ["native_client_timed_out"]
        assert closed == [True]


def test_expired_request_does_not_start_a_resident_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    failures: list[str] = []
    client = stream._PersistentNativeClient(
        executable=tmp_path / "runtime",
        state_dir=tmp_path / "native-runtime",
        environment={},
        failure_recorder=failures.append,
    )

    def forbidden_start():
        raise AssertionError("An expired request must not spawn a client")

    monkeypatch.setattr(stream.time, "monotonic", lambda: 10.0)
    monkeypatch.setattr(client, "_request_snapshot", forbidden_start)

    assert client.request(b"request", deadline_monotonic=10.0) is None
    assert failures == ["native_client_timed_out"]
