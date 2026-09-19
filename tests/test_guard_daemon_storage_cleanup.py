from __future__ import annotations

import json
import urllib.request
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests import test_guard_daemon_storage_liveness as storage_liveness


# These cases call the actual liveness test under owned external-boundary doubles.
# They prove cleanup control flow, not latency or actual daemon retirement.
@pytest.mark.parametrize(
    "phase",
    ["burst-assertion", "future-error", "connect-error", "recovery-assertion", "complete"],
)
def test_storage_burst_always_stops_its_started_daemon(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
) -> None:
    events: list[str] = []
    submitted: list[int] = []
    completed: list[int] = []
    reviews: list[int] = []
    original_error = RuntimeError("synthetic owned boundary failure")
    store = SimpleNamespace(path=tmp_path / "guard.db", guard_home=tmp_path / "guard-home")

    def capacity(*, minimum_workers: int, timeout_seconds: float) -> bool:
        assert minimum_workers == 1
        assert timeout_seconds == 15
        events.append("capacity")
        return phase != "recovery-assertion"

    daemon = SimpleNamespace(
        port=12345,
        start=lambda: events.append("daemon-start"),
        stop=lambda: events.append("daemon-stop"),
        _server=SimpleNamespace(
            auth_token="synthetic-token",
            active_hook_requests=0,
            hook_process_runner=SimpleNamespace(
                wait_for_capacity=capacity,
                stats=lambda: {"timeouts": 0, "ready": 1},
            ),
        ),
    )

    class Blocker:
        def execute(self, statement: str) -> None:
            assert statement == "begin exclusive"
            events.append("db-lock")

        def rollback(self) -> None:
            events.append("db-rollback")

        def close(self) -> None:
            events.append("db-close")

    def connect(path: Path, *, timeout: float, isolation_level: None) -> Blocker:
        assert path == store.path
        assert timeout == 0.1
        assert isolation_level is None
        events.append("db-connect")
        if phase == "connect-error":
            raise original_error
        return Blocker()

    def open_json(
        request: str | urllib.request.Request,
        *,
        timeout_seconds: float = 1,
    ) -> tuple[dict[str, object], float]:
        if isinstance(request, str):
            assert request.endswith("/healthz")
            assert timeout_seconds == 1
            events.append("health")
            return {"ok": True}, 0.01
        assert timeout_seconds == 1.75
        assert request.data is not None
        payload = json.loads(request.data)
        index = int(payload["tool_input"]["command"].removeprefix("echo bounded-"))
        reviews.append(index)
        return (
            {"decision": "allow", "policy_action": "allow"},
            1.6 if phase == "burst-assertion" and index < 24 else 0.01,
        )

    class Future:
        def __init__(self, index: int, value: tuple[dict[str, object], float]) -> None:
            self.index = index
            self.value = value

        def result(self, *, timeout: float) -> tuple[dict[str, object], float]:
            assert timeout == 2
            completed.append(self.index)
            if phase == "future-error" and self.index == 0:
                raise original_error
            return self.value

    class Executor:
        def __init__(self, *, max_workers: int) -> None:
            assert max_workers == 24

        def __enter__(self) -> Executor:
            return self

        def __exit__(self, *_args: object) -> None:
            events.append("executor-exit")

        def submit(
            self,
            function: Callable[[int], tuple[dict[str, object], float]],
            index: int,
        ) -> Future:
            submitted.append(index)
            return Future(index, function(index))

    with monkeypatch.context() as patch:
        patch.setattr(storage_liveness, "GuardStore", lambda _path: store)
        patch.setattr(storage_liveness, "GuardDaemonServer", lambda *_args, **_kwargs: daemon)
        patch.setattr(storage_liveness.sqlite3, "connect", connect)
        patch.setattr(storage_liveness, "ThreadPoolExecutor", Executor)
        patch.setattr(storage_liveness, "_open_json", open_json)
        run = storage_liveness.test_locked_storage_hook_burst_fails_safe_without_stranding_daemon
        if phase in {"future-error", "connect-error"}:
            with pytest.raises(RuntimeError) as raised:
                run(tmp_path, patch)
            assert raised.value is original_error
        elif phase in {"burst-assertion", "recovery-assertion"}:
            with pytest.raises(AssertionError):
                run(tmp_path, patch)
        else:
            run(tmp_path, patch)

    assert events[0] == "daemon-start"
    assert events.count("db-connect") == 1
    if phase == "connect-error":
        assert submitted == completed == reviews == []
        assert "db-close" not in events
    else:
        assert submitted == list(range(24))
        assert completed == ([0] if phase == "future-error" else list(range(24)))
        assert reviews == (list(range(24)) + ([100] if phase == "complete" else []))
        assert events.count("db-rollback") == events.count("db-close") == 1
        assert events.index("db-rollback") < events.index("db-close")
    assert events.count("capacity") == int(phase in {"recovery-assertion", "complete"})
    assert events.count("daemon-stop") == 1
    assert events[-1] == "daemon-stop"
