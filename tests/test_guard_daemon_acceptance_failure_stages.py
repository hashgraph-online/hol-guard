from __future__ import annotations

import http.client
import json
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests import guard_daemon_acceptance_fixtures as fixtures


@dataclass
class _ConnectionTrace:
    timeout: float
    paths: list[str] = field(default_factory=list)
    responses: int = 0
    closed: bool = False


@dataclass
class _Response:
    payload: dict[str, object]
    status: int = 200
    reason: str = "OK"

    def read(self) -> bytes:
        return json.dumps(self.payload).encode()


@pytest.mark.parametrize("harness", ["codex", "claude-code"])
@pytest.mark.parametrize("failure_stage", [None, "identity_challenge", "hook_exchange", "response_classification"])
def test_failure_stage_preserves_exception_accounting_without_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, harness: str, failure_stage: str | None
) -> None:
    connections: list[_ConnectionTrace] = []
    stopped: list[bool] = []

    class FakeStore:
        def __init__(self, guard_home: Path) -> None:
            self.guard_home = guard_home

        def list_approval_requests(self, *, status: object, limit: object) -> list[object]:
            assert status is None and limit is None
            return []

    class FakeRunner:
        def stats(self) -> dict[str, int]:
            return {"target": 1, "workers": 0, "configured": 1, "failures": 0, "restarts": 0}

        def wait_for_capacity(self, *, minimum_workers: int, timeout_seconds: float) -> bool:
            assert minimum_workers == 1 and timeout_seconds == 15
            return True

    class FakeDaemon:
        def __init__(self, store: FakeStore, *, host: str, port: int, idle_timeout_seconds: int) -> None:
            assert host == "127.0.0.1" and port == 0 and idle_timeout_seconds == 0
            self.store = store
            self.port = 8765
            self._server = SimpleNamespace(
                hook_process_runner=FakeRunner(),
                runtime_hook_scheduler=SimpleNamespace(
                    stats=lambda: {"queued": 0, "queued_limit": 1, "retained_bytes": 0}
                ),
                auth_token="fixture-auth-value",
            )

        def start(self) -> None:
            self.store.guard_home.mkdir(parents=True)
            (self.store.guard_home / "daemon-state.json").write_text('{"state_id":"fixture-state"}')

        def stop(self) -> None:
            stopped.append(True)

    class FakeConnection:
        sock = None

        def __init__(self, host: str, port: int, *, timeout: float) -> None:
            assert host == "127.0.0.1" and port == 8765
            self.index = len(connections)
            self.trace = _ConnectionTrace(timeout=timeout)
            connections.append(self.trace)

        def request(self, method: str, path: str, *, body: bytes, headers: dict[str, str]) -> None:
            assert method == "POST"
            assert isinstance(body, bytes) and headers["Content-Type"] == "application/json"
            self.trace.paths.append(path.partition("?")[0])

        def getresponse(self) -> _Response:
            self.trace.responses += 1
            is_challenge = self.trace.paths[-1] == "/v1/daemon/identity-challenge"
            stage = "identity_challenge" if is_challenge else "hook_exchange"
            if self.index == 1 and failure_stage == stage:
                raise http.client.RemoteDisconnected("Remote end closed connection without response")
            if is_challenge:
                return _Response({"proof": "fixture-proof"})
            return _Response({"decision": "deny" if self.index == 0 else "allow"})

        def close(self) -> None:
            self.trace.closed = True

    original_classify = fixtures._response_blocks_action

    def classify(result: dict[str, object]) -> bool:
        if failure_stage == "response_classification" and result.get("decision") == "allow":
            raise RuntimeError("synthetic classification failure")
        return original_classify(result)

    monkeypatch.setattr(fixtures, "GuardStore", FakeStore)
    monkeypatch.setattr(fixtures, "GuardDaemonServer", FakeDaemon)
    monkeypatch.setattr(fixtures.http.client, "HTTPConnection", FakeConnection)
    monkeypatch.setattr(fixtures, "_response_blocks_action", classify)
    result = fixtures.run_workload(
        {
            "id": "fixed-stage-witness",
            "clients": [{"harness": harness, "client": "fixture-client", "requests": 2, "concurrency": 1}],
            "secret_stride": 10,
        },
        root=tmp_path,
    )

    assert len(connections) == 2
    assert all(connection.closed and 0 < connection.timeout <= 12 for connection in connections)
    assert stopped == [True]
    assert connections[0].paths == ["/v1/daemon/identity-challenge", f"/v1/hooks/{harness}"]
    expected_last_paths = ["/v1/daemon/identity-challenge"]
    if failure_stage != "identity_challenge":
        expected_last_paths.append(f"/v1/hooks/{harness}")
    assert connections[1].paths == expected_last_paths
    assert connections[0].responses == 2
    assert connections[1].responses == len(expected_last_paths)

    failed = int(failure_stage is not None)
    expected_stages = {} if failure_stage is None else {failure_stage: 1}
    assert result.requests == 2
    assert result.secrets_denied == 1
    assert result.routine_allowed == 1 - failed
    assert result.capacity_denials == 0
    assert result.generic_failures == failed
    assert result.routine_allowed + result.secrets_denied + result.generic_failures == result.requests
    assert result.dispatch_counts == {harness: 2 - failed}
    assert result.failure_stages == expected_stages
    # This final dataclass field remains visible in failed-assertion/raw repr output.
    assert repr(result).endswith(f"failure_stages={expected_stages!r})")
    expected_reasons = (
        {}
        if failure_stage is None
        else {"RuntimeError:synthetic classification failure": 1}
        if failure_stage == "response_classification"
        else {"RemoteDisconnected:Remote end closed connection without response": 1}
    )
    assert result.failure_reasons == expected_reasons
    assert result.browser_launches == 0 and result.inbox_requests == 0
    assert result.pid_stable and result.workers_stable and result.queue_bounded
    transport_counts = getattr(result, "transport_counts", None)
    if transport_counts is not None:
        assert transport_counts == {
            "challenge_attempts": 2,
            "hook_attempts": 1 if failure_stage == "identity_challenge" else 2,
        }
