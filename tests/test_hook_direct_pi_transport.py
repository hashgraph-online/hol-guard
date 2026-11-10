from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.daemon.hook_direct_pi_transport import PI_DIRECT_SWITCH, pi_direct_answer

PAYLOAD = {"tool_name": "bash", "tool_input": {"command": "pwd"}, "cwd": "/work", "guard_remaining_ms": 4000}
RESPONSE = {"decision": "allow", "policy_action": "allow", "reason_code": "native_allow", "extra": [1, None]}
ANSWER = {"schema": "guard-hook-direct-result.v1", "outcome": "answer", "edge": {"harness_response": RESPONSE}}
DEFER = {"schema": "guard-hook-direct-result.v1", "outcome": "defer", "reason": "direct_hook_event_unsupported"}


class _Client:
    def __init__(self, output: object) -> None:
        self.output = output
        self.calls: list[dict[str, object]] = []

    def __call__(self, **values: object) -> bytes | None:
        self.calls.append(values)
        if isinstance(self.output, Exception):
            raise self.output
        return None if self.output is None else json.dumps(self.output).encode("utf-8")


def _worker(client: _Client | None, guard_home: Path, routes: list[str] | None = None) -> SimpleNamespace:
    transport = None if client is None else (Path("/bin/resident"), client)
    return SimpleNamespace(
        guard_home=guard_home,
        policy_snapshot_publisher=SimpleNamespace(direct_hook_transport=lambda: transport),
        metrics=SimpleNamespace(record_route=(routes if routes is not None else []).append),
        prepare_workspace_policy=lambda workspace, *, deadline: None,
    )


def _ask(worker: SimpleNamespace, harness: str = "pi", **overrides: object) -> dict[str, object] | None:
    values: dict[str, object] = {
        "default_harness": harness,
        "params": {"workspace": ["/work"]},
        "payload": PAYLOAD,
        "home_dir": "/home/user",
        "deadline": 104.0,
        "monotonic": lambda: 100.0,
    }
    values.update(overrides)
    return pi_direct_answer(worker, **values)  # pyright: ignore[reportArgumentType]


@pytest.fixture(autouse=True)
def _switch_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(PI_DIRECT_SWITCH, raising=False)


@pytest.mark.parametrize("harness", ["pi", "omp"])
def test_an_answer_is_returned_unchanged(tmp_path: Path, harness: str) -> None:
    client = _Client(ANSWER)
    routes: list[str] = []
    assert _ask(_worker(client, tmp_path, routes), harness) == RESPONSE
    assert routes == ["native_resident"]
    [call] = client.calls
    assert call["executable"] == Path("/bin/resident")
    assert call["guard_home"] == tmp_path
    assert call["deadline_monotonic"] == 101.0
    assert json.loads(call["payload"]) == {  # pyright: ignore[reportArgumentType]
        "operation": "hook_direct",
        "deadline_budget_ms": 1000,
        "request": {
            "harness": harness,
            "guard_home": str(tmp_path),
            "home_dir": "/home/user",
            "workspace": "/work",
            "deadline_budget_ms": 1000,
            "payload": PAYLOAD,
        },
    }


def test_the_caller_budget_bounds_the_request(tmp_path: Path) -> None:
    client = _Client(ANSWER)
    assert _ask(_worker(client, tmp_path), deadline=100.25, home_dir=None, params={}) == RESPONSE
    request = json.loads(client.calls[0]["payload"])["request"]  # pyright: ignore[reportArgumentType]
    assert request["deadline_budget_ms"] == 250
    assert "home_dir" not in request
    assert "workspace" not in request


@pytest.mark.parametrize(
    "output",
    [
        DEFER,
        None,
        b"",
        RuntimeError("resident unavailable"),
        {**ANSWER, "schema": "other"},
        {**ANSWER, "edge": {"harness_response": "allow"}},
        {"schema": "guard-hook-direct-result.v1", "outcome": "answer"},
        ["not", "an", "object"],
    ],
)
def test_a_defer_or_failure_keeps_the_daemon_path(tmp_path: Path, output: object) -> None:
    routes: list[str] = []
    assert _ask(_worker(_Client(output), tmp_path, routes)) is None
    assert routes == []


@pytest.mark.parametrize(
    "overrides",
    [
        {"harness": "codex"},
        {"harness": "oh-my-pi"},
        {"params": {"runtime-harness": ["codex"]}},
        {"deadline": 100.04},
    ],
)
def test_the_resident_is_not_asked_outside_the_pi_lane(tmp_path: Path, overrides: dict[str, object]) -> None:
    client = _Client(ANSWER)
    assert _ask(_worker(client, tmp_path), **overrides) is None  # pyright: ignore[reportArgumentType]
    assert client.calls == []


def test_the_switch_and_a_missing_resident_keep_the_daemon_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _ask(_worker(None, tmp_path)) is None
    assert _ask(SimpleNamespace()) is None
    client = _Client(ANSWER)
    monkeypatch.setenv(PI_DIRECT_SWITCH, "0")
    assert _ask(_worker(client, tmp_path)) is None
    assert client.calls == []
    monkeypatch.setenv(PI_DIRECT_SWITCH, "1")
    assert _ask(_worker(client, tmp_path)) == RESPONSE
