"""Python's unavailable inspection says what the native readiness contract says.

`native-readiness.v1.json` is the one source for which state a runtime reason
code means. Command inspection projects that state when it has no native
answer. These tests pin the projection to the contract for every code Python
can emit, and check that no such answer reads as a verdict or a match.
"""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import command_inspection_client
from codex_plugin_scanner.guard.native_daemon_client import GuardDaemonRequestError
from codex_plugin_scanner.guard.runtime.command_inspection import (
    UNAVAILABLE_REASON_CODES,
    inspection_readiness,
    recovery_commands,
    unavailable_command_inspection,
)


def _contract() -> dict[str, object]:
    text = resources.files("codex_plugin_scanner.guard").joinpath("contracts/native-readiness.v1.json").read_text()
    return json.loads(text)


def _declared_state(code: str) -> str:
    contract = _contract()
    reasons = contract["reasons"]
    assert isinstance(reasons, dict)
    state = reasons.get(code)
    assert isinstance(state, str), f"{code} is not declared in native-readiness.v1.json"
    return state


CODES = sorted(UNAVAILABLE_REASON_CODES)


@pytest.mark.parametrize("code", CODES)
def test_every_python_reason_code_is_declared_and_never_ready(code):
    assert _declared_state(code) != "ready"


@pytest.mark.parametrize("code", CODES)
def test_the_projected_state_is_the_declared_state(code):
    readiness = inspection_readiness(code)

    assert readiness["state"] == _declared_state(code)
    assert readiness["reason_code"] == code


@pytest.mark.parametrize("code", CODES)
def test_an_unavailable_inspection_is_never_a_verdict_or_a_match(code):
    payload = unavailable_command_inspection("git status", reason_code=code)
    readiness = payload["readiness"]

    assert payload["status"] == "native_unavailable"
    assert payload["minimum_action"] in {"review", "block"}
    assert payload["rules"] == []
    assert isinstance(readiness, dict)
    assert readiness["verdict"] == "not_evaluated"
    assert readiness["safe_verdict"] is False
    assert readiness["state"] == _declared_state(code)


def test_the_recovery_commands_are_the_declared_ones():
    assert recovery_commands() == _contract()["recovery_commands"]
    assert inspection_readiness("daemon_not_running")["recovery_commands"] == _contract()["recovery_commands"]


def test_an_unknown_code_is_reported_as_the_default_state_without_echoing_it():
    readiness = inspection_readiness("native_made_up_reason")

    assert readiness["state"] == _contract()["default_state"]
    assert readiness["reason_code"] == "native_review_unavailable"


class _AlwaysAnswers:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload
        self.calls = 0

    def inspect_command(self, payload: dict[str, object], *, timeout: float | None = None) -> dict[str, object]:
        del payload, timeout
        self.calls += 1
        return json.loads(json.dumps(self.payload))


def _inspect(client: _AlwaysAnswers, tmp_path: Path) -> dict[str, object]:
    now = [0.0]

    def sleep(seconds: float) -> None:
        now[0] += seconds

    return command_inspection_client.inspect_through_daemon(
        "git status",
        guard_home=tmp_path / "guard",
        workspace=tmp_path,
        home=tmp_path,
        client_for=lambda _home: client,
        ensure_daemon=lambda *_args, **_kwargs: None,
        clock=lambda: now[0],
        sleep=sleep,
    )


def test_a_failed_evaluation_is_terminal_and_is_not_asked_again(tmp_path):
    # Before the state followed the code, a daemon reporting this code without
    # the failed flag read as a cold runtime and was asked again for 5 seconds.
    answer = unavailable_command_inspection("git status", reason_code="native_evaluation_failed")
    client = _AlwaysAnswers(answer)

    payload = _inspect(client, tmp_path)

    assert client.calls == 1
    readiness = payload["readiness"]
    assert isinstance(readiness, dict)
    assert readiness["state"] == "failed"


@pytest.mark.parametrize("code", sorted(UNAVAILABLE_REASON_CODES - {"native_evaluation_failed"}))
def test_a_cold_runtime_is_asked_again_within_the_budget_and_stays_unavailable(code, tmp_path):
    client = _AlwaysAnswers(unavailable_command_inspection("git status", reason_code=code))

    payload = _inspect(client, tmp_path)

    assert client.calls > 1
    assert payload["status"] == "native_unavailable"
    readiness = payload["readiness"]
    assert isinstance(readiness, dict)
    assert readiness["recovery_commands"] == recovery_commands(tmp_path / "guard")


def test_a_daemon_that_never_answers_is_typed_not_a_match(tmp_path):
    class _Refuses:
        def inspect_command(self, payload: dict[str, object], *, timeout: float | None = None) -> dict[str, object]:
            del payload, timeout
            raise GuardDaemonRequestError("down")

    def start_times_out(*_args: object, **_kwargs: object) -> None:
        raise TimeoutError

    payload = command_inspection_client.inspect_through_daemon(
        "git status",
        guard_home=tmp_path / "guard",
        workspace=tmp_path,
        home=tmp_path,
        client_for=lambda _home: _Refuses(),
        ensure_daemon=start_times_out,
    )

    readiness = payload["readiness"]
    assert payload["status"] == "native_unavailable"
    assert isinstance(readiness, dict)
    assert readiness["reason_code"] == "daemon_start_timeout"
    assert readiness["state"] == _declared_state("daemon_start_timeout")
