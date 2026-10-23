"""`nice` and `stdbuf` run the program they name; the sink plans that program."""

from __future__ import annotations

import shlex
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_restricted_pytest
from codex_plugin_scanner.guard.runtime import contained_test_hook as sink
from codex_plugin_scanner.guard.runtime.contained_command_prefix import peel_run_prefixes
from codex_plugin_scanner.guard.runtime.restricted_pytest_model import (
    PYTEST_INVALID_COMMAND_REASON_CODE,
    RestrictedPytestError,
)

# Where native authority reads the program for each launcher shape; the grammar
# itself is tested in `guard-command` (`parser_launchers_tests.rs`).
_PROGRAM = {
    ("nice", "-n", "10", "pytest", "-q"): 3,
    ("nice", "pytest", "-q"): 1,
    ("stdbuf", "-oL", "pytest", "-q"): 2,
    ("nice", "-n", "10", "timeout", "20", "pytest", "-q"): 3,
    ("stdbuf", "-oL", "env", "CI=1", "pytest", "-q"): 2,
}
_KINDS = dict.fromkeys(("inline_eval", "node_test", "vitest", "git", "node_tool"), False)


def _native(operation: str, fields: dict[str, object], expected: object) -> object:
    if operation == "launcher_program":
        return _PROGRAM.get(tuple(fields["command"]))  # type: ignore[arg-type]
    return dict(_KINDS) if operation == "contained_kind" else None


@pytest.fixture(autouse=True)
def _native_authority(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(native_restricted_pytest, "restricted_native", _native)


def test_launchers_and_clocks_peel_in_either_order() -> None:
    assert peel_run_prefixes(shlex.split("nice -n 10 timeout 20 pytest -q")) == (["pytest", "-q"], 20)
    assert peel_run_prefixes(shlex.split("timeout 20 stdbuf -oL pytest -q")) == (["pytest", "-q"], 20)
    assert peel_run_prefixes(shlex.split("stdbuf -oL env CI=1 pytest -q")) == (["pytest", "-q"], None)
    assert peel_run_prefixes(shlex.split("nohup pytest -q")) == (["nohup", "pytest", "-q"], None)


def test_an_answer_outside_the_command_leaves_it_whole(monkeypatch: pytest.MonkeyPatch) -> None:
    for answer in (0, 2, -1, True, "1", None):
        monkeypatch.setattr(native_restricted_pytest, "restricted_native", lambda *_, a=answer: a)
        assert peel_run_prefixes(["nice", "pytest"]) == (["nice", "pytest"], None), answer


def test_only_a_launcher_name_asks_native_authority(monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[object] = []

    def native(operation: str, fields: dict[str, object], expected: object) -> object:
        asked.append(fields["command"])
        return _native(operation, fields, expected)

    monkeypatch.setattr(native_restricted_pytest, "restricted_native", native)
    for text in ("pytest -q", "timeout 20 pytest -q", "./nice pytest -q"):
        peel_run_prefixes(shlex.split(text))
    assert asked == []
    assert peel_run_prefixes(shlex.split("nice pytest -q")) == (["pytest", "-q"], None)
    assert asked == [["nice", "pytest", "-q"]]


def _required() -> dict[str, object]:
    return {
        "decision": "deny",
        "policy_action": "sandbox-required",
        "reason_code": "native_pytest_readonly_containment_required",
        "required_execution_profile": "pytest-readonly-v2",
    }


def _plan_only_pytest(command: list[str], **_: object) -> None:
    if command[0] != "pytest":
        raise RestrictedPytestError(PYTEST_INVALID_COMMAND_REASON_CODE, "accepts only a pytest executable")


@pytest.mark.parametrize("text", ["nice -n 10 pytest -q", "nice pytest -q", "stdbuf -oL pytest -q"])
def test_the_sink_runs_the_program_the_receipt_authorized(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, text: str
) -> None:
    executed: list[list[str]] = []
    asked: list[str] = []
    monkeypatch.setattr(sink, "prepare_restricted_pytest", _plan_only_pytest)
    monkeypatch.setattr(sink, "run_restricted_pytest", lambda command, **_: executed.append(command) or 0)

    def authorize(original: dict[str, object]) -> dict[str, object]:
        asked.append(original["tool_input"]["command"])  # type: ignore[index]
        return _required()

    payload = {"hook_event_name": "PreToolUse", "tool_name": "bash", "tool_input": {"command": text}}
    assert sink.run_authorized_contained_test(payload, workspace=tmp_path, timeout_seconds=20, authorize=authorize) == 0
    # The receipt is drawn for the command as issued; only its program runs.
    assert asked == [text]
    assert executed == [["pytest", "-q"]]


@pytest.mark.parametrize("text", ["./nice -n 10 pytest -q", "stdbuf pytest -q", "nohup pytest -q"])
def test_the_sink_still_refuses_a_launcher_native_authority_does_not_read(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, text: str
) -> None:
    monkeypatch.setattr(sink, "prepare_restricted_pytest", _plan_only_pytest)
    monkeypatch.setattr(sink, "run_restricted_pytest", lambda *args, **kwargs: pytest.fail("ran"))
    monkeypatch.setattr(sink, "run_workspace_contained", lambda *args, **kwargs: pytest.fail("ran"))
    payload = {"hook_event_name": "PreToolUse", "tool_name": "bash", "tool_input": {"command": text}}
    with pytest.raises(RestrictedPytestError) as refused:
        sink.run_authorized_contained_test(
            payload, workspace=tmp_path, timeout_seconds=20, authorize=lambda _: _required()
        )
    assert refused.value.reason_code == "contained_run_authorization_failed"
