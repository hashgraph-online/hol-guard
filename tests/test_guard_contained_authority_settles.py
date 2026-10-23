"""A contained run waits for a decision instead of cancelling ordinary work."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import contained_test_hook as sink
from codex_plugin_scanner.guard.runtime.contained_authority import authority_unavailable, settled_authority
from codex_plugin_scanner.guard.runtime.restricted_pytest import RestrictedPytestError
from codex_plugin_scanner.guard.runtime.restricted_pytest_model import PYTEST_INVALID_COMMAND_REASON_CODE

UNAVAILABLE = {
    "decision": "block",
    "policy_action": "block",
    "reason_code": "native_hook_worker_exception",
}
ALLOW = {"decision": "allow", "policy_action": "allow"}


def test_an_undecided_runtime_is_asked_again() -> None:
    answers = [UNAVAILABLE, UNAVAILABLE, ALLOW]
    asked: list[dict[str, object]] = []
    slept: list[float] = []

    def authorize(payload: dict[str, object]) -> object:
        asked.append(payload)
        return answers[len(asked) - 1]

    assert settled_authority(authorize, {"tool_input": {}}, pause=slept.append) == ALLOW
    assert len(asked) == 3
    assert slept == [0.75, 0.75]


def test_a_decision_is_taken_as_it_stands() -> None:
    asked: list[dict[str, object]] = []

    def authorize(payload: dict[str, object]) -> object:
        asked.append(payload)
        return ALLOW

    def never(_seconds: float) -> None:
        raise AssertionError("a settled decision must not be re-asked")

    assert settled_authority(authorize, {"tool_input": {}}, pause=never) == ALLOW
    assert len(asked) == 1


def test_an_unreachable_runtime_is_not_mistaken_for_a_verdict() -> None:
    assert authority_unavailable(UNAVAILABLE)
    assert authority_unavailable({**UNAVAILABLE, "reason_code": "native_pre_tool_unavailable"})
    assert not authority_unavailable(ALLOW)
    assert not authority_unavailable({"reason_code": "native_workspace_containment_required"})
    assert not authority_unavailable("native_hook_worker_exception")


def test_a_missing_resident_reply_is_asked_again() -> None:
    """The contained authorizer reports a missing resident edge as this reason."""
    miss = {**UNAVAILABLE, "reason_code": "native_pre_tool_unavailable"}
    answers = [miss, ALLOW]
    asked: list[dict[str, object]] = []
    slept: list[float] = []

    def authorize(payload: dict[str, object]) -> object:
        asked.append(payload)
        return answers[len(asked) - 1]

    assert settled_authority(authorize, {"tool_input": {}}, pause=slept.append) == ALLOW
    assert len(asked) == 2
    assert slept == [0.75]


def test_an_ask_that_waited_out_the_readiness_window_is_not_asked_again(monkeypatch: pytest.MonkeyPatch) -> None:
    """Three 27 second asks were an 84 second backgrounded job with nothing to report."""
    from types import SimpleNamespace

    from codex_plugin_scanner.guard.runtime import contained_authority

    now = [0.0]
    asked: list[dict[str, object]] = []

    def authorize(payload: dict[str, object]) -> object:
        asked.append(payload)
        now[0] += 27.0
        return {**UNAVAILABLE, "reason_code": "native_pre_tool_unavailable"}

    monkeypatch.setattr(contained_authority, "time", SimpleNamespace(monotonic=lambda: now[0], sleep=lambda _s: None))
    response = settled_authority(authorize, {"tool_input": {}})
    assert len(asked) == 1
    assert authority_unavailable(response)


def test_a_quick_miss_is_still_asked_again_after_a_slow_one_elsewhere(monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace

    from codex_plugin_scanner.guard.runtime import contained_authority

    now = [0.0]
    answers = [UNAVAILABLE, ALLOW]
    asked: list[dict[str, object]] = []

    def authorize(payload: dict[str, object]) -> object:
        asked.append(payload)
        now[0] += 0.4
        return answers[len(asked) - 1]

    monkeypatch.setattr(contained_authority, "time", SimpleNamespace(monotonic=lambda: now[0], sleep=lambda _s: None))
    assert settled_authority(authorize, {"tool_input": {}}) == ALLOW
    assert len(asked) == 2


def _not_a_pytest(*_args: object, **_kwargs: object) -> object:
    """The planner's own refusal, independent of this host's sandbox support."""
    raise RestrictedPytestError(PYTEST_INVALID_COMMAND_REASON_CODE, "Restricted pytest accepts only pytest.")


def test_a_silent_runtime_is_reported_as_silent_not_as_a_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The operator is told the runtime did not answer, with its code, and how to recover."""
    from codex_plugin_scanner.guard import native_restricted_pytest
    from codex_plugin_scanner.guard.runtime import contained_authority

    monkeypatch.setattr(contained_authority.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        native_restricted_pytest,
        "restricted_native",
        lambda *_args, **_kwargs: {
            "inline_eval": False,
            "node_test": False,
            "vitest": False,
            "git": False,
            "node_tool": False,
        },
    )
    monkeypatch.setattr(sink, "prepare_restricted_pytest", _not_a_pytest)
    silent = {**UNAVAILABLE, "reason_code": "native_pre_tool_unavailable"}
    with pytest.raises(RestrictedPytestError) as failure:
        _ = sink.run_authorized_contained_test(
            {"hook_event_name": "PreToolUse", "tool_name": "bash", "tool_input": {"command": "ls src"}},
            workspace=tmp_path,
            authorize=lambda _payload: silent,
            timeout_seconds=30,
        )
    assert failure.value.reason_code == "contained_run_authorization_failed"
    assert "native_pre_tool_unavailable" in str(failure.value)
    assert "did not answer" in str(failure.value)
    assert "hol-guard repair" in str(failure.value)
    assert "could not authorize" not in str(failure.value)


def test_a_real_refusal_keeps_the_refusal_wording(tmp_path: Path) -> None:
    """A decided command is not described as an unreachable runtime."""
    assert settled_authority(lambda _payload: ALLOW, {"tool_input": {}}) == ALLOW
    assert "did not answer" not in str(sink._reject(ALLOW))


def test_unavailable_wording_never_leaks_into_independent_rejections() -> None:
    assert authority_unavailable(
        settled_authority(lambda _payload: UNAVAILABLE, {"tool_input": {}}, pause=lambda _: None)
    )
    assert "did not answer" in str(sink._reject(UNAVAILABLE))
    assert "did not answer" not in str(sink._reject())
    assert "did not answer" not in str(sink._reject({"reason_code": "native_command_review_required"}))


@pytest.mark.parametrize(
    ("command_text", "expected_reason"),
    [
        ("python3 scripts/report.py", "contained_run_authorization_failed"),
        ("pytest -q", PYTEST_INVALID_COMMAND_REASON_CODE),
        ("python3 -m pytest -q", PYTEST_INVALID_COMMAND_REASON_CODE),
    ],
)
def test_only_a_command_that_never_named_pytest_loses_the_planner_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, command_text: str, expected_reason: str
) -> None:
    """The pytest planner is the last shape tried, and it uses one reason code.

    A script that never named pytest must not be told to fix a pytest
    invocation. A real pytest command, including `python -m pytest`, keeps
    the planner's own refusal.
    """
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    _ = (scripts / "report.py").write_text("print('report')\n", encoding="utf-8")
    planner_message = "Restricted pytest accepts only a pytest executable or a Python `-m pytest` invocation."

    def not_a_pytest(*_args: object, **_kwargs: object) -> object:
        raise RestrictedPytestError(PYTEST_INVALID_COMMAND_REASON_CODE, planner_message)

    from codex_plugin_scanner.guard import native_restricted_pytest
    from codex_plugin_scanner.guard.runtime import contained_authority

    monkeypatch.setattr(contained_authority.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        native_restricted_pytest,
        "restricted_native",
        lambda *_args, **_kwargs: {
            "inline_eval": False,
            "node_test": False,
            "vitest": False,
            "git": False,
            "node_tool": False,
        },
    )
    monkeypatch.setattr(sink, "prepare_restricted_pytest", not_a_pytest)
    with pytest.raises(RestrictedPytestError) as failure:
        _ = sink.run_authorized_contained_test(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "bash",
                "tool_input": {"command": command_text},
            },
            workspace=tmp_path,
            authorize=lambda _payload: UNAVAILABLE,
            timeout_seconds=30,
        )
    assert failure.value.reason_code == expected_reason
    if expected_reason == PYTEST_INVALID_COMMAND_REASON_CODE:
        assert str(failure.value) == planner_message


def test_a_later_contained_receipt_waits_for_the_resident(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Re-checks after the first receipt use the same retry as the first ask."""
    from types import SimpleNamespace

    from codex_plugin_scanner.guard import native_restricted_pytest
    from codex_plugin_scanner.guard.runtime import contained_authority
    from codex_plugin_scanner.guard.runtime import restricted_node_test as node

    monkeypatch.setattr(contained_authority.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        native_restricted_pytest,
        "restricted_native",
        lambda *_args, **_kwargs: {
            "inline_eval": False,
            "node_test": True,
            "vitest": False,
            "git": False,
            "node_tool": False,
        },
    )
    monkeypatch.setattr(
        node,
        "prepare_restricted_node_test",
        lambda *_args, **_kwargs: SimpleNamespace(command=("/usr/bin/node", "--test", "tests/test.mjs")),
    )
    monkeypatch.setattr(node, "run_restricted_node_test", lambda *_args, **_kwargs: 0)
    profile = {
        "decision": "deny",
        "policy_action": "sandbox-required",
        "reason_code": "native_node_test_readonly_containment_required",
        "required_execution_profile": "node-test-readonly-v1",
    }
    miss = {**UNAVAILABLE, "reason_code": "native_pre_tool_unavailable"}
    queued = [profile, miss, profile]
    asked: list[str] = []

    def authorize(payload: dict[str, object]) -> object:
        tool_input = payload["tool_input"]
        assert isinstance(tool_input, dict)
        command = tool_input["command"]
        assert isinstance(command, str)
        asked.append(command)
        return queued.pop(0)

    assert (
        sink.run_authorized_contained_test(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "bash",
                "tool_input": {"command": "node --test tests/test.mjs"},
            },
            workspace=tmp_path,
            authorize=authorize,
            timeout_seconds=30,
        )
        == 0
    )
    assert asked == [
        "node --test tests/test.mjs",
        "/usr/bin/node --test tests/test.mjs",
        "/usr/bin/node --test tests/test.mjs",
    ]
    assert queued == []
