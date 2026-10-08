"""Hook-boundary integration and non-interference tests for command activity."""

# pyright: reportUnusedCallResult=false

from __future__ import annotations

import sqlite3
from datetime import date
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.cli.commands_support_command_activity import (
    hook_post_succeeded,
    record_post_hook_command_activity_best_effort,
    record_pre_hook_command_activity_best_effort,
)
from codex_plugin_scanner.guard.runtime.command_activity_api_contract import CommandActivityAnalyticsQuery
from codex_plugin_scanner.guard.runtime.command_activity_contract import (
    COMMAND_ACTIVITY_HARNESSES,
    ActivityDecisionReason,
    CommandExecutionStatus,
)
from codex_plugin_scanner.guard.runtime.command_activity_correlation import (
    derive_proven_request_correlation,
    load_or_create_installation_correlation_key,
)
from codex_plugin_scanner.guard.runtime.native_command_evaluation import review_command_native
from codex_plugin_scanner.guard.store import GuardStore
from tests.native_command_test_support import RealNativeReviewFixture, real_native_review_fixture


@pytest.fixture(autouse=True)
def _real_native_command_reviews(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.cli import commands_support_command_activity as activity_support
    from codex_plugin_scanner.guard.runtime import native_command_evaluation

    fixtures: dict[str, RealNativeReviewFixture] = {}

    def review(command: str, **_kwargs: object) -> dict[str, object]:
        fixture = fixtures.get(command)
        if fixture is None:
            fixture = real_native_review_fixture(command)
            fixtures[command] = fixture
        return fixture.payload

    seed = real_native_review_fixture("printf native-fixture")
    monkeypatch.setattr(native_command_evaluation, "review_pre_tool_native", review)
    monkeypatch.setattr(
        activity_support.ExtensionControlRuntimeSnapshot,
        "from_authority_view",
        staticmethod(lambda _view: seed.snapshot),
    )


def _command_payload(*, request_id: str | None = "toolcall_abcdef1234567890") -> dict[str, object]:
    payload: dict[str, object] = {
        "tool_name": "Shell",
        "tool_input": {"command": "git push origin release/2.2 --force"},
    }
    if request_id is not None:
        payload["tool_call_id"] = request_id
    return payload


def _store(guard_home: Path) -> GuardStore:
    return GuardStore(guard_home, prime_policy_integrity=False)


def test_codex_pre_and_post_transition_one_matched_activity(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    store = _store(guard_home)
    payload = _command_payload()

    assert record_pre_hook_command_activity_best_effort(
        store=store,
        guard_home=guard_home,
        harness="codex",
        event="PreToolUse",
        payload=payload,
        policy_action="allow",
        receipt_id=None,
        prompted=False,
        cwd=tmp_path,
        home_dir=tmp_path,
    )
    assert not record_pre_hook_command_activity_best_effort(
        store=store,
        guard_home=guard_home,
        harness="codex",
        event="PreToolUse",
        payload=payload,
        policy_action="allow",
        receipt_id=None,
        prompted=False,
        cwd=tmp_path,
        home_dir=tmp_path,
    )
    assert store.count_command_activities() == 1
    assert store.count_command_activity_rule_hits() >= 1

    assert record_post_hook_command_activity_best_effort(
        store=store,
        guard_home=guard_home,
        harness="codex",
        event="PostToolUse",
        payload=payload,
        succeeded=True,
    )
    key = load_or_create_installation_correlation_key(guard_home)
    correlation = derive_proven_request_correlation(
        harness="codex",
        event="PostToolUse",
        payload=payload,
        key=key,
    )
    assert correlation is not None
    activity = store.get_command_activity_by_request_correlation(correlation)
    assert activity is not None
    assert activity.execution_status is CommandExecutionStatus.CONFIRMED_SUCCESS
    assert store.count_command_activities() == 1
    assert not record_post_hook_command_activity_best_effort(
        store=store,
        guard_home=guard_home,
        harness="codex",
        event="PostToolUse",
        payload=payload,
        succeeded=True,
    )
    health = store.get_command_activity_persistence_health()
    assert health.dropped_event_count == 0
    assert health.persistence_error_count == 0


def test_every_supported_harness_records_matched_pre_hook_evidence(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    store = _store(guard_home)
    for harness in sorted(COMMAND_ACTIVITY_HARNESSES):
        payload = _command_payload(request_id=None)
        event = "preToolUse" if harness == "copilot" else "PreToolUse"
        if harness in {"codex", "pi"}:
            payload["tool_call_id"] = f"{harness}_toolcall_abcdef1234567890"
        elif harness == "claude-code":
            payload["tool_use_id"] = "claude_tooluse_abcdef1234567890"
        elif harness == "cursor":
            payload["generation_id"] = "cursor_generation_abcdef1234567890"
            payload["cursor_source_hook_event"] = "beforeShellExecution"
        assert record_pre_hook_command_activity_best_effort(
            store=store,
            guard_home=guard_home,
            harness=harness,
            event=event,
            payload=payload,
            policy_action="allow",
            receipt_id=None,
            prompted=False,
        )
    assert store.count_command_activities() == len(COMMAND_ACTIVITY_HARNESSES)


def test_same_request_id_with_changed_decision_is_a_counted_conflict(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    store = _store(guard_home)
    payload = _command_payload()
    assert record_pre_hook_command_activity_best_effort(
        store=store,
        guard_home=guard_home,
        harness="codex",
        event="PreToolUse",
        payload=payload,
        policy_action="allow",
        receipt_id=None,
        prompted=False,
    )
    assert not record_pre_hook_command_activity_best_effort(
        store=store,
        guard_home=guard_home,
        harness="codex",
        event="PreToolUse",
        payload=payload,
        policy_action="warn",
        receipt_id=None,
        prompted=False,
    )
    assert store.count_command_activities() == 1
    health = store.get_command_activity_persistence_health()
    assert health.dropped_event_count == 1
    assert health.last_error_code == "pre_record_failed"


def test_unsupported_native_wrapper_records_no_fabricated_rule_ids(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    store = _store(guard_home)
    command = "sudo -u alternate-user git push origin main --force"
    payload: dict[str, object] = {
        "tool_name": "Shell",
        "tool_input": {"command": command},
        "tool_call_id": "toolcall_wrapped_abcdef1234567890",
    }
    native = real_native_review_fixture(command)
    reviewed = review_command_native(
        command,
        guard_home=guard_home,
        cwd=tmp_path,
        home_dir=tmp_path,
        extension_control_snapshot=native.snapshot,
    )
    assert native.payload["minimum_action"] == "block"
    model = cast(dict[str, object], native.payload["command_model"])
    assert model["confidence"] == "uncertain"
    assert model["uncertainty_reason"] == "transparent_wrapper_not_yet_supported"
    extension_evidence = cast(dict[str, object], native.payload["command_extensions"])
    assert extension_evidence["evaluation_error"] == "native_command_evaluation_failed"
    assert extension_evidence["observations"] == []
    assert reviewed is not None
    assert reviewed.evaluation.minimum_action == "block"
    assert reviewed.evaluation.matches == ()
    assert reviewed.evaluation.controlling_rule_id is None
    assert reviewed.payload["command_extensions"] == extension_evidence

    # Offline native classification does not issue the linked receipt required
    # for recording a review-or-stronger final decision.
    assert not record_pre_hook_command_activity_best_effort(
        store=store,
        guard_home=guard_home,
        harness="codex",
        event="PreToolUse",
        payload=payload,
        policy_action="block",
        receipt_id=None,
        prompted=False,
        cwd=tmp_path,
        home_dir=tmp_path,
    )
    assert store.count_command_activities() == 0
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("select rule_id from command_activity_matches").fetchall() == []


def test_failure_post_transitions_with_same_native_identifier(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    store = _store(guard_home)
    payload = _command_payload()
    assert record_pre_hook_command_activity_best_effort(
        store=store,
        guard_home=guard_home,
        harness="codex",
        event="PreToolUse",
        payload=payload,
        policy_action="allow",
        receipt_id=None,
        prompted=False,
    )

    assert record_post_hook_command_activity_best_effort(
        store=store,
        guard_home=guard_home,
        harness="codex",
        event="PostToolUseFailure",
        payload=payload,
        succeeded=False,
    )
    key = load_or_create_installation_correlation_key(guard_home)
    correlation = derive_proven_request_correlation(
        harness="codex",
        event="PostToolUseFailure",
        payload=payload,
        key=key,
    )
    assert correlation is not None
    activity = store.get_command_activity_by_request_correlation(correlation)
    assert activity is not None
    assert activity.execution_status is CommandExecutionStatus.CONFIRMED_FAILURE


def test_strong_post_pairs_without_repeated_command_content(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    store = _store(guard_home)
    payload = _command_payload()
    assert record_pre_hook_command_activity_best_effort(
        store=store,
        guard_home=guard_home,
        harness="codex",
        event="PreToolUse",
        payload=payload,
        policy_action="allow",
        receipt_id=None,
        prompted=False,
    )
    assert record_post_hook_command_activity_best_effort(
        store=store,
        guard_home=guard_home,
        harness="codex",
        event="PostToolUse",
        payload={"tool_call_id": payload["tool_call_id"]},
        succeeded=True,
    )
    assert store.count_command_activities() == 1


def test_conflicting_terminal_post_is_counted_without_creating_unpaired_evidence(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    store = _store(guard_home)
    payload = _command_payload()
    assert record_pre_hook_command_activity_best_effort(
        store=store,
        guard_home=guard_home,
        harness="codex",
        event="PreToolUse",
        payload=payload,
        policy_action="allow",
        receipt_id=None,
        prompted=False,
    )
    assert record_post_hook_command_activity_best_effort(
        store=store,
        guard_home=guard_home,
        harness="codex",
        event="PostToolUse",
        payload=payload,
        succeeded=True,
    )
    assert not record_post_hook_command_activity_best_effort(
        store=store,
        guard_home=guard_home,
        harness="codex",
        event="PostToolUseFailure",
        payload=payload,
        succeeded=False,
    )
    assert store.count_command_activities() == 1
    health = store.get_command_activity_persistence_health()
    assert health.dropped_event_count == 1
    assert health.persistence_error_count == 0
    assert health.last_error_code == "post_result_conflict"
    analytics = store.command_activity_analytics(CommandActivityAnalyticsQuery(days=7), as_of=date.today())
    assert cast(dict[str, object], analytics["health"])["status"] == "healthy"


def test_non_hook_command_event_does_not_create_pre_evidence(tmp_path: Path) -> None:
    store = _store(tmp_path / "guard-home")
    assert not record_pre_hook_command_activity_best_effort(
        store=store,
        guard_home=store.guard_home,
        harness="codex",
        event="UserPromptSubmit",
        payload=_command_payload(),
        policy_action="allow",
        receipt_id=None,
        prompted=False,
    )
    assert store.count_command_activities() == 0


def test_native_git_diff_match_records_one_activity(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    store = _store(guard_home)
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Shell",
        "tool_input": {"command": "git diff --stat"},
        "tool_call_id": "codex_read_abcdef1234567890",
    }

    assert record_pre_hook_command_activity_best_effort(
        store=store,
        guard_home=guard_home,
        harness="codex",
        event="PreToolUse",
        payload=payload,
        policy_action="allow",
        receipt_id=None,
        prompted=False,
        cwd=tmp_path,
        home_dir=tmp_path,
    )
    assert record_post_hook_command_activity_best_effort(
        store=store,
        guard_home=guard_home,
        harness="codex",
        event="PostToolUse",
        payload=payload,
        succeeded=True,
    )

    correlation = derive_proven_request_correlation(
        harness="codex",
        event="PreToolUse",
        payload=payload,
        key=load_or_create_installation_correlation_key(guard_home),
    )
    assert correlation is not None
    activity = store.get_command_activity_by_request_correlation(correlation)
    assert activity is not None
    assert activity.execution_status is CommandExecutionStatus.CONFIRMED_SUCCESS
    assert activity.decision_reason_code is ActivityDecisionReason.EXTENSION_MATCH
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("select rule_id from command_activity_matches").fetchall() == [("command.git.diff",)]
    assert activity.match_count == 1


def test_cursor_before_and_trusted_after_events_pair_by_generation_id(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    store = _store(guard_home)
    payload = {
        **_command_payload(request_id=None),
        "generation_id": "generation_abcdef1234567890",
        "cursor_source_hook_event": "beforeShellExecution",
    }
    assert record_pre_hook_command_activity_best_effort(
        store=store,
        guard_home=guard_home,
        harness="cursor",
        event="PreToolUse",
        payload=payload,
        policy_action="allow",
        receipt_id=None,
        prompted=False,
    )
    payload.pop("cursor_source_hook_event")
    assert record_post_hook_command_activity_best_effort(
        store=store,
        guard_home=guard_home,
        harness="cursor",
        event="afterShellExecution",
        payload=payload,
        succeeded=True,
    )
    assert store.count_command_activities() == 1


def test_unsupported_post_is_explicitly_unpaired(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    store = _store(guard_home)

    assert record_post_hook_command_activity_best_effort(
        store=store,
        guard_home=guard_home,
        harness="kimi",
        event="PostToolUse",
        payload=_command_payload(request_id=None),
        succeeded=True,
    )
    with sqlite3.connect(store.path) as connection:
        row = cast(
            tuple[str, str, int] | None,
            connection.execute("select execution_status, proof_level, match_count from command_activity").fetchone(),
        )
    assert row is not None
    assert tuple(row) == ("unpaired_post", "unpaired_post", 0)


def test_persistence_failure_is_counted_without_escaping(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    guard_home = tmp_path / "guard-home"
    store = _store(guard_home)

    def fail_record(_evidence: object) -> bool:
        raise RuntimeError("fixture-only persistence failure")

    monkeypatch.setattr(store, "record_command_activity", fail_record)
    assert not record_pre_hook_command_activity_best_effort(
        store=store,
        guard_home=guard_home,
        harness="codex",
        event="PreToolUse",
        payload=_command_payload(),
        policy_action="allow",
        receipt_id=None,
        prompted=False,
    )
    health = store.get_command_activity_persistence_health()
    assert health.dropped_event_count == 1
    assert health.persistence_error_count == 1
    assert health.last_error_code == "pre_record_failed"


def test_primary_and_health_failures_are_both_non_interfering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path / "guard-home")

    def fail(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("fixture-only failure")

    monkeypatch.setattr(store, "record_command_activity", fail)
    monkeypatch.setattr(store, "record_command_activity_persistence_failure", fail)
    assert not record_pre_hook_command_activity_best_effort(
        store=store,
        guard_home=store.guard_home,
        harness="codex",
        event="PreToolUse",
        payload=_command_payload(),
        policy_action="allow",
        receipt_id=None,
        prompted=False,
    )


@pytest.mark.parametrize(
    ("event", "payload", "expected"),
    (
        ("PostToolUse", {}, True),
        ("PostToolUseFailure", {}, False),
        ("PostToolUse", {"is_error": True}, False),
        ("postToolUse", {"success": False}, False),
        ("afterShellExecution", {"exitCode": 7}, False),
    ),
)
def test_post_success_interpretation_is_closed(
    event: str,
    payload: dict[str, object],
    expected: bool,
) -> None:
    assert hook_post_succeeded(event, payload) is expected
