"""Copilot's local approval-queue fallback keeps the deny when the store fails."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard.cli import commands_hook_native_copilot as copilot


def _raise_daemon_unavailable(_guard_home: object) -> object:
    raise RuntimeError("guard surface daemon client unavailable")


def _run_with_failing_queue(
    monkeypatch: pytest.MonkeyPatch, store_error: Exception
) -> tuple[list[list[dict[str, object]]], list[dict[str, Any]]]:
    emitted: list[dict[str, Any]] = []
    bound: list[list[dict[str, object]]] = []

    def failing_queue(**_kwargs: object) -> list[dict[str, object]]:
        raise store_error

    stubs: dict[str, Any] = {
        "_runtime_detection": lambda *_args: None,
        "schedule_guard_daemon_ensure": lambda *_args, **_kwargs: "http://127.0.0.1:1",
        "get_adapter": lambda _harness: SimpleNamespace(approval_flow=lambda **_kwargs: None),
        "_codex_browser_wait_metadata": lambda **_kwargs: {},
        "_hook_command_text": lambda _payload: "run",
        "capture_retry_lineage": lambda *_args, **_kwargs: None,
        "load_guard_surface_daemon_client": _raise_daemon_unavailable,
        "queue_blocked_approvals": failing_queue,
        "_bind_hook_blocked_operation_queue": lambda **kwargs: bound.append(kwargs["queued"]),
        "approval_center_hint": lambda **_kwargs: "hint",
        "_preferred_approval_review_url": lambda *_args, **_kwargs: None,
        "_localize_pending_approval_copy": lambda *_args, **_kwargs: None,
        "_record_harness_usage_for_hook": lambda **_kwargs: None,
        "_native_approval_center_context": lambda *_args, **_kwargs: None,
        "_copilot_hook_reason": lambda reason, _context: reason,
        "_emit_copilot_permission_request_response": lambda **kwargs: emitted.append(kwargs),
    }
    for name, stub in stubs.items():
        monkeypatch.setattr(copilot, name, stub)

    copilot._queue_copilot_approval(
        SimpleNamespace(harness="copilot"),
        effect={
            "evaluation_artifact": {"artifact_id": "copilot:tool", "policy_action": "require-reapproval"},
            "response_payload": {"artifact_id": "copilot:tool"},
            "deny_reason": "Guard paused this action for review.",
        },
        policy_action="require-reapproval",
        runtime_artifact=SimpleNamespace(artifact_id="copilot:tool"),
        approval_reuse=None,
        scanner_evidence=(),
        config=SimpleNamespace(receipt_redaction_level="full", approval_surface_policy="auto"),
        context=SimpleNamespace(home_dir=None),
        guard_home=None,
        managed_install=None,
        now="2026-01-01T00:00:00+00:00",
        output_stream=None,
        payload={"tool_name": "bash"},
        runtime_workspace=None,
        store=SimpleNamespace(),
        action_envelope=None,
    )
    return bound, emitted


@pytest.mark.parametrize(
    "store_error",
    [TimeoutError("Guard storage operation deadline expired."), OSError("disk"), RuntimeError("native")],
)
def test_local_queue_store_failure_still_denies(monkeypatch: pytest.MonkeyPatch, store_error: Exception) -> None:
    bound, emitted = _run_with_failing_queue(monkeypatch, store_error)

    assert bound == [[]]
    assert len(emitted) == 1
    assert emitted[0]["behavior"] == "deny"
    assert emitted[0]["interrupt"] is True
    assert emitted[0]["message"] == "Guard paused this action for review."


def test_requests_queued_before_a_store_failure_stay_in_the_reply(monkeypatch: pytest.MonkeyPatch) -> None:
    store_error = OSError("disk")
    store_error.queued_approvals = [{"request_id": "req-1"}]  # type: ignore[attr-defined]

    bound, emitted = _run_with_failing_queue(monkeypatch, store_error)

    assert bound == [[{"request_id": "req-1"}]]
    assert emitted[0]["behavior"] == "deny"
