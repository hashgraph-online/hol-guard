"""Scoped authority cannot become an availability continuation at admission."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from types import MethodType, SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard.daemon import hook_worker as worker_module
from codex_plugin_scanner.guard.daemon.hook_worker_responses import prepare_native_hook_policy
from tests.test_native_scoped_result import _bound_result


@pytest.mark.parametrize("selected", [None, 8])
@pytest.mark.parametrize(
    "failure", [None, "source-changed", "missing-check", "check-error", "non-bool", "missing-result"]
)
def test_worker_rechecks_scoped_publication_before_receipt_or_allow(
    tmp_path: Path, selected: int | None, failure: str | None
) -> None:
    edge, snapshot = _bound_result()
    edge["policy_binding"]["selected_decision_id"] = selected
    expected_binding = deepcopy(edge["policy_binding"])
    publisher = SimpleNamespace(
        requires_scoped_authority=True,
        current=True,
        capture_policy_decision_context=lambda binding, receipt: (True, None),
    )
    checks: list[object] = []
    receipts: list[object] = []
    routes: list[str] = []

    def check(binding: object) -> object:
        checks.append(binding)
        assert binding == expected_binding
        if failure == "check-error":
            raise RuntimeError("synthetic publication changed")
        return 1 if failure == "non-bool" else publisher.current

    if failure != "missing-check":
        publisher.result_binding_is_current = check

    def transport(**_kwargs: object) -> object:
        # The source change occurs after the initial binding was obtained.
        publisher.current = failure != "source-changed"
        return None if failure == "missing-result" else edge

    host: Any = SimpleNamespace(
        policy_snapshot_publisher=publisher,
        _native_policy_snapshot=lambda *_args, **_kwargs: dict(snapshot),
        _review_raw_hook_native=transport,
        _record_native_decision_receipt=lambda receipt: receipts.append(receipt) or receipt,
        metrics=SimpleNamespace(record_route=routes.append),
        activity_writer=None,
    )
    host._review_native_edge_with_snapshot = MethodType(
        worker_module.HookWorker._review_native_edge_with_snapshot, host
    )
    actual = worker_module.HookWorker._review_native_edge(
        host,
        payload={"tool_name": "Bash", "tool_input": {"command": "printf safe"}},
        harness="claude-code",
        event_name="PreToolUse",
        default_harness="claude-code",
        home_dir=tmp_path,
        guard_home=tmp_path,
        workspace=tmp_path,
        deadline=None,
    )
    output = actual["hookSpecificOutput"]
    assert isinstance(output, dict)
    if failure is None:
        assert output["permissionDecision"] == "allow"
        assert receipts == [edge["receipt"]]
        assert routes == ["native_resident"]
    else:
        assert output["permissionDecision"] == "deny"
        assert actual["reason_code"] == "native_scoped_authority_unavailable"
        assert receipts == []
        assert routes == ["native_fail_safe"]
    assert len(checks) == (0 if failure in {"missing-result", "missing-check"} else 1)


def test_worker_rejects_scoped_readiness_loss_before_transport(tmp_path: Path) -> None:
    def forbidden(**_kwargs: object) -> None:
        pytest.fail("no transport or receipt may use an unavailable scoped binding")

    host: Any = SimpleNamespace(
        policy_snapshot_publisher=SimpleNamespace(requires_scoped_authority=True),
        _native_policy_snapshot=lambda *_args, **_kwargs: None,
        _review_raw_hook_native=forbidden,
        _record_native_decision_receipt=forbidden,
        metrics=SimpleNamespace(record_route=lambda _route: None),
    )
    host._review_native_edge_with_snapshot = MethodType(
        worker_module.HookWorker._review_native_edge_with_snapshot, host
    )
    actual = worker_module.HookWorker._review_native_edge(
        host,
        payload={"tool_name": "Bash", "tool_input": {"command": "printf safe"}},
        harness="claude-code",
        event_name="PreToolUse",
        default_harness="claude-code",
        home_dir=tmp_path,
        guard_home=tmp_path,
        workspace=tmp_path,
        deadline=None,
    )
    output = actual["hookSpecificOutput"]
    assert isinstance(output, dict)
    assert output["permissionDecision"] == "deny"


def test_scoped_preparation_never_reuses_a_legacy_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(worker_module, "native_mode", lambda: "auto")

    def forbidden() -> None:
        pytest.fail("a scoped negotiation refusal cannot reuse legacy authority")

    host: Any = SimpleNamespace(
        _publish_native_policy=False,
        policy_snapshot_publisher=SimpleNamespace(
            requires_scoped_authority=True,
            current_snapshot_binding=lambda: None,
            current_snapshot=forbidden,
        ),
    )
    assert worker_module.HookWorker.prepare_workspace_policy(host) is None


def test_scoped_admission_does_not_use_emergency_safe_continuation(tmp_path: Path) -> None:
    emitted: list[dict[str, Any]] = []
    routes: list[str] = []
    worker = SimpleNamespace(
        prepare_workspace_policy=lambda *_args, **_kwargs: None,
        policy_snapshot_publisher=SimpleNamespace(requires_scoped_authority=True),
        metrics=SimpleNamespace(record_route=routes.append),
    )
    assert not prepare_native_hook_policy(
        SimpleNamespace(_write_json=emitted.append),
        SimpleNamespace(hook_worker=worker),
        {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "pwd"}},
        {},
        "claude-code",
        str(tmp_path),
        0.0,
    )
    assert len(emitted) == 1
    assert emitted[0]["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert routes == ["native_fail_safe"]


@pytest.mark.parametrize("observe", [False, True])
def test_scoped_native_deny_cannot_be_lowered_by_python_watch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    observe: bool,
) -> None:
    from codex_plugin_scanner.guard.daemon import hook_worker_native

    edge, snapshot = _bound_result(observe=observe)
    edge["result"].update(decision="deny", minimum_action="block", policy_action="block", explicitly_benign=False)
    edge["receipt"].update(decision="deny", policy_action="block")
    receipts: list[object] = []
    monkeypatch.setattr(hook_worker_native, "hook_review_is_recording_only", lambda **_kwargs: True)
    host: Any = SimpleNamespace(
        policy_snapshot_publisher=SimpleNamespace(
            requires_scoped_authority=True,
            result_binding_is_current=lambda _binding: True,
            capture_policy_decision_context=lambda binding, receipt: (True, None),
        ),
        _native_policy_snapshot=lambda *_args, **_kwargs: dict(snapshot),
        _review_raw_hook_native=lambda **_kwargs: edge,
        _record_native_decision_receipt=lambda receipt: receipts.append(receipt) or receipt,
        metrics=SimpleNamespace(record_route=lambda _route: None),
        activity_writer=None,
    )
    host._review_native_edge_with_snapshot = MethodType(
        worker_module.HookWorker._review_native_edge_with_snapshot, host
    )
    actual = worker_module.HookWorker._review_native_edge(
        host,
        payload={"tool_name": "Bash", "tool_input": {"command": "printf safe"}},
        harness="claude-code",
        event_name="PreToolUse",
        default_harness="claude-code",
        home_dir=tmp_path,
        guard_home=tmp_path,
        workspace=tmp_path,
        deadline=None,
    )
    output = actual["hookSpecificOutput"]
    assert isinstance(output, dict)
    assert output["permissionDecision"] == "deny"
    assert actual["policy_action"] == "block"
    assert receipts == [edge["receipt"]]


@pytest.mark.parametrize("has_snapshot", [False, True])
@pytest.mark.parametrize("native_available", [False, True])
def test_scoped_authority_refusal_preserves_post_tool_response_shape(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    has_snapshot: bool,
    native_available: bool,
) -> None:
    from codex_plugin_scanner.guard.daemon import hook_worker_native

    _, snapshot = _bound_result()
    activities: list[object] = []
    receipts: list[object] = []
    routes: list[str] = []
    edge = {
        "schema": "guard-hook-edge-result.v2",
        "authority": "rust",
        "event_name": "PostToolUse",
        "harness": "claude-code",
        "payload_kind": "inline",
        "result": {"decision": "allow", "model_output_action": "allow_original", "policy_action": "allow"},
        "receipt": None,
    }

    def forbidden(_binding: object) -> bool:
        pytest.fail("an unbound legacy result cannot establish scoped post-tool authority")

    monkeypatch.setattr(hook_worker_native, "hook_review_is_recording_only", lambda **_kwargs: False)
    host: Any = SimpleNamespace(
        policy_snapshot_publisher=SimpleNamespace(
            requires_scoped_authority=True,
            requires_policy_authority=True,
            result_binding_is_current=forbidden,
        ),
        _native_policy_snapshot=lambda *_args, **_kwargs: dict(snapshot) if has_snapshot else None,
        _review_raw_hook_native=lambda **_kwargs: edge if native_available else None,
        _record_native_decision_receipt=lambda receipt: receipts.append(receipt) or receipt,
        _record_post_tool_activity=lambda **kwargs: activities.append(kwargs),
        metrics=SimpleNamespace(record_route=routes.append),
        activity_writer=None,
    )
    host._review_native_edge_with_snapshot = MethodType(
        worker_module.HookWorker._review_native_edge_with_snapshot, host
    )
    actual = worker_module.HookWorker._review_native_edge(
        host,
        payload={"hook_event_name": "PostToolUse", "tool_name": "Read", "tool_response": "synthetic output"},
        harness="claude-code",
        event_name="PostToolUse",
        default_harness="claude-code",
        home_dir=tmp_path,
        guard_home=tmp_path,
        workspace=tmp_path,
        deadline=None,
    )
    output = actual["hookSpecificOutput"]
    assert isinstance(output, dict)
    assert output["hookEventName"] == "PostToolUse"
    assert "permissionDecision" not in output
    assert activities == []
    assert actual["policy_action"] == "block"
    assert actual["model_output_action"] == "block"
    assert actual["reason_code"] == "native_scoped_authority_unavailable"
    assert receipts == []
    assert routes == ["native_fail_safe"]
