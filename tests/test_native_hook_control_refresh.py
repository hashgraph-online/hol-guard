"""Control transitions may retry admission, never a verdict or a deadline."""

import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import Mock

import pytest

from codex_plugin_scanner.guard.daemon import hook_worker_native_review as review
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.native_hook_edge import review_raw_hook_native
from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_resident_client import (
    native_resident_client_failure_code,
    record_native_resident_client_failure_code,
)
from codex_plugin_scanner.guard.store import GuardStore


@pytest.fixture
def worker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> HookWorker:
    result = HookWorker(store=GuardStore(tmp_path / "guard"), start_native_policy=False)
    monkeypatch.setattr(result, "_native_policy_snapshot", Mock(return_value={"generation": 2, "mode": "enforce"}))
    monkeypatch.setattr(result.policy_snapshot_publisher, "request_control_binding_refresh", Mock())
    return result


def _call(worker: HookWorker, tmp_path: Path, deadline: float | None):
    return worker._review_native_edge(
        payload={"hook_event_name": "UserPromptSubmit", "prompt": "What is 2 plus 2?"},
        harness="grok",
        event_name="UserPromptSubmit",
        default_harness="grok",
        home_dir=tmp_path,
        guard_home=tmp_path / "guard",
        workspace=tmp_path,
        deadline=deadline,
        policy_snapshot={"generation": 1, "mode": "enforce"},
    )


@pytest.mark.parametrize("code", sorted(review.CONTROL_BINDING_REFRESH_ERRORS))
def test_refresh_releases_fence_and_keeps_original_deadline(
    worker: HookWorker,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    code: str,
) -> None:
    held: list[bool] = []

    @contextmanager
    def fence(**_kwargs: object) -> Iterator[bool]:
        held.append(True)
        try:
            yield True
        finally:
            held.pop()

    def publish(_generation: int | None) -> None:
        assert not held, "publication must happen after the rejected review releases its shared lease"

    monkeypatch.setattr(review, "native_review_fence", fence)
    publisher = Mock(side_effect=publish)
    monkeypatch.setattr(worker.policy_snapshot_publisher, "request_control_binding_refresh", publisher)
    native = Mock(side_effect=[review.NativePolicyBindingRefreshError(code), ({"policy_action": "allow"}, True)])
    monkeypatch.setattr(worker, "_review_native_edge_with_snapshot", native)
    deadline = time.monotonic() + 2
    assert _call(worker, tmp_path, deadline)["policy_action"] == "allow"
    assert native.call_count == 2
    assert [call.kwargs["deadline"] for call in native.call_args_list] == [deadline, deadline]
    assert native.call_args_list[1].kwargs["policy_snapshot"]["generation"] == 2
    publisher.assert_called_once()


@pytest.mark.parametrize("action", ["review", "require-reapproval", "sandbox-required", "block"])
def test_actual_native_verdict_never_retries(
    worker: HookWorker,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    action: str,
) -> None:
    native = Mock(return_value=({"policy_action": action, "decision": "deny"}, True))
    monkeypatch.setattr(worker, "_review_native_edge_with_snapshot", native)
    assert _call(worker, tmp_path, time.monotonic() + 2)["policy_action"] == action
    native.assert_called_once()
    worker.policy_snapshot_publisher.request_control_binding_refresh.assert_not_called()


@pytest.mark.parametrize("deadline", [None, 0.0])
def test_missing_or_expired_deadline_stays_blocked(
    worker: HookWorker,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    deadline: float | None,
) -> None:
    native = Mock(side_effect=review.NativePolicyBindingRefreshError("native_command_control_authority_not_current"))
    monkeypatch.setattr(worker, "_review_native_edge_with_snapshot", native)
    assert _call(worker, tmp_path, deadline)["decision"] == "block"
    native.assert_called_once()
    worker.policy_snapshot_publisher.request_control_binding_refresh.assert_not_called()


@pytest.mark.parametrize("replacement", [None, {"generation": 2, "mode": "observe"}])
def test_missing_protect_ack_never_reuses_previous_binding(
    worker: HookWorker,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replacement: object,
) -> None:
    monkeypatch.setattr(worker, "_native_policy_snapshot", Mock(return_value=replacement))
    native = Mock(side_effect=review.NativePolicyBindingRefreshError("native_command_control_mutation_in_progress"))
    monkeypatch.setattr(worker, "_review_native_edge_with_snapshot", native)
    assert _call(worker, tmp_path, time.monotonic() + 2)["decision"] == "block"
    native.assert_called_once()


def test_persistent_authority_failure_stops_after_one_refresh(
    worker: HookWorker,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native = Mock(side_effect=review.NativePolicyBindingRefreshError("native_command_control_authority_not_current"))
    monkeypatch.setattr(worker, "_review_native_edge_with_snapshot", native)
    response = _call(worker, tmp_path, time.monotonic() + 2)
    assert response["decision"] == "block"
    assert response["native_failure_code"] == "native_command_control_authority_not_current"
    assert native.call_count == 2
    worker.policy_snapshot_publisher.request_control_binding_refresh.assert_called_once()


def test_fresh_authority_deny_is_preserved(worker: HookWorker, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    denied = {"policy_action": "block", "decision": "deny", "reason_code": "native_policy_block"}
    native = Mock(
        side_effect=[
            review.NativePolicyBindingRefreshError("native_command_control_authority_not_current"),
            (denied, True),
        ]
    )
    monkeypatch.setattr(worker, "_review_native_edge_with_snapshot", native)
    assert _call(worker, tmp_path, time.monotonic() + 2) == denied
    assert native.call_count == 2
    worker.policy_snapshot_publisher.request_control_binding_refresh.assert_called_once()


def test_isolated_worker_cannot_publish_refresh(
    worker: HookWorker, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(worker, "_publish_native_policy", False)
    native = Mock(side_effect=review.NativePolicyBindingRefreshError("native_command_control_authority_not_current"))
    monkeypatch.setattr(worker, "_review_native_edge_with_snapshot", native)
    assert _call(worker, tmp_path, time.monotonic() + 2)["decision"] == "block"
    native.assert_called_once()
    worker.policy_snapshot_publisher.request_control_binding_refresh.assert_not_called()


def test_invalid_next_request_clears_previous_admission_failure(tmp_path: Path) -> None:
    record_native_resident_client_failure_code("native_command_control_authority_not_current")
    assert (
        review_raw_hook_native(
            payload={},
            harness="grok",
            event="UserPromptSubmit",
            guard_home=tmp_path / "guard",
            home_dir=tmp_path,
            cwd=tmp_path,
            source_ref_external_allowed=False,
            observe_mode=False,
            deadline=time.monotonic() + 2,
            request_id="INVALID request",
        )
        is None
    )
    assert native_resident_client_failure_code() is None


def test_concurrent_rejections_withdraw_one_ack_only(tmp_path: Path) -> None:
    publisher = NativePolicySnapshotPublisher(store=GuardStore(tmp_path / "guard"))
    publisher._snapshot = {"generation": 4, "mode": "enforce"}
    publisher._acked = True
    epoch = publisher._epoch
    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(publisher.request_control_binding_refresh, [4] * 32))
    assert publisher._epoch == epoch + 1
    assert publisher._acked is False
    assert publisher._publish_event.is_set()


def test_newer_ack_is_not_withdrawn_by_older_rejection(tmp_path: Path) -> None:
    publisher = NativePolicySnapshotPublisher(store=GuardStore(tmp_path / "guard"))
    publisher._snapshot = {"generation": 5, "mode": "enforce"}
    publisher._acked = True
    publisher.request_control_binding_refresh(4)
    assert publisher._acked is True
    assert publisher._epoch == 0
    assert not publisher._publish_event.is_set()


@pytest.mark.parametrize("code", sorted(review.CONTROL_BINDING_REFRESH_ERRORS))
def test_raw_admission_rejection_requests_refresh(
    worker: HookWorker,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    code: str,
) -> None:
    def reject(**_kwargs: object) -> None:
        record_native_resident_client_failure_code(code)

    monkeypatch.setattr(worker, "_review_raw_hook_native", reject)
    try:
        with pytest.raises(review.NativePolicyBindingRefreshError):
            worker._review_native_edge_with_snapshot(
                payload={"hook_event_name": "UserPromptSubmit", "prompt": "What is 2 plus 2?"},
                harness="grok",
                event_name="UserPromptSubmit",
                default_harness="grok",
                home_dir=tmp_path,
                guard_home=tmp_path / "guard",
                workspace=tmp_path,
                deadline=time.monotonic() + 2,
                policy_snapshot={"mode": "enforce", "generation": 1},
                recording_only=False,
            )
    finally:
        record_native_resident_client_failure_code(None)


def test_stale_admission_failure_does_not_leak_into_next_review(
    worker: HookWorker,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record_native_resident_client_failure_code("native_command_control_authority_not_current")
    monkeypatch.setattr(worker, "_review_raw_hook_native", lambda **_kwargs: None)
    try:
        response, _ = worker._review_native_edge_with_snapshot(
            payload={"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": {"file_path": "a.ts"}},
            harness="grok",
            event_name="PreToolUse",
            default_harness="grok",
            home_dir=tmp_path,
            guard_home=tmp_path / "guard",
            workspace=tmp_path,
            deadline=time.monotonic() + 2,
            policy_snapshot={"mode": "enforce", "generation": 1},
            recording_only=False,
        )
    finally:
        record_native_resident_client_failure_code(None)
    assert response["reason_code"] == "native_pre_tool_unavailable"
