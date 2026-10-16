"""Control transitions may retry admission, never a verdict or a deadline."""

import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import Mock

import pytest

from codex_plugin_scanner.guard.daemon import hook_worker_native as native_module
from codex_plugin_scanner.guard.daemon import hook_worker_native_review as review
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.native_hook_edge import review_raw_hook_native
from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
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


@pytest.mark.parametrize("code", sorted(review.NATIVE_REVIEW_REFRESH_ERRORS))
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


@pytest.mark.parametrize("code", sorted(review.NATIVE_REVIEW_REFRESH_ERRORS))
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


def _raw_rejection(worker: HookWorker, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: str, mode: str):
    def reject(**_kwargs: object) -> None:
        record_native_resident_client_failure_code(code)

    monkeypatch.setattr(worker, "_review_raw_hook_native", reject)
    try:
        return worker._review_native_edge_with_snapshot(
            payload={"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": {"file_path": "a.ts"}},
            harness="grok",
            event_name="PreToolUse",
            default_harness="grok",
            home_dir=tmp_path,
            guard_home=tmp_path / "guard",
            workspace=tmp_path,
            deadline=time.monotonic() + 2,
            policy_snapshot={"mode": mode, "generation": 3},
            recording_only=mode == "observe",
        )
    finally:
        record_native_resident_client_failure_code(None)


def test_superseded_watch_snapshot_requests_refresh(
    worker: HookWorker, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Another process published a newer generation; the binding this worker
    # holds is stale in Watch as well as in enforce.
    with pytest.raises(review.NativePolicyBindingRefreshError) as raised:
        _raw_rejection(worker, tmp_path, monkeypatch, review.SNAPSHOT_NOT_CURRENT_ERROR, "observe")
    assert raised.value.generation == 3
    assert raised.value.recording_only is True


@pytest.mark.parametrize("code", sorted(review.CONTROL_BINDING_REFRESH_ERRORS))
def test_watch_control_binding_rejection_does_not_refresh(
    worker: HookWorker, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: str
) -> None:
    response, native_used = _raw_rejection(worker, tmp_path, monkeypatch, code, "observe")
    assert native_used is False
    assert response["reason_code"] == "native_pre_tool_unavailable"


def test_superseded_snapshot_retries_with_refreshed_watch_binding(
    worker: HookWorker, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(worker, "_native_policy_snapshot", Mock(return_value={"generation": 4, "mode": "observe"}))
    native = Mock(
        side_effect=[
            review.NativePolicyBindingRefreshError(review.SNAPSHOT_NOT_CURRENT_ERROR, 3),
            ({"policy_action": "allow"}, True),
        ]
    )
    monkeypatch.setattr(worker, "_review_native_edge_with_snapshot", native)
    assert _call(worker, tmp_path, time.monotonic() + 2)["policy_action"] == "allow"
    assert native.call_args_list[1].kwargs["policy_snapshot"]["generation"] == 4
    worker.policy_snapshot_publisher.request_control_binding_refresh.assert_called_once_with(3)


def test_superseded_snapshot_without_fresh_ack_stays_blocked(
    worker: HookWorker, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(worker, "_native_policy_snapshot", Mock(return_value=None))
    native = Mock(side_effect=review.NativePolicyBindingRefreshError(review.SNAPSHOT_NOT_CURRENT_ERROR, 3))
    monkeypatch.setattr(worker, "_review_native_edge_with_snapshot", native)
    response = _call(worker, tmp_path, time.monotonic() + 2)
    assert response["decision"] == "block"
    assert response["native_failure_code"] == review.SNAPSHOT_NOT_CURRENT_ERROR
    native.assert_called_once()


def _pre_tool_call(worker: HookWorker, tmp_path: Path, policy_snapshot: dict[str, object]):
    return worker._review_native_edge(
        payload={"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": {"file_path": "a.ts"}},
        harness="grok",
        event_name="PreToolUse",
        default_harness="grok",
        home_dir=tmp_path,
        guard_home=tmp_path / "guard",
        workspace=tmp_path,
        deadline=time.monotonic() + 2,
        policy_snapshot=policy_snapshot,
    )


def test_superseded_watch_snapshot_without_fresh_ack_keeps_recording(
    worker: HookWorker, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(worker, "_native_policy_snapshot", Mock(return_value=None))
    native = Mock(
        side_effect=review.NativePolicyBindingRefreshError(review.SNAPSHOT_NOT_CURRENT_ERROR, 3, recording_only=True)
    )
    monkeypatch.setattr(worker, "_review_native_edge_with_snapshot", native)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker_native.render_recording_only_pre_tool",
        lambda *_args, **_kwargs: {"policy_action": "allow"},
    )
    response = _pre_tool_call(worker, tmp_path, {"generation": 3, "mode": "observe"})
    assert response["policy_action"] != "block"
    assert response["native_failure_code"] == review.SNAPSHOT_NOT_CURRENT_ERROR
    native.assert_called_once()


@pytest.mark.parametrize("code", sorted(review.CONTROL_BINDING_REFRESH_ERRORS))
def test_control_binding_failure_without_fresh_ack_stays_blocked(
    worker: HookWorker, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: str
) -> None:
    monkeypatch.setattr(worker, "_native_policy_snapshot", Mock(return_value=None))
    native = Mock(side_effect=review.NativePolicyBindingRefreshError(code, 3, recording_only=True))
    monkeypatch.setattr(worker, "_review_native_edge_with_snapshot", native)
    assert _pre_tool_call(worker, tmp_path, {"generation": 3, "mode": "enforce"})["policy_action"] == "block"


def _post_tool_rejections(
    worker: HookWorker, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, codes: list[str], deadline: float | None
) -> tuple[list[object], list[dict[str, object]]]:
    calls: list[dict[str, object]] = []
    unavailable = Mock(wraps=native_module._record_unavailable_native)

    def reject(**kwargs: object) -> None:
        calls.append(kwargs)
        record_native_resident_client_failure_code(codes[len(calls) - 1])

    monkeypatch.setattr(worker, "_review_raw_hook_native", reject)
    monkeypatch.setattr(native_module, "_record_unavailable_native", unavailable)
    try:
        _response, native_used = worker._review_native_edge_with_snapshot(
            payload={"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_input": {"command": "true"}},
            harness="grok",
            event_name="PostToolUse",
            default_harness="grok",
            home_dir=tmp_path,
            guard_home=tmp_path / "guard",
            workspace=tmp_path,
            deadline=deadline,
            policy_snapshot={"mode": "enforce", "generation": 3},
            recording_only=False,
        )
    finally:
        record_native_resident_client_failure_code(None)
    assert native_used is False
    return [call.kwargs["reason_code"] for call in unavailable.call_args_list], calls


def test_superseded_post_tool_snapshot_retries_under_refreshed_binding(
    worker: HookWorker, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A contained test run publishes its own snapshot while the tool runs, so
    # the result review must rebind instead of answering fail-safe.
    monkeypatch.setattr(worker, "_native_policy_snapshot", Mock(return_value={"generation": 4, "mode": "observe"}))
    codes = [review.SNAPSHOT_NOT_CURRENT_ERROR, "native_hook_edge_unavailable"]
    reasons, calls = _post_tool_rejections(worker, tmp_path, monkeypatch, codes, time.monotonic() + 2)
    assert [call["policy_snapshot"]["generation"] for call in calls] == [3, 4]
    assert [call["observe_mode"] for call in calls] == [False, True]
    worker.policy_snapshot_publisher.request_control_binding_refresh.assert_called_once_with(3)
    assert reasons == ["native_post_tool_unavailable"]


@pytest.mark.parametrize("code", sorted(review.CONTROL_BINDING_REFRESH_ERRORS))
def test_post_tool_control_binding_rejection_does_not_refresh(
    worker: HookWorker, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: str
) -> None:
    reasons, calls = _post_tool_rejections(worker, tmp_path, monkeypatch, [code], time.monotonic() + 2)
    assert len(calls) == 1
    worker.policy_snapshot_publisher.request_control_binding_refresh.assert_not_called()
    assert reasons == ["native_post_tool_unavailable"]


@pytest.mark.parametrize("publish", [True, False])
def test_post_tool_refresh_needs_deadline_and_publisher(
    worker: HookWorker, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, publish: bool
) -> None:
    monkeypatch.setattr(worker, "_publish_native_policy", publish)
    deadline = None if publish else time.monotonic() + 2
    codes = [review.SNAPSHOT_NOT_CURRENT_ERROR]
    reasons, calls = _post_tool_rejections(worker, tmp_path, monkeypatch, codes, deadline)
    assert len(calls) == 1
    worker.policy_snapshot_publisher.request_control_binding_refresh.assert_not_called()
    assert reasons == ["native_post_tool_unavailable"]


@pytest.mark.parametrize("error", [OSError("resident gone"), TimeoutError(), NativePolicySnapshotError("not ready")])
def test_post_tool_refresh_failure_keeps_unavailable_answer(
    worker: HookWorker, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    monkeypatch.setattr(worker, "_native_policy_snapshot", Mock(side_effect=error))
    codes = [review.SNAPSHOT_NOT_CURRENT_ERROR]
    reasons, calls = _post_tool_rejections(worker, tmp_path, monkeypatch, codes, time.monotonic() + 2)
    assert len(calls) == 1
    worker.policy_snapshot_publisher.request_control_binding_refresh.assert_called_once_with(3)
    assert reasons == ["native_post_tool_unavailable"]
