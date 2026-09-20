# pyright: reportMissingImports=false
from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import commands_dispatch_cloud_review as cloud_review_dispatch
from codex_plugin_scanner.guard.runtime.exact_cloud_review import (
    EXACT_CLOUD_REVIEW_OPERATION,
    ExactCloudReviewError,
    enable_exact_cloud_review,
    exact_cloud_review_operations,
    exact_cloud_review_status,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_exact_cloud_review_support import (
    add_review_request as _add_request,
)
from tests.guard_exact_cloud_review_support import (
    connected_exact_review_store as _connected_store,
)
from tests.guard_exact_cloud_review_support import (
    review_request as _request,
)


def test_successful_connect_issues_cloud_review_capability_only_after_explicit_consent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _connected_store(tmp_path)
    monkeypatch.setattr(
        cloud_review_dispatch,
        "_refresh_cloud_review_worker",
        lambda _guard_home: {"status": "refreshed", "running": True, "sync_running": True},
    )
    base_payload: dict[str, object] = {"status": "connected"}

    unchanged = cloud_review_dispatch.apply_connect_time_cloud_review_consent(
        args=argparse.Namespace(enable_cloud_review=False),
        store=store,
        guard_home=store.guard_home,
        payload=base_payload,
        exit_code=0,
    )
    assert unchanged is base_payload
    assert exact_cloud_review_status(store)["enabled"] is False
    assert exact_cloud_review_operations(store) == (EXACT_CLOUD_REVIEW_OPERATION,)

    failed_connect = cloud_review_dispatch.apply_connect_time_cloud_review_consent(
        args=argparse.Namespace(enable_cloud_review=True),
        store=store,
        guard_home=store.guard_home,
        payload=base_payload,
        exit_code=1,
    )
    assert failed_connect["cloud_review"] == {
        "enabled": False,
        "reason": "connect_not_completed",
    }
    assert exact_cloud_review_operations(store) == (EXACT_CLOUD_REVIEW_OPERATION,)

    connected = cloud_review_dispatch.apply_connect_time_cloud_review_consent(
        args=argparse.Namespace(enable_cloud_review=True),
        store=store,
        guard_home=store.guard_home,
        payload=base_payload,
        exit_code=0,
    )
    cloud_review = connected["cloud_review"]
    assert isinstance(cloud_review, dict)
    assert cloud_review["enabled"] is True
    assert cloud_review["pending_requests_requeued"] == 0
    assert cloud_review["pending_request_requeue_status"] == "requeued"
    assert cloud_review["worker"] == {"status": "refreshed", "running": True, "sync_running": True}
    assert isinstance(cloud_review["capability"], dict)
    assert exact_cloud_review_operations(store) == (EXACT_CLOUD_REVIEW_OPERATION,)


def test_cloud_review_enable_requeues_existing_pending_requests(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    store = _connected_store(tmp_path)
    request = _request("pending-before-consent")
    _add_request(store, request)
    monkeypatch.setattr(
        cloud_review_dispatch,
        "_refresh_cloud_review_worker",
        lambda _guard_home: {"status": "refreshed", "running": True, "sync_running": True},
    )

    exit_code = cloud_review_dispatch._run_guard_cloud_review_command(
        argparse.Namespace(
            cloud_review_command="enable",
            expires_in_days=30,
            json=True,
        ),
        guard_home=store.guard_home,
        store=store,
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["pending_requests_requeued"] == 1
    assert payload["pending_request_requeue_status"] == "requeued"
    assert payload["worker"] == {"status": "refreshed", "running": True, "sync_running": True}


def test_cloud_review_enable_failure_does_not_requeue_pending_requests(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    store = _connected_store(tmp_path)
    _add_request(store, _request("enable-fails-before-requeue"))

    def fail_enable(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise ExactCloudReviewError("cloud_review_grant_binding_missing")

    monkeypatch.setattr(
        cloud_review_dispatch,
        "enable_exact_cloud_review",
        fail_enable,
    )

    exit_code = cloud_review_dispatch._run_guard_cloud_review_command(
        argparse.Namespace(cloud_review_command="enable", expires_in_days=30, json=True),
        guard_home=store.guard_home,
        store=store,
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 2
    assert payload["error"] == "cloud_review_grant_binding_missing"
    assert exact_cloud_review_status(store)["enabled"] is False
    assert exact_cloud_review_operations(store) == (EXACT_CLOUD_REVIEW_OPERATION,)
    with store._connect() as connection:
        event_types = [
            row[0]
            for row in connection.execute(
                "select event_type from guard_review_outbox_events order by stream_sequence"
            ).fetchall()
        ]
    assert event_types == ["review.request.created"]


def test_cloud_review_requeue_database_failure_is_retryable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _connected_store(tmp_path)

    def fail_requeue(*, changed_at: str, require_binding: bool) -> int:
        del changed_at
        assert require_binding is True
        raise sqlite3.OperationalError("database is busy")

    monkeypatch.setattr(store, "requeue_pending_review_events", fail_requeue)

    with pytest.raises(cloud_review_dispatch.PendingReviewRequeueError):
        cloud_review_dispatch._requeue_pending_cloud_review_requests(store)


def test_connect_consent_does_not_enable_capability_when_requeue_needs_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _connected_store(tmp_path)

    def fail_requeue(_store: GuardStore) -> int:
        raise cloud_review_dispatch.PendingReviewRequeueError

    monkeypatch.setattr(
        cloud_review_dispatch,
        "_requeue_pending_cloud_review_requests",
        fail_requeue,
    )
    monkeypatch.setattr(
        cloud_review_dispatch,
        "_refresh_cloud_review_worker",
        lambda _guard_home: {"status": "refreshed", "running": True, "sync_running": True},
    )

    connected = cloud_review_dispatch.apply_connect_time_cloud_review_consent(
        args=argparse.Namespace(enable_cloud_review=True),
        store=store,
        guard_home=store.guard_home,
        payload={"status": "connected"},
        exit_code=0,
    )

    cloud_review = connected["cloud_review"]
    assert isinstance(cloud_review, dict)
    assert cloud_review["capability_enabled"] is True
    assert cloud_review["enabled"] is False
    assert cloud_review["reason"] == "pending_request_requeue_failed"
    assert cloud_review["pending_request_requeue_status"] == "retry_required"
    assert cloud_review["retained_existing_capability"] is False
    assert cloud_review["activation_status"] == "enabled_requeue_retry_required"
    assert exact_cloud_review_operations(store) == (EXACT_CLOUD_REVIEW_OPERATION,)


def test_cloud_review_enable_reports_requeue_retry_without_crashing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    store = _connected_store(tmp_path)

    def fail_requeue(_store: GuardStore) -> int:
        raise cloud_review_dispatch.PendingReviewRequeueError

    monkeypatch.setattr(
        cloud_review_dispatch,
        "_requeue_pending_cloud_review_requests",
        fail_requeue,
    )
    monkeypatch.setattr(
        cloud_review_dispatch,
        "_refresh_cloud_review_worker",
        lambda _guard_home: {"status": "refreshed", "running": True, "sync_running": True},
    )

    exit_code = cloud_review_dispatch._run_guard_cloud_review_command(
        argparse.Namespace(cloud_review_command="enable", expires_in_days=30, json=True),
        guard_home=store.guard_home,
        store=store,
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 2
    assert payload["status"] == "error"
    assert payload["error"] == "pending_request_requeue_failed"
    assert payload["pending_requests_requeued"] == 0
    assert payload["pending_request_requeue_status"] == "retry_required"
    assert payload["capability_enabled"] is True
    assert payload["retained_existing_capability"] is False
    assert payload["activation_status"] == "enabled_requeue_retry_required"
    assert exact_cloud_review_operations(store) == (EXACT_CLOUD_REVIEW_OPERATION,)


def test_connect_consent_reports_retained_capability_as_failed_activation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _connected_store(tmp_path)
    enable_exact_cloud_review(store)

    def fail_requeue(_store: GuardStore) -> int:
        raise cloud_review_dispatch.PendingReviewRequeueError

    monkeypatch.setattr(
        cloud_review_dispatch,
        "_requeue_pending_cloud_review_requests",
        fail_requeue,
    )

    connected = cloud_review_dispatch.apply_connect_time_cloud_review_consent(
        args=argparse.Namespace(enable_cloud_review=True),
        store=store,
        guard_home=store.guard_home,
        payload={"status": "connected"},
        exit_code=0,
    )

    cloud_review = connected["cloud_review"]
    assert isinstance(cloud_review, dict)
    assert cloud_review["enabled"] is False
    assert cloud_review["capability_enabled"] is True
    assert cloud_review["retained_existing_capability"] is True
    assert cloud_review["reason"] == "pending_request_requeue_failed"
    assert cloud_review["activation_status"] == "enabled_requeue_retry_required"


def test_cloud_review_enable_reports_retained_capability_when_requeue_retry_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    store = _connected_store(tmp_path)
    enable_exact_cloud_review(store)

    def fail_requeue(_store: GuardStore) -> int:
        raise cloud_review_dispatch.PendingReviewRequeueError

    monkeypatch.setattr(
        cloud_review_dispatch,
        "_requeue_pending_cloud_review_requests",
        fail_requeue,
    )

    exit_code = cloud_review_dispatch._run_guard_cloud_review_command(
        argparse.Namespace(cloud_review_command="enable", expires_in_days=30, json=True),
        guard_home=store.guard_home,
        store=store,
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 2
    assert payload["error"] == "pending_request_requeue_failed"
    assert payload["capability_enabled"] is True
    assert payload["retained_existing_capability"] is True
    assert payload["activation_status"] == "enabled_requeue_retry_required"
    assert exact_cloud_review_operations(store) == (EXACT_CLOUD_REVIEW_OPERATION,)
