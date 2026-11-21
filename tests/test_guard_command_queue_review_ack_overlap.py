"""An exact Review job settles while its acknowledgement is in flight."""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import command_capability, command_queue
from codex_plugin_scanner.guard.runtime.command_queue_state import (
    COMMAND_QUEUE_STATE_KEY,
    current_command_queue_lane,
)
from codex_plugin_scanner.guard.runtime.exact_cloud_review import EXACT_CLOUD_REVIEW_OPERATION
from tests.test_guard_command_queue import FakeStore, _context
from tests.test_guard_command_queue_review_drain import _enable_queue, _exact_job, _in_lane


def _exact_review_job() -> dict[str, object]:
    return {**_exact_job("job-1"), "operation": EXACT_CLOUD_REVIEW_OPERATION, "payload": {}, "leaseId": "lease-1"}


def test_poll_once_authorizes_while_acknowledging(tmp_path: Path, monkeypatch) -> None:
    store = FakeStore(tmp_path / "guard-home")
    _enable_queue(store, monkeypatch)
    exact_review_job = _exact_review_job()
    monkeypatch.setattr(command_queue, "_lease_job_with_401_retry", lambda *_args, **_kwargs: exact_review_job)
    authorized = threading.Event()
    authorizing_lanes: list[str] = []
    acknowledged: list[bool] = []

    def authorize(_store: object, job: dict[str, object], **_kwargs: object) -> object:
        authorizing_lanes.append(current_command_queue_lane().state_key)
        authorized.set()
        raise command_capability.CommandCapabilityError("stop after authorize")

    def acknowledge(_auth_context: object, _job: dict[str, object]) -> None:
        # The ack only returns once authorization has run beside it.
        acknowledged.append(authorized.wait(5))

    monkeypatch.setattr(command_queue, "authorize_command_queue_job", authorize)
    monkeypatch.setattr(command_queue, "_heartbeat", acknowledge)
    monkeypatch.setattr(command_queue, "_post_result", lambda *_args: None)

    _in_lane(1, lambda: command_queue.poll_command_queue_once(store, _context(tmp_path)))

    assert authorizing_lanes == [f"{COMMAND_QUEUE_STATE_KEY}.review_drain.1"]
    assert acknowledged == [True]


def test_poll_once_settles_an_exact_review_job_while_acknowledging_and_posts_after_the_ack(
    tmp_path: Path, monkeypatch, caplog
) -> None:
    # The exact Review apply checks the capability, expiry, replay and pending
    # state again as it runs, so it need not wait out the ack round trip. The
    # ack still reaches Cloud before the result, and a failed ack leaves the
    # posted result to tell Cloud how the lease ended.
    store = FakeStore(tmp_path / "guard-home")
    _enable_queue(store, monkeypatch)
    exact_review_job = _exact_review_job()
    monkeypatch.setattr(command_queue, "_lease_job_with_401_retry", lambda *_args, **_kwargs: exact_review_job)
    settled = threading.Event()
    events: list[str] = []

    def settle(_store: object, _context: object, _job: dict[str, object], _authorized: object) -> dict[str, object]:
        events.append("settle")
        settled.set()
        return {"approved": True}

    def acknowledge(_auth_context: object, _job: dict[str, object]) -> None:
        # The ack only returns once the job has settled beside it.
        if not settled.wait(5):
            events.append("settle never started")
        events.append("ack")
        raise RuntimeError("ack failed")

    monkeypatch.setattr(command_queue, "authorize_command_queue_job", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(command_queue, "_settle_authorized_job", settle)
    monkeypatch.setattr(command_queue, "_heartbeat", acknowledge)
    monkeypatch.setattr(command_queue, "_post_result", lambda *_args: events.append("result"))

    status = command_queue.poll_command_queue_once(store, _context(tmp_path))

    assert events == ["settle", "ack", "result"]
    assert status["pending_result"] is None
    assert "Guard Review acknowledgement failed; posting the result" in caplog.text


def test_poll_once_still_ends_the_process_when_the_acknowledgement_does(tmp_path: Path, monkeypatch) -> None:
    store = FakeStore(tmp_path / "guard-home")
    _enable_queue(store, monkeypatch)
    exact_review_job = _exact_review_job()
    monkeypatch.setattr(command_queue, "_lease_job_with_401_retry", lambda *_args, **_kwargs: exact_review_job)
    posted: list[object] = []

    def acknowledge(_auth_context: object, _job: dict[str, object]) -> None:
        raise SystemExit("daemon stopping")

    monkeypatch.setattr(command_queue, "authorize_command_queue_job", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(command_queue, "_settle_authorized_job", lambda *_args: {"approved": True})
    monkeypatch.setattr(command_queue, "_heartbeat", acknowledge)
    monkeypatch.setattr(command_queue, "_post_result", lambda *args: posted.append(args))

    with pytest.raises(SystemExit, match="daemon stopping"):
        command_queue.poll_command_queue_once(store, _context(tmp_path))
    assert posted == []
