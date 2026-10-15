from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from ci.gauntlet import guard_tap
from ci.gauntlet.guard_tap import GuardTap, read_tap


class _Worker:
    def __init__(self) -> None:
        self._last_native_decision_receipt: dict[str, object] | None = None
        self.both_reviewing = threading.Barrier(2, timeout=5)

    def _record_native_decision_receipt(self, receipt: object) -> dict[str, object] | None:
        accepted = dict(receipt) if isinstance(receipt, dict) else None
        self._last_native_decision_receipt = accepted
        return accepted

    def review_http_payload(self, *, payload: dict[str, object], **_kwargs: object) -> dict[str, object]:
        tool = str(payload["tool_name"])
        self._record_native_decision_receipt({"decision_id": tool})
        # Both reviews must be in flight at once, as they are in the daemon.
        self.both_reviewing.wait()
        return {"tool": tool}


def test_tap_lets_parallel_reviews_overlap_and_keeps_each_receipt(tmp_path: Path) -> None:
    worker = _Worker()
    log = tmp_path / "tap.jsonl"
    errors: list[BaseException] = []

    def call(tool: str) -> None:
        try:
            worker.review_http_payload(payload={"tool_name": tool}, default_harness="claude-code")
        except BaseException as error:
            errors.append(error)

    with GuardTap(worker, log):
        threads = [threading.Thread(target=call, args=(tool,)) for tool in ("Read", "Bash")]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

    assert errors == []
    rows = read_tap(log)
    assert sorted((row["payload"]["tool_name"], row["receipt"]["decision_id"]) for row in rows) == [
        ("Bash", "Bash"),
        ("Read", "Read"),
    ]
    assert "review_http_payload" not in worker.__dict__
    assert "_record_native_decision_receipt" not in worker.__dict__


def test_tap_exit_waits_for_a_running_review_to_record_its_receipt(tmp_path: Path) -> None:
    worker = _Worker()
    log = tmp_path / "tap.jsonl"
    started = threading.Event()
    release = threading.Event()

    def slow_review(*, payload: dict[str, object], **_kwargs: object) -> dict[str, object]:
        started.set()
        release.wait(timeout=5)
        worker._record_native_decision_receipt({"decision_id": "late"})
        return {"tool": payload["tool_name"]}

    worker.review_http_payload = slow_review
    tap = GuardTap(worker, log)
    tap.__enter__()
    thread = threading.Thread(target=lambda: worker.review_http_payload(payload={"tool_name": "Read"}))
    thread.start()
    assert started.wait(timeout=5)
    exiting = threading.Thread(target=tap.__exit__)
    exiting.start()
    # Let the review finish only once the tap has started leaving.
    deadline = time.monotonic() + 5
    while "review_http_payload" in worker.__dict__ and time.monotonic() < deadline:
        time.sleep(0.01)
    assert "review_http_payload" not in worker.__dict__
    release.set()
    exiting.join(timeout=10)
    thread.join(timeout=10)

    rows = read_tap(log)
    assert [row["receipt"]["decision_id"] for row in rows] == ["late"]
    assert "_record_native_decision_receipt" not in worker.__dict__


def test_review_that_outlives_the_drain_removes_the_recorder_when_it_ends(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(guard_tap, "_DRAIN_SECONDS", 0.05)
    worker = _Worker()
    log = tmp_path / "tap.jsonl"
    started = threading.Event()
    release = threading.Event()

    def slow_review(*, payload: dict[str, object], **_kwargs: object) -> dict[str, object]:
        started.set()
        release.wait(timeout=5)
        worker._record_native_decision_receipt({"decision_id": "late"})
        return {"tool": payload["tool_name"]}

    worker.review_http_payload = slow_review
    tap = GuardTap(worker, log)
    tap.__enter__()
    thread = threading.Thread(target=lambda: worker.review_http_payload(payload={"tool_name": "Read"}))
    thread.start()
    assert started.wait(timeout=5)
    tap.__exit__()
    # The drain gave up, so the running review still needs the recorder.
    assert "_record_native_decision_receipt" in worker.__dict__
    release.set()
    thread.join(timeout=10)

    assert [row["receipt"]["decision_id"] for row in read_tap(log)] == ["late"]
    assert "_record_native_decision_receipt" not in worker.__dict__
