"""Tests for the hook enrichment queue."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.hook_enrichment_queue import (
    HookEnrichmentQueue,
    HookEnrichmentTask,
)
from codex_plugin_scanner.guard.store import GuardStore


@pytest.fixture()
def store(tmp_path: Path) -> GuardStore:
    return GuardStore(tmp_path / "guard-home")


class TestEnrichmentQueueBasic:
    def test_enqueue_and_pending_count(self) -> None:
        queue = HookEnrichmentQueue(max_items=10)
        task = HookEnrichmentTask(
            task_id="test-1",
            task_type="receipt_enrichment",
            payload={"harness": "pi", "event_name": "PostToolUse", "decision": "allow"},
            created_at="2026-01-01T00:00:00Z",
        )
        assert queue.enqueue(task) is True
        assert queue.pending_count == 1

    def test_enqueue_returns_false_on_overflow(self) -> None:
        queue = HookEnrichmentQueue(max_items=2)
        for i in range(3):
            task = HookEnrichmentTask(
                task_id=f"test-{i}",
                task_type="receipt_enrichment",
                payload={"harness": "pi"},
                created_at="2026-01-01T00:00:00Z",
            )
            result = queue.enqueue(task)
            if i < 2:
                assert result is True
            else:
                assert result is False

        assert queue.dropped_count == 1
        assert queue.pending_count == 2

    def test_drain_once_processes_tasks(self, store: GuardStore) -> None:
        queue = HookEnrichmentQueue(store=store, max_items=100)
        for i in range(5):
            task = queue.make_receipt_task(
                task_id=f"receipt-{i}",
                harness="pi",
                event_name="PostToolUse",
                decision="allow",
                reason_code="source_full_scan_allow",
            )
            queue.enqueue(task)

        drained = queue.drain_once(max_items=3)
        assert drained == 3
        assert queue.pending_count == 2

        # Drain the rest
        drained = queue.drain_once(max_items=10)
        assert drained == 2
        assert queue.pending_count == 0

    def test_drain_once_with_empty_queue(self) -> None:
        queue = HookEnrichmentQueue(max_items=10)
        assert queue.drain_once() == 0


class TestEnrichmentQueueSecurity:
    def test_receipt_task_payload_excludes_raw_output(self) -> None:
        queue = HookEnrichmentQueue(max_items=10)
        task = queue.make_receipt_task(
            task_id="test-1",
            harness="pi",
            event_name="PostToolUse",
            decision="allow",
            reason_code="source_full_scan_allow",
            reason="Some reason",
            workspace="/workspace",
        )

        # Verify no raw output fields exist
        assert "tool_response" not in task.payload
        assert "stdout" not in task.payload
        assert "content" not in task.payload
        assert "output" not in task.payload
        assert "secret" not in task.payload
        assert "prompt" not in task.payload

    def test_receipt_task_payload_has_only_safe_fields(self) -> None:
        queue = HookEnrichmentQueue(max_items=10)
        task = queue.make_receipt_task(
            task_id="test-1",
            harness="pi",
            event_name="PostToolUse",
            decision="allow",
            reason_code="source_full_scan_allow",
        )

        expected_keys = {"harness", "event_name", "decision", "reason_code", "reason", "workspace"}
        assert set(task.payload.keys()) == expected_keys

    def test_dropped_tasks_increment_counter(self) -> None:
        queue = HookEnrichmentQueue(max_items=1)
        task1 = HookEnrichmentTask(
            task_id="t1",
            task_type="receipt_enrichment",
            payload={},
            created_at="2026-01-01T00:00:00Z",
        )
        task2 = HookEnrichmentTask(
            task_id="t2",
            task_type="receipt_enrichment",
            payload={},
            created_at="2026-01-01T00:00:00Z",
        )
        assert queue.enqueue(task1) is True
        assert queue.enqueue(task2) is False  # Queue full
        assert queue.dropped_count == 1

    def test_drain_silently_skips_failed_tasks(self, store: GuardStore) -> None:
        queue = HookEnrichmentQueue(store=store, max_items=100)
        # Create a task with invalid receipt data that will fail processing
        bad_task = HookEnrichmentTask(
            task_id="bad-1",
            task_type="receipt_enrichment",
            payload={"harness": None, "event_name": None},  # Invalid types
            created_at="2026-01-01T00:00:00Z",
        )
        queue.enqueue(bad_task)

        # Should not raise
        # Should not raise — drain_once removes tasks from the queue
        # without processing them (best-effort enrichment).
        drained = queue.drain_once(max_items=1)
        assert drained == 1


class TestEnrichmentQueueThreadSafety:
    def test_concurrent_enqueue(self) -> None:
        """Test that enqueue is thread-safe under concurrent access."""
        import threading

        queue = HookEnrichmentQueue(max_items=10000)
        barrier = threading.Barrier(4)
        results: list[bool] = []

        def worker() -> None:
            barrier.wait()
            local_results: list[bool] = []
            for i in range(100):
                task = HookEnrichmentTask(
                    task_id=f"task-{threading.get_ident()}-{i}",
                    task_type="receipt_enrichment",
                    payload={},
                    created_at="2026-01-01T00:00:00Z",
                )
                local_results.append(queue.enqueue(task))
            results.extend(local_results)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All 400 tasks should be enqueued (under max_items)
        assert queue.pending_count == 400
        assert all(results)
