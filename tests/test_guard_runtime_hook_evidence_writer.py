from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from errno import ENOSPC
from pathlib import Path
from unittest.mock import patch

import pytest

from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_journal import _McpDiscoveryRecord
from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer import RuntimeHookEvidenceWriter
from codex_plugin_scanner.guard.runtime.composio_discovery import ComposioActionSchema
from codex_plugin_scanner.guard.store import GuardStore


def test_provider_discovery_is_private_and_persists_off_the_hook_thread(tmp_path: Path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "home")
    entered, release = threading.Event(), threading.Event()
    original = store.record_composio_discovery

    def blocked_record(*args, **kwargs):
        entered.set()
        assert release.wait(timeout=2)
        return original(*args, **kwargs)

    monkeypatch.setattr(store, "record_composio_discovery", blocked_record)
    response = {
        "successful": True,
        "error": None,
        "data": {
            "tool_schemas": {
                "SLACK_SEARCH_MESSAGES": {
                    "toolkit": "slack",
                    "tool_slug": "SLACK_SEARCH_MESSAGES",
                    "description": "Synthetic tool",
                    "input_schema": {"type": "object"},
                    "hasFullSchema": True,
                }
            },
            "session": {"session_id": "private-session-do-not-persist"},
        },
    }
    writer = RuntimeHookEvidenceWriter(store=store)
    try:
        started = time.monotonic()
        assert writer.submit_composio_discovery(
            harness="codex",
            succeeded=True,
            payload={
                "tool_name": "mcp__codex_apps__composio__composio_search_tools",
                "tool_response": {"content": [{"type": "text", "text": json.dumps(response)}]},
                "tool_input": {"query": "private-query-do-not-persist"},
            },
        )
        assert time.monotonic() - started < 0.1
        assert entered.wait(timeout=1)
        journal = (store.guard_home / "runtime-hook-evidence.jsonl").read_text()
        assert "SLACK_SEARCH_MESSAGES" in journal
        assert "private-session-do-not-persist" not in journal
        assert "private-query-do-not-persist" not in journal
    finally:
        release.set()
        assert writer.stop(timeout_seconds=2)
    assert writer.stats()["processed"] == 1
    item = store.list_local_cli_items()[0]
    assert item["provider_catalog"]["known_count"] == 1
    assert store.read_local_cli_grant(item["cli_id"]) is None


def test_provider_discovery_rejects_error_results_and_unqualified_sources(tmp_path: Path) -> None:
    writer = RuntimeHookEvidenceWriter(store=GuardStore(tmp_path / "home"))
    try:
        assert not writer.submit_composio_discovery(
            harness="codex",
            succeeded=False,
            payload={
                "tool_name": "mcp__codex_apps__composio__composio_search_tools",
                "tool_response": {},
            },
        )
        assert not writer.submit_composio_discovery(
            harness="codex",
            succeeded=True,
            payload={
                "tool_name": "composio_search_tools",
                "tool_response": {},
            },
        )
        assert writer.stats()["accepted"] == 0
    finally:
        assert writer.stop(timeout_seconds=1)


def test_provider_metadata_journal_recovers_after_restart(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "home")
    record = _McpDiscoveryRecord(
        "fixture-provider-record",
        "codex",
        "mcp__codex_apps__composio__composio_search_tools",
        "2026-09-27T12:00:00+00:00",
        (ComposioActionSchema("slack", "SLACK_SEARCH_MESSAGES", "Synthetic metadata", {"type": "object"}, True),),
    )
    journal = store.guard_home / "runtime-hook-evidence.jsonl"
    journal.write_bytes(record.serialized())
    journal.chmod(0o600)
    writer = RuntimeHookEvidenceWriter(store=store, batch_wait_seconds=0)
    assert writer.stop(timeout_seconds=6)
    assert writer.stats()["recovered"] == 1
    assert writer.stats()["durable_pending"] == 0
    assert store.list_local_cli_items()[0]["provider_catalog"]["known_count"] == 1
    assert journal.read_text() == ""


def test_malformed_provider_workflow_journal_does_not_block_writer_start(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "home")
    record = _McpDiscoveryRecord(
        "fixture-provider-record",
        "codex",
        "mcp__codex_apps__composio__composio_search_tools",
        "2026-09-27T12:00:00+00:00",
        (ComposioActionSchema("slack", "SLACK_SEARCH_MESSAGES", "Synthetic metadata", {"type": "object"}, True),),
    )
    malformed = json.loads(record.serialized())
    malformed["workflow_proposals"] = None
    journal = store.guard_home / "runtime-hook-evidence.jsonl"
    journal.write_text(json.dumps(malformed) + "\n")
    journal.chmod(0o600)
    writer = RuntimeHookEvidenceWriter(store=store, batch_wait_seconds=0)
    try:
        assert writer.stats()["recovered"] == 0
        assert writer.stats()["failures"] >= 1
    finally:
        assert writer.stop(timeout_seconds=2)


def test_hook_worker_forwards_successful_provider_results_to_background_writer(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "home")
    writer = RuntimeHookEvidenceWriter(store=store)
    worker = HookWorker(store=store, activity_writer=writer, wait_for_native_policy=False, publish_native_policy=False)
    try:
        worker._record_post_tool_activity(
            harness="codex",
            succeeded=True,
            payload={
                "tool_name": "mcp__codex_apps__composio__composio_search_tools",
                "tool_response": {
                    "successful": True,
                    "error": None,
                    "data": {
                        "tool_schemas": {
                            "SLACK_SEARCH_MESSAGES": {
                                "toolkit": "slack",
                                "tool_slug": "SLACK_SEARCH_MESSAGES",
                                "description": "Synthetic tool",
                                "input_schema": {"type": "object"},
                                "hasFullSchema": True,
                            },
                        }
                    },
                },
            },
        )
        assert writer.stop(timeout_seconds=6)
        provider_catalog = next(
            item["provider_catalog"] for item in store.list_local_cli_items() if "provider_catalog" in item
        )
        assert provider_catalog["known_count"] == 1
    finally:
        writer.stop(timeout_seconds=2)
        worker.close()
        worker.policy_snapshot_publisher.close()


def test_writer_keeps_blocked_persistence_off_submitter_without_raw_payload(tmp_path: Path) -> None:
    entered = threading.Event()
    release = threading.Event()
    recorded: list[object] = []

    def record(**kwargs: object) -> bool:
        recorded.append(kwargs["has_command"])
        entered.set()
        assert release.wait(timeout=1)
        return True

    with patch(
        "codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer.persist_deferred_post_hook_command_activity",
        side_effect=record,
    ):
        writer = RuntimeHookEvidenceWriter(store=GuardStore(tmp_path / "guard-home"))
        started = time.monotonic()
        metadata: dict[str, object] = {"command": "rg safe"}
        try:
            accepted = writer.submit_command_activity(
                harness="pi",
                event="PostToolUse",
                payload={"tool_name": "read", "tool_call_id": "private-request-id", "metadata": metadata},
                succeeded=True,
            )
            metadata["command"] = "changed after submission"
            elapsed = time.monotonic() - started
            assert accepted is True
            assert elapsed < 0.1
            assert entered.wait(timeout=1)
            journal = (tmp_path / "guard-home" / "runtime-hook-evidence.jsonl").read_text(encoding="utf-8")
            assert "rg safe" not in journal
            assert "changed after submission" not in journal
            assert "private-request-id" not in journal
        finally:
            release.set()
            assert writer.stop(timeout_seconds=1)

    assert writer.stats()["processed"] == 1
    assert recorded == [False]


def test_writer_drops_only_evidence_when_queue_is_full(tmp_path: Path) -> None:
    entered = threading.Event()
    release = threading.Event()

    def record(**_kwargs: object) -> bool:
        entered.set()
        assert release.wait(timeout=1)
        return True

    with patch(
        "codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer.persist_deferred_post_hook_command_activity",
        side_effect=record,
    ):
        writer = RuntimeHookEvidenceWriter(
            store=GuardStore(tmp_path / "guard-home"),
            max_records=1,
            max_bytes=1_024,
            batch_wait_seconds=0,
        )
        try:
            assert writer.submit_command_activity(
                harness="pi",
                event="PostToolUse",
                payload={"command": "first"},
                succeeded=True,
            )
            assert entered.wait(timeout=1)
            assert writer.submit_command_activity(
                harness="pi",
                event="PostToolUse",
                payload={"command": "second"},
                succeeded=True,
            )
            assert not writer.submit_command_activity(
                harness="pi",
                event="PostToolUse",
                payload={"command": "third"},
                succeeded=True,
            )
            assert writer.stats()["dropped"] == 1
        finally:
            release.set()
            assert writer.stop(timeout_seconds=1)


def test_writer_stops_with_bounded_sqlite_contention(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    lock = sqlite3.connect(store.path)
    _ = lock.execute("begin immediate")
    writer = RuntimeHookEvidenceWriter(
        store=store,
        batch_wait_seconds=0,
    )
    try:
        assert writer.submit_command_activity(
            harness="pi",
            event="PostToolUse",
            payload={"command": "rg safe"},
            succeeded=True,
        )
        time.sleep(0.02)
        started = time.monotonic()
        assert writer.stop(timeout_seconds=1)
        assert time.monotonic() - started < 0.5
        assert writer.stats()["durable_pending"] == 1
        assert writer.stats()["failures"] >= 1
    finally:
        lock.rollback()
        lock.close()


def test_writer_drains_accepted_records_on_shutdown(tmp_path: Path) -> None:
    recorded: list[bool] = []

    def record(**kwargs: object) -> bool:
        recorded.append(bool(kwargs["has_command"]))
        return True

    with patch(
        "codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer.persist_deferred_post_hook_command_activity",
        side_effect=record,
    ):
        writer = RuntimeHookEvidenceWriter(
            store=GuardStore(tmp_path / "guard-home"),
            batch_wait_seconds=0.025,
        )
        for command in ("first", "second", "third"):
            assert writer.submit_command_activity(
                harness="pi",
                event="PostToolUse",
                payload={"command": command},
                succeeded=True,
            )
        assert writer.stop(timeout_seconds=1)

    assert recorded == [True, True, True]
    assert writer.stats()["durable_pending"] == 0


def test_writer_recovers_accepted_record_after_failed_process(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    journal = guard_home / "runtime-hook-evidence.jsonl"
    failed = threading.Event()

    def fail(**_kwargs: object) -> bool:
        failed.set()
        raise sqlite3.OperationalError("database is locked")

    with patch(
        "codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer.persist_deferred_post_hook_command_activity",
        side_effect=fail,
    ):
        first = RuntimeHookEvidenceWriter(store=GuardStore(guard_home), batch_wait_seconds=0)
        assert first.submit_command_activity(
            harness="pi",
            event="PostToolUse",
            payload={"command": "recover me"},
            succeeded=True,
        )
        assert failed.wait(timeout=1)
        assert first.stop(timeout_seconds=1)
        assert first.stats()["durable_pending"] == 1
        assert journal.stat().st_mode & 0o777 == 0o600

    recorded: list[object] = []
    with patch(
        "codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer.persist_deferred_post_hook_command_activity",
        side_effect=lambda **kwargs: recorded.append(kwargs["has_command"]) or True,
    ):
        recovered = RuntimeHookEvidenceWriter(store=GuardStore(guard_home), batch_wait_seconds=0)
        assert recovered.stop(timeout_seconds=1)

    assert recovered.stats()["recovered"] == 1
    assert recovered.stats()["durable_pending"] == 0
    assert recorded == [True]


def test_writer_retries_transient_partial_batch_failure_live(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    attempts: list[int] = []

    def record(**kwargs: object) -> bool:
        del kwargs
        attempts.append(len(attempts) + 1)
        if len(attempts) == 2:
            raise sqlite3.OperationalError("partial batch failure")
        return True

    with patch(
        "codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer.persist_deferred_post_hook_command_activity",
        side_effect=record,
    ):
        writer = RuntimeHookEvidenceWriter(store=GuardStore(guard_home), batch_wait_seconds=0.05)
        for command in ("first", "second", "third"):
            assert writer.submit_command_activity(
                harness="pi",
                event="PostToolUse",
                payload={"command": command},
                succeeded=True,
            )
        deadline = time.monotonic() + 1
        while writer.stats()["processed"] != 3 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert writer.stop(timeout_seconds=1)

    assert attempts == [1, 2, 3, 4]
    assert writer.stats()["processed"] == 3
    assert writer.stats()["durable_pending"] == 0
    journal = (guard_home / "runtime-hook-evidence.jsonl").read_text(encoding="utf-8")
    assert journal == ""
    assert "first" not in journal
    assert "second" not in journal
    assert "third" not in journal


def test_writer_rejects_record_when_durable_journal_is_full(tmp_path: Path) -> None:
    writer = RuntimeHookEvidenceWriter(
        store=GuardStore(tmp_path / "guard-home"),
        batch_wait_seconds=0,
    )
    try:
        attempted = threading.Event()

        def fail_write(*_args: object) -> int:
            attempted.set()
            raise OSError(ENOSPC, "No space left on device")

        with patch("os.write", side_effect=fail_write):
            assert writer.submit_command_activity(
                harness="pi",
                event="PostToolUse",
                payload={"command": "not accepted"},
                succeeded=True,
            )
            assert attempted.wait(timeout=1)
            deadline = time.monotonic() + 1
            while writer.stats()["dropped"] != 1 and time.monotonic() < deadline:
                time.sleep(0.01)
        stats = writer.stats()
        assert stats["accepted"] == 1
        assert stats["dropped"] == 1
        assert stats["failures"] == 1
        assert stats["degraded"] is True
    finally:
        assert writer.stop(timeout_seconds=1)


@pytest.mark.skipif(os.name == "nt", reason="unprivileged Windows runners cannot create symlinks")
def test_writer_rejects_symlinked_journal_without_modifying_target(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    victim = tmp_path / "victim.txt"
    victim.write_text("do not modify", encoding="utf-8")
    (guard_home / "runtime-hook-evidence.jsonl").symlink_to(victim)

    writer = RuntimeHookEvidenceWriter(store=GuardStore(guard_home), batch_wait_seconds=0)
    try:
        assert writer.submit_command_activity(
            harness="pi",
            event="PostToolUse",
            payload={"command": "rg safe"},
            succeeded=True,
        )
        deadline = time.monotonic() + 1
        while writer.stats()["dropped"] != 1 and time.monotonic() < deadline:
            time.sleep(0.01)
    finally:
        assert writer.stop(timeout_seconds=1)

    assert victim.read_text(encoding="utf-8") == "do not modify"
    assert writer.stats()["degraded"] is True


def test_writer_bounds_oversized_journal_recovery(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    (guard_home / "runtime-hook-evidence.jsonl").write_bytes(b"x" * 65)

    writer = RuntimeHookEvidenceWriter(store=GuardStore(guard_home), max_bytes=64)
    try:
        assert writer.stats()["recovered"] == 0
        assert writer.stats()["degraded"] is True
    finally:
        assert writer.stop(timeout_seconds=1)
