"""Remote approval callbacks retain daemon configuration scope and wait bounds."""

from __future__ import annotations

import threading
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.config_source_io import GuardConfigSourceError
from codex_plugin_scanner.guard.daemon import command_queue_worker
from codex_plugin_scanner.guard.live_process_identity import current_process_identity
from codex_plugin_scanner.guard.runtime import command_executors, command_queue
from codex_plugin_scanner.guard.store import GuardStore

from .test_guard_continuation_runtime import NOW, _seed_request


@pytest.mark.parametrize("harness", ["codex", "pi"])
def test_remote_approval_uses_scoped_legacy_expiry(tmp_path, monkeypatch, harness):
    store = GuardStore(tmp_path / "guard-home")
    workspace = tmp_path / "workspace"
    identity = current_process_identity()
    assert identity is not None
    request = _seed_request(
        store,
        harness=harness,
        request_id="remote-reader",
        metadata={"hook_event_name": "PreToolUse", "codex_browser_wait_process": identity, "workspace": str(workspace)},
    )
    now = (datetime.fromisoformat(NOW) + timedelta(seconds=4)).isoformat()
    seen: list[Path] = []

    def read(path):
        seen.append(path)
        return {"approval_wait_timeout_seconds": 0} if path.parent == store.guard_home else {}

    def approved(*, resume_after_approval, **_kwargs):
        # The authorization executor is outside this transport regression. Its
        # post-approval callback runs the actual continuation/configuration path.
        return resume_after_approval(
            store=store, request_row=request, request_id="remote-reader", action="allow", now=now
        )

    monkeypatch.setattr(command_executors, "execute_exact_cloud_review_operation", approved)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.continuation_runtime.notify_pending_approval_once", lambda *_a, **_k: False
    )
    result = command_executors.execute_guard_command_job(
        {"operation": command_executors.EXACT_CLOUD_REVIEW_OPERATION, "payload": {}},
        context=command_queue.default_command_context(store),
        store=store,
        now=lambda: now,
        config_reader=read,
    )
    assert result["continuationStatus"] == "manual_retry_required"
    assert seen == [
        store.guard_home / "config.toml",
        workspace / ".ai-plugin-scanner-guard.toml",
        workspace / ".hol-guard.toml",
    ]


def test_existing_queue_worker_cannot_silently_change_reader(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "guard-home")
    monkeypatch.setattr(command_queue_worker, "command_queue_should_poll", lambda _store: True)

    def original(_path):
        return {}

    def replacement(_path):
        return {}

    worker = command_queue_worker.CommandQueueWorker(
        thread=threading.Thread(), stop_event=threading.Event(), config_reader=original
    )
    with pytest.raises(ValueError, match="command_queue_config_scope_changed"):
        command_queue_worker.start_command_queue_worker(store, worker, config_reader=replacement)
    assert worker.config_reader is original


@pytest.mark.parametrize("reject", [False, True])
def test_remote_package_audit_retains_scoped_home_reader(tmp_path, monkeypatch, reject):
    store = GuardStore(tmp_path / "guard-home")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    context = replace(command_queue.default_command_context(store), workspace_dir=workspace)
    seen: list[Path] = []
    audited: list[int] = []

    def read(path):
        seen.append(path)
        if reject:
            raise GuardConfigSourceError("guard_config_unexpected_root")
        return {"approval_wait_timeout_seconds": 7}

    def audit(*, config, **_kwargs):
        audited.append(config.approval_wait_timeout_seconds)
        return {"wait_budget": config.approval_wait_timeout_seconds}, 1

    monkeypatch.setattr(command_executors, "build_workspace_audit_payload", audit)
    result = command_executors.execute_guard_command_job(
        {"operation": "guard.packageShims.audit", "payload": {}},
        context=context,
        store=store,
        now=lambda: NOW,
        config_reader=read,
    )
    assert seen == [store.guard_home / "config.toml"]
    if reject:
        assert result["failureCode"] == "guard_config_unexpected_root"
        assert not audited
    else:
        assert result["data"]["wait_budget"] == 7
        assert audited == [7]
