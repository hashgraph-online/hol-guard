"""Daemon readers remain authoritative through posture and approval coordination."""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.config import MAX_APPROVAL_WAIT_TIMEOUT_SECONDS
from codex_plugin_scanner.guard.config_source_io import GuardConfigSourceError, capture_guard_config
from codex_plugin_scanner.guard.daemon import hook_worker as worker_module
from codex_plugin_scanner.guard.daemon.hook_native_review_approval import (
    pause_native_pre_tool_for_approval,
    queue_native_pre_tool_review,
)
from codex_plugin_scanner.guard.daemon.hook_native_review_continuation import native_codex_wait_operation
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.live_process_identity import (
    CODEX_BROWSER_WAIT_PROCESS_KEY,
    CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY,
    current_process_identity,
)
from codex_plugin_scanner.guard.runtime.approval_attention import ApprovalAttentionCoordinator
from codex_plugin_scanner.guard.store import GuardStore

from .test_guard_approval_attention import _queue_operation
from .test_native_review_policy_binding import _bind_receipt, _bound_edge


def _reject_workspace_reader(guard_home: Path, seen: list[Path]):
    def read(path: Path) -> dict[str, object]:
        seen.append(path)
        if path.parent != guard_home:
            raise GuardConfigSourceError("fixture_workspace_rejected")
        return {}

    return read


def _worker(store: GuardStore, monkeypatch: pytest.MonkeyPatch, reader, **kwargs) -> HookWorker:
    monkeypatch.setattr(worker_module, "native_mode", lambda: "off")
    monkeypatch.setattr(worker_module, "python_oracle_enabled", lambda: False)
    return HookWorker(
        store=store,
        wait_for_native_policy=False,
        publish_native_policy=False,
        config_reader=reader,
        **kwargs,
    )


def test_worker_keeps_explicit_reader_and_capture_with_terminal_posture_rejection(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "guard-home")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / ".hol-guard.toml").write_text('mode = "observe"\nprotection_posture = "watch"\n')
    seen: list[Path] = []
    reader = _reject_workspace_reader(store.guard_home, seen)
    captures = []
    publisher = SimpleNamespace()

    def get_publisher(actual_store, *, config_capture):
        assert actual_store is store
        captures.append(config_capture)
        return publisher

    monkeypatch.setattr(worker_module, "get_native_policy_snapshot_publisher", get_publisher)
    worker = _worker(store, monkeypatch, reader, config_capture=capture_guard_config)
    assert worker.config_reader is reader
    assert worker.policy_snapshot_publisher is publisher
    assert captures == [capture_guard_config]
    with pytest.raises(GuardConfigSourceError, match="fixture_workspace_rejected"):
        worker._load_config(store.guard_home, workspace)
    seen.clear()
    monkeypatch.setattr(
        worker,
        "_review_pre_tool_native",
        lambda *_args, **_kwargs: {
            "decision": "deny",
            "minimum_action": "block",
            "policy_action": "block",
            "reason_code": "native_destructive_command",
            "reason": "Synthetic terminal native block.",
        },
    )
    response = worker._review_pre_tool_http(
        {"tool_name": "Bash", "tool_input": {"command": "rm -rf fixture"}},
        harness="cursor",
        home_dir=tmp_path,
        guard_home=store.guard_home,
        workspace=workspace,
    )
    assert response["policy_action"] == "block"
    assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert seen == [store.guard_home / "config.toml", workspace / ".ai-plugin-scanner-guard.toml"]


@pytest.mark.parametrize("entry", ["queue", "pause", "worker"])
def test_rejected_workspace_cannot_queue_native_wait_or_approval(tmp_path, monkeypatch, entry):
    monkeypatch.setenv("HOL_GUARD_NATIVE", "auto")
    store = GuardStore(tmp_path / "guard-home")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    seen: list[Path] = []
    reader = _reject_workspace_reader(store.guard_home, seen)
    edge = _bound_edge()
    edge["harness"] = edge["receipt"]["harness"] = "codex"
    _bind_receipt(edge)
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "ollama push fixture"},
        CODEX_BROWSER_WAIT_PROCESS_KEY: current_process_identity(),
        CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY: 120,
    }
    assert payload[CODEX_BROWSER_WAIT_PROCESS_KEY] is not None
    if entry == "worker":
        worker = _worker(store, monkeypatch, reader)
        monkeypatch.setattr(worker, "_review_raw_hook_native", lambda **_kwargs: edge)
        response, used = worker._review_native_edge_with_snapshot(
            payload=payload,
            harness="codex",
            event_name="PreToolUse",
            default_harness="codex",
            home_dir=tmp_path,
            guard_home=store.guard_home,
            workspace=workspace,
            deadline=None,
            policy_snapshot={"mode": "enforce"},
            recording_only=False,
        )
        assert used is True
    else:
        queue = queue_native_pre_tool_review if entry == "queue" else pause_native_pre_tool_for_approval
        response = queue(
            store,
            harness="codex",
            payload=payload,
            native_result=edge["result"],
            workspace=workspace,
            guard_home=store.guard_home,
            home_dir=tmp_path,
            verified_receipt=edge["receipt"],
            config_reader=reader,
        )
    if entry == "queue":
        assert response is None
    else:
        assert response["policy_action"] == "block"
        assert response["reason_code"] == "native_review_queue_failed"
    assert seen == [store.guard_home / "config.toml", workspace / ".ai-plugin-scanner-guard.toml"]
    assert store.list_approval_requests(status="pending") == []
    assert store.list_guard_operations() == []


@pytest.mark.parametrize(
    ("requested", "configured", "expected"),
    [(120, 17, 17), (11, 120, 11), (600, 900, MAX_APPROVAL_WAIT_TIMEOUT_SECONDS), (120, 0, None)],
)
def test_explicit_reader_preserves_original_codex_wait_deadline(tmp_path, requested, configured, expected):
    store = GuardStore(tmp_path / "guard-home")
    workspace = tmp_path / "workspace"
    seen: list[Path] = []

    def read(path: Path) -> dict[str, object]:
        seen.append(path)
        return {"approval_wait_timeout_seconds": configured} if path.parent == store.guard_home else {}

    identity = current_process_identity()
    assert identity is not None
    started = "2026-09-17T00:00:00+00:00"
    operation = native_codex_wait_operation(
        store,
        harness="codex",
        payload={CODEX_BROWSER_WAIT_PROCESS_KEY: identity, CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY: requested},
        workspace=workspace,
        home_dir=tmp_path,
        now=started,
        config_reader=read,
    )
    assert seen == [
        store.guard_home / "config.toml",
        workspace / ".ai-plugin-scanner-guard.toml",
        workspace / ".hol-guard.toml",
    ]
    if expected is None:
        assert operation is None
    else:
        metadata = operation["metadata"]
        assert (
            operation["created_at"] == operation["updated_at"] == metadata["codex_browser_wait_started_at"] == started
        )
        assert metadata["codex_browser_wait_timeout_seconds"] == expected
        assert (
            metadata["codex_browser_wait_deadline_at"]
            == (datetime.fromisoformat(started) + timedelta(seconds=expected)).isoformat()
        )
        assert metadata["codex_browser_wait_process"] == identity


@pytest.mark.parametrize("reject_at_schedule", [True, False])
def test_attention_rejects_workspace_at_schedule_or_delayed_recheck(tmp_path, reject_at_schedule):
    store, runtime, result = _queue_operation(tmp_path, harness="pi", severity="medium")
    now = [100.0]
    opened: list[str] = []
    seen: list[Path] = []
    reject = [reject_at_schedule]

    def read(path: Path) -> dict[str, object]:
        seen.append(path)
        if path.parent == store.guard_home:
            return {"approval_surface_policy": "attention-aware", "approval_browser_delay_seconds": 20}
        if reject[0]:
            raise GuardConfigSourceError("fixture_workspace_rejected")
        return {}

    coordinator = ApprovalAttentionCoordinator(
        store=store,
        runtime=runtime,
        opener=lambda url: opened.append(url) or True,
        clock=lambda: now[0],
        config_reader=read,
    )

    def schedule():
        coordinator.schedule(
            operation_id=result["operation"]["operation_id"],
            requests=result["approval_requests"],
            browser_url="http://127.0.0.1:5474/requests/pending",
        )

    if reject_at_schedule:
        with pytest.raises(GuardConfigSourceError, match="fixture_workspace_rejected"):
            schedule()
    else:
        schedule()
        coordinator.process_due()
        assert opened == []
        now[0] += 20
        reject[0] = True
        seen.clear()
        with pytest.raises(GuardConfigSourceError, match="fixture_workspace_rejected"):
            coordinator.process_due()
    assert seen == [store.guard_home / "config.toml", tmp_path / "workspace" / ".ai-plugin-scanner-guard.toml"]
    assert opened == []
    assert coordinator._pending == {}
