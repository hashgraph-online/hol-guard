"""Persisted approval paths keep explicit readers and existing wait formulas."""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import approvals
from codex_plugin_scanner.guard.codex_live_decision import complete_codex_live_decision
from codex_plugin_scanner.guard.codex_resume import defer_request_resume_to_live_hook
from codex_plugin_scanner.guard.config_source_io import GuardConfigSourceError
from codex_plugin_scanner.guard.continuation_runtime import (
    continuation_offer_payload,
    continue_request_after_application,
    record_live_hook_completion,
)
from codex_plugin_scanner.guard.daemon.local_approval_continuation import apply_local_approval_continuation
from codex_plugin_scanner.guard.live_process_identity import current_process_identity
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.runtime.surface_server import GuardSurfaceRuntime
from codex_plugin_scanner.guard.store import GuardStore

from .test_guard_continuation_runtime import NOW, _seed_request


@pytest.mark.parametrize("reject_workspace", [False, True])
def test_surface_queue_uses_reader_for_continuation_and_notification(tmp_path, monkeypatch, reject_workspace):
    store = GuardStore(tmp_path / "guard-home")
    workspace = tmp_path / "workspace"
    runtime = GuardSurfaceRuntime(store)
    session = runtime.start_session(
        harness="codex", surface="harness-adapter", workspace=str(workspace), client_name="reader-fixture"
    )
    artifact = GuardArtifact(
        artifact_id="codex:project:reader-test",
        name="Reader test",
        harness="codex",
        artifact_type="tool_call",
        source_scope="project",
        config_path=str(workspace / "settings.json"),
        metadata={},
    )
    detection = HarnessDetection(
        harness="codex",
        installed=True,
        command_available=True,
        config_paths=(artifact.config_path,),
        artifacts=(artifact,),
    )
    seen: list[Path] = []
    notified = []

    def read(path):
        seen.append(path)
        if path.parent == store.guard_home:
            return {"desktop_notifications": True, "approval_wait_timeout_seconds": 17}
        if reject_workspace:
            raise GuardConfigSourceError("fixture_rejected_persisted_workspace")
        return {"desktop_notifications": False}

    monkeypatch.setattr(
        approvals, "notify_pending_approval_once", lambda notification, **_kw: notified.append(notification)
    )
    identity = current_process_identity()
    assert identity is not None
    result = runtime.queue_blocked_operation(
        session_id=session["session_id"],
        operation_type="tool_call",
        harness="codex",
        metadata={"hook_event_name": "PreToolUse", "codex_browser_wait_process": identity, "workspace": str(workspace)},
        detection=detection.to_dict(),
        evaluation={
            "artifacts": [
                {
                    "artifact_id": artifact.artifact_id,
                    "artifact_name": artifact.name,
                    "artifact_hash": "hash-reader-test",
                    "artifact_type": artifact.artifact_type,
                    "source_scope": "project",
                    "config_path": artifact.config_path,
                    "workspace": str(workspace),
                    "policy_action": "review",
                    "changed_fields": ["runtime_tool_call"],
                }
            ]
        },
        approval_center_url="http://127.0.0.1:5474",
        approval_surface_policy="attention-aware",
        open_key=None,
        opener=lambda _url: False,
        config_reader=read,
    )
    row = result["approval_requests"][0]
    assert row["workspace"] == str(workspace)
    captured = [store.guard_home / "config.toml", workspace / ".ai-plugin-scanner-guard.toml"]
    if not reject_workspace:
        captured.append(workspace / ".hol-guard.toml")
    assert seen == captured * 2
    # Config read errors retain the established legacy 120-second fallback and
    # notification fallback; neither silently falls back to an unscoped reader.
    seconds = 123 if reject_workspace else 20
    assert (
        row["continuation_snapshot"]["waitDeadline"]
        == (datetime.fromisoformat(row["created_at"]) + timedelta(seconds=seconds)).isoformat()
    )
    assert len(notified) == int(reject_workspace)


@pytest.mark.parametrize("entry", ["offer", "continue", "record", "defer", "local", "complete"])
def test_persisted_legacy_wait_expiry_uses_explicit_reader(tmp_path, monkeypatch, entry):
    store = GuardStore(tmp_path / "guard-home")
    workspace = tmp_path / "workspace"
    identity = current_process_identity()
    assert identity is not None
    request = _seed_request(
        store,
        harness="codex",
        request_id="reader-wait",
        metadata={"hook_event_name": "PreToolUse", "codex_browser_wait_process": identity, "workspace": str(workspace)},
    )
    seen: list[Path] = []

    def read(path):
        seen.append(path)
        return {"approval_wait_timeout_seconds": 0} if path.parent == store.guard_home else {}

    now = (datetime.fromisoformat(NOW) + timedelta(seconds=4)).isoformat()
    if entry == "offer":
        result = continuation_offer_payload(store, request_row=request, now=now, headless=False, config_reader=read)
        assert result["hookAttached"] is False
        assert result["waitDeadline"] is None
    elif entry == "continue":
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.continuation_runtime.notify_pending_approval_once", lambda *_a, **_k: False
        )
        result = continue_request_after_application(
            store, request_row=request, action="allow", now=now, config_reader=read
        )
        assert result["continuationStatus"] == "manual_retry_required"
    elif entry == "record":
        assert (
            record_live_hook_completion(store, request_id="reader-wait", action="block", now=now, config_reader=read)
            is None
        )
    elif entry == "defer":
        assert (
            defer_request_resume_to_live_hook(
                store, request_id="reader-wait", action="allow", now=now, config_reader=read
            )
            is None
        )
    elif entry == "local":
        store.resolve_one_request_only(
            "reader-wait", resolution_action="allow", resolution_scope="artifact", reason="fixture", resolved_at=now
        )
        result, _ = apply_local_approval_continuation(
            store=store,
            updated={},
            request_id="reader-wait",
            action="allow",
            harness="codex",
            copy={"title": "Saved", "body": "Saved fixture decision"},
            now=lambda: now,
            config_reader=read,
        )
        assert result["codexResume"]["reason"] == "session_not_found"
    else:
        store.resolve_one_request_only(
            "reader-wait", resolution_action="block", resolution_scope="artifact", reason="fixture", resolved_at=now
        )
        result = complete_codex_live_decision(store, request_id="reader-wait", now=now, config_reader=read)
        assert result == {"completed": False, "error": "continuation_not_recorded"}
    assert seen == [
        store.guard_home / "config.toml",
        workspace / ".ai-plugin-scanner-guard.toml",
        workspace / ".hol-guard.toml",
    ]
