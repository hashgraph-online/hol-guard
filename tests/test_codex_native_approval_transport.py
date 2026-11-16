"""Codex browser transport metadata must not orphan an approved command (#7193)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.codex_live_decision import (
    complete_codex_live_decision,
    resolve_codex_live_allow_authority,
)
from codex_plugin_scanner.guard.codex_live_decision_revalidation import revalidate_codex_live_allow
from codex_plugin_scanner.guard.config import update_guard_settings
from codex_plugin_scanner.guard.hook_review.hook_worker import HookWorker
from codex_plugin_scanner.guard.live_process_identity import (
    CODEX_BROWSER_WAIT_PROCESS_KEY,
    CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY,
    current_process_identity,
    process_start_token,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_native_review_codex_live_wait import _allow_once


@pytest.mark.parametrize("completion", ["retry", "live", "changed-command", "changed-session"])
def test_real_codex_hook_honors_once_across_transport_changes(
    live_hook_root: Path, monkeypatch: pytest.MonkeyPatch, completion: str
) -> None:
    home = live_hook_root / "home"
    workspace = home / "workspace"
    workspace.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    store = GuardStore(home / ".hol-guard")
    update_guard_settings(store.guard_home, {"blocked_request_mode": "ask"})
    worker = HookWorker(store=store, workspace=workspace)
    scratch = workspace / "sandbox-dir"
    scratch.mkdir()
    (scratch / "notes.txt").write_text("disposable maintenance fixture\n", encoding="utf-8")
    payload = {
        "hook_event_name": "PreToolUse",
        "session_id": "codex-approval-transport",
        "tool_use_id": "call-first",
        "tool_name": "Bash",
        "tool_input": {"command": f"rm -rf {workspace / 'sandbox-dir'}"},
        "cwd": str(workspace),
        CODEX_BROWSER_WAIT_PROCESS_KEY: current_process_identity(),
        CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY: 120,
        "guard_remaining_ms": 60_000,
    }

    def review(hook_payload: dict[str, object], **claims: object) -> dict[str, object]:
        return worker.review_http_payload(
            payload=hook_payload,
            params={},
            default_harness="codex",
            home_dir=home,
            guard_home=store.guard_home,
            workspace=workspace,
            **claims,
        )

    try:
        first = review(payload)
        assert first["policy_action"] == "review", first
        request_id = str(first["approval_request_id"])
        _allow_once(store, request_id, workspace)
        if completion != "live":
            # Use the real token grammar: arbitrary token text is itself
            # reviewed as a possible secret by the production policy.
            bridge = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
            try:
                retry_process = {"pid": bridge.pid, "startToken": process_start_token(bridge.pid)}
                assert retry_process["startToken"] is not None
            finally:
                bridge.terminate()
                bridge.wait(timeout=5)
            retry = {
                **payload,
                "tool_use_id": "call-retry",
                CODEX_BROWSER_WAIT_PROCESS_KEY: retry_process,
                CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY: 90,
                "guard_remaining_ms": 59_700,
            }
            if completion == "changed-command":
                retry["tool_input"] = {"command": f"rm -rf {workspace / 'another-dir'}"}
            elif completion == "changed-session":
                retry["session_id"] = "another-session"
            response = review(retry)
            if completion in {"changed-command", "changed-session"}:
                assert response["policy_action"] == "review"
                assert response.get("approval_reuse_status") != "accepted"
                assert scratch.is_dir()
                return
            assert response.get("approval_reuse_status") == "accepted", [
                {key: row.get(key) for key in ("artifact_hash", "resolution_action", "resolution_scope", "status")}
                for row in store.list_approval_requests(status=None)
            ]
            assert store.list_approval_requests(status="pending") == []
            assert review(retry)["policy_action"] == "review"
        else:
            row = store.get_approval_request(request_id)
            assert row is not None
            authority = resolve_codex_live_allow_authority(
                store, request=row, request_id=request_id, now=str(row["resolved_at"])
            )
            assert authority is not None
            # live-decision receives prepared input, without the HTTP hint.
            hook_input = {key: value for key, value in payload.items() if key != "guard_remaining_ms"}
            authorized = revalidate_codex_live_allow(
                row,
                {"hook_input": json.dumps(hook_input)},
                home_dir=home,
                guard_home=store.guard_home,
                previous=store.get_request_resume(request_id),
                request_id=request_id,
                authority_resolved=True,
                reviewer=lambda fresh, _workspace, claimed_hash, claimed_id: review(
                    fresh,
                    claim_saved_approval=False,
                    claimed_saved_allow_hash=claimed_hash,
                    claimed_approval_request_id=claimed_id,
                ),
            )
            assert authorized is True
            completed = complete_codex_live_decision(
                store, request_id=request_id, now=str(row["resolved_at"]), fresh_allow_authorized=authorized
            )
            assert completed["completed"] is True, completed
        # This is an admission test only. Never execute the reported removal.
        assert scratch.is_dir()
    finally:
        worker.close()
