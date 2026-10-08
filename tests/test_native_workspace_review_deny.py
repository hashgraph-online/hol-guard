from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.adapters.grok_approval_resume import wait_for_grok_live_approval
from codex_plugin_scanner.guard.approvals import wait_for_approval_requests
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.runtime import native_workspace_review as native
from codex_plugin_scanner.guard.runtime import native_workspace_review_transport as transport
from codex_plugin_scanner.guard.store import GuardStore
from tests.native_workspace_review_test_support import _staged_digest, _status


def test_signed_deny_is_block_to_real_waiter_and_grok_harness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    request = GuardApprovalRequest(
        request_id="request-deny",
        harness="grok",
        artifact_id="grok:project:request-deny",
        artifact_name="request-deny",
        artifact_hash="hash-request-deny",
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("args",),
        source_scope="project",
        config_path=str(tmp_path / "grok-config.toml"),
        review_command="hol-guard approvals approve request-deny",
        approval_url="http://127.0.0.1/pending/request-deny",
        workspace=str(tmp_path),
        artifact_type="command",
        launch_target="git status",
        action_envelope_json={"command": "git status"},
    )
    store.add_approval_request(request, "2026-09-25T12:00:00+00:00")
    monkeypatch.setattr(
        native,
        "matching_workspace_review_snapshot",
        lambda _store, _home, _request_id, _decision, current: dict(current),
    )
    monkeypatch.setattr(transport, "native_runtime_status", _status)
    monkeypatch.setattr(transport, "_isolated_environment", lambda: {})
    monkeypatch.setattr(
        transport,
        "native_resident_client_request",
        lambda **kwargs: json.dumps(
            {
                "status": "verified",
                "replayed": False,
                "request_id": "request-deny",
                "decision": "deny",
                "claim_id": "a" * 64,
                "authority_record_digest": "c" * 64,
                "workspace_binding": "4" * 64,
                "device_binding": "5" * 64,
                "installation_binding": "6" * 64,
                "scope_binding": "7" * 64,
                "request_binding": "d" * 64,
                "action_binding": "e" * 64,
                "intent_binding": "f" * 64,
                "revision_binding": "1" * 64,
                "policy_binding": "2" * 64,
                "retry_scope_binding": "3" * 64,
                "envelope_digest": "b" * 64,
                "request_snapshot_digest": _staged_digest(cast(Path, kwargs["guard_home"]), "request-deny"),
            }
        ).encode("utf-8"),
    )

    result = native.apply_native_workspace_review_decision(
        store,
        tmp_path / "guard-home",
        "request-deny",
        {"signed": "native-envelope"},
    )
    assert result["decision"] == "deny"
    assert result["resolution_action"] == "block"
    native_receipt = result["native_receipt"]
    assert isinstance(native_receipt, dict)
    assert native_receipt["decision"] == "deny"
    resolved = store.get_approval_request("request-deny")
    assert resolved is not None
    assert resolved["resolution_action"] == "block"

    waited = wait_for_approval_requests(
        store=store,
        request_ids=["request-deny"],
        timeout_seconds=0,
    )
    assert waited["resolved"] is True
    waited_items = waited["items"]
    assert isinstance(waited_items, list)
    assert isinstance(waited_items[0], dict)
    assert waited_items[0]["resolution_action"] == "block"
    payload: dict[str, object] = {"approval_requests": [{"request_id": "request-deny"}]}
    assert (
        wait_for_grok_live_approval(
            event_name="PreToolUse",
            policy_action="require-reapproval",
            response_payload=payload,
            store=store,
            timeout_seconds=1,
            json_mode=False,
        )
        == "block"
    )
