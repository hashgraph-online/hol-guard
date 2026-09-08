from __future__ import annotations

from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store import GuardStore


def _request(*, command: str | None) -> GuardApprovalRequest:
    return GuardApprovalRequest(
        request_id="req-everyday-live",
        harness="codex",
        artifact_id="codex:project:file-read:private",
        artifact_name="Private file read",
        artifact_type="file_read_request",
        artifact_hash="hash-private-read",
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("tool_action",),
        source_scope="project",
        config_path="/Users/alice/private/project",
        workspace="/Users/alice/private/project",
        launch_target=command or "file read request",
        action_envelope_json={
            "schema_version": 1,
            "action_type": "file_read",
            "target_paths": ["/Users/alice/private/project/.env"],
            "command": command,
        },
        raw_command_text=command,
        review_command="hol-guard approvals approve req-everyday-live",
        approval_url="http://127.0.0.1:5474/requests/req-everyday-live",
    )


def test_live_store_reads_attach_persisted_identity_bound_explanations(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.add_approval_request(_request(command="read private environment file"), "2026-09-08T12:00:00+00:00")

    detail = store.get_approval_request("req-everyday-live")
    assert detail is not None
    identity = detail["action_identity"]
    explanation = detail["action_explanation"]
    assert isinstance(identity, str) and identity
    assert isinstance(explanation, dict)
    assert explanation["action_identity"] == identity
    assert explanation["kind"] == "file_read"
    assert explanation["technical"]["command_display"] is None
    serialized = str(explanation)
    assert "/Users/alice/private/project" not in serialized
    assert "read private environment file" not in serialized

    listed = store.list_approval_requests(limit=10)
    assert listed[0]["action_explanation"]["action_identity"] == identity
    page = store.list_pending_approval_summaries(limit=10)
    summary = page["items"][0]
    assert summary["action_explanation"]["action_identity"] == identity
    assert summary["action_explanation"]["technical"]["command_display"] is None


def test_review_command_does_not_make_stopped_action_look_retained(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.add_approval_request(_request(command=None), "2026-09-08T12:00:00+00:00")

    detail = store.get_approval_request("req-everyday-live")
    assert detail is not None
    explanation = detail["action_explanation"]
    assert isinstance(explanation, dict)
    assert explanation["technical"]["available"] is False
    assert explanation["technical"]["unavailable_reason"] == "The exact action was not retained."
