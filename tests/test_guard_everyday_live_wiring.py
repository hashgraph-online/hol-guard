from __future__ import annotations

from typing import cast

from codex_plugin_scanner.guard.models import GuardApprovalRequest


def _request(*, envelope: dict[str, object] | None) -> GuardApprovalRequest:
    return GuardApprovalRequest(
        request_id="req-everyday-live",
        harness="codex",
        artifact_id="codex:file:read",
        artifact_name="id_rsa",
        artifact_hash="sha256:test",
        policy_action="review",
        recommended_scope="artifact",
        changed_fields=("target",),
        source_scope="workspace",
        config_path="/tmp/config.json",
        review_command="cat /Users/alice/.ssh/id_rsa",
        approval_url="http://127.0.0.1:9999/requests/req-everyday-live",
        artifact_type="file_read_request",
        action_identity="action:file-read:1",
        action_envelope_json=envelope,
    )


def test_approval_request_serialization_attaches_core_owned_explanation() -> None:
    payload = _request(
        envelope={
            "action_type": "file_read",
            "target_paths": ["/Users/alice/.ssh/id_rsa"],
            "command": "cat /Users/alice/.ssh/id_rsa",
        }
    ).to_dict()

    explanation = cast(dict[str, object], payload["action_explanation"])
    everyday = cast(dict[str, object], explanation["everyday"])
    technical = cast(dict[str, object], explanation["technical"])

    assert explanation["schema_version"] == "guard.action-explanation.v1"
    assert explanation["action_identity"] == "action:file-read:1"
    assert everyday["headline"] == "Read a file"
    assert "/Users/alice/.ssh" not in str(everyday)
    assert technical["available"] is False
    assert technical["command_display"] is None


def test_approval_request_without_typed_envelope_falls_back_cleanly() -> None:
    payload = _request(envelope=None).to_dict()
    assert payload["action_explanation"] is None
