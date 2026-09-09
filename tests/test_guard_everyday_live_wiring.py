from __future__ import annotations

import re

from codex_plugin_scanner.guard import store_approval_queries
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store import GuardStore

_OPAQUE_ACTION_ID = re.compile(r"^act_[0-9a-f]{64}$")


def _request(*, command: str | None, raw_command_text: str | None = None) -> GuardApprovalRequest:
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
        raw_command_text=raw_command_text if raw_command_text is not None else command,
        review_command="hol-guard approvals approve req-everyday-live",
        approval_url="http://127.0.0.1:5474/requests/req-everyday-live",
    )


def test_live_store_reads_attach_opaque_identity_bound_explanations(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.add_approval_request(
        _request(command="read private environment file"),
        "2026-09-08T12:00:00+00:00",
    )

    detail = store.get_approval_request("req-everyday-live")
    assert detail is not None
    internal_identity = detail["action_identity"]
    explanation = detail["action_explanation"]
    assert isinstance(internal_identity, str) and internal_identity
    assert isinstance(explanation, dict)
    public_identity = explanation["action_identity"]
    assert isinstance(public_identity, str)
    assert _OPAQUE_ACTION_ID.fullmatch(public_identity)
    assert public_identity != internal_identity
    assert explanation["technical"]["action_id"] == public_identity
    assert explanation["kind"] == "file_read"
    assert explanation["technical"]["command_display"] is None
    serialized = str(explanation)
    assert internal_identity not in serialized
    assert "/Users/alice/private/project" not in serialized
    assert "read private environment file" not in serialized

    listed = store.list_approval_requests(limit=10)
    assert listed[0]["action_explanation"]["action_identity"] == public_identity
    page = store.list_pending_approval_summaries(limit=10)
    summary = page["items"][0]
    assert summary["action_explanation"]["action_identity"] == public_identity
    assert summary["action_explanation"]["technical"]["command_display"] is None


def test_review_command_does_not_make_stopped_action_look_retained(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.add_approval_request(
        _request(command=None),
        "2026-09-08T12:00:00+00:00",
    )

    detail = store.get_approval_request("req-everyday-live")
    assert detail is not None
    explanation = detail["action_explanation"]
    assert isinstance(explanation, dict)
    assert explanation["technical"]["available"] is False
    assert explanation["technical"]["unavailable_reason"] == "The exact action was not retained."


def test_raw_only_retained_command_reports_deliberate_disclosure(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.add_approval_request(
        _request(command=None, raw_command_text="cat /Users/alice/private/project/.env"),
        "2026-09-08T12:00:00+00:00",
    )

    detail = store.get_approval_request("req-everyday-live")
    assert detail is not None
    explanation = detail["action_explanation"]
    assert isinstance(explanation, dict)
    assert explanation["technical"]["available"] is False
    assert (
        explanation["technical"]["unavailable_reason"] == "Exact technical details require deliberate local disclosure."
    )
    assert "cat /Users/alice" not in str(explanation)


def test_summary_explanations_do_not_reload_each_detail(tmp_path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.add_approval_request(
        _request(command="read private environment file"),
        "2026-09-08T12:00:00+00:00",
    )

    def fail_detail_reload(*_args, **_kwargs):
        raise AssertionError("summary projection must not perform per-item detail loads")

    monkeypatch.setattr(store_approval_queries, "load_approval_request", fail_detail_reload)
    page = store.list_pending_approval_summaries(limit=10)
    assert page["items"][0]["action_explanation"] is not None
