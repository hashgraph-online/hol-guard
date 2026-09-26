from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from codex_plugin_scanner.cli import _build_parser
from codex_plugin_scanner.guard.adapters.grok_approval_resume import wait_for_grok_live_approval
from codex_plugin_scanner.guard.approvals import wait_for_approval_requests
from codex_plugin_scanner.guard.cli.commands_dispatch_cloud_review import _run_guard_cloud_review_command
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.runtime import native_workspace_review as native
from codex_plugin_scanner.guard.runtime.exact_cloud_review import EXACT_CLOUD_REVIEW_REVOCATION_STATE_KEY
from codex_plugin_scanner.guard.store import GuardStore


def _request(request_id: str = "request-1") -> dict[str, object]:
    return {
        "request_id": request_id,
        "status": "pending",
        "harness": "codex",
        "artifact_id": "artifact-1",
        "artifact_type": "command",
        "workspace": "/workspace",
        "action_identity": "action-1",
        "action_envelope_json": {"command": "git status"},
        "launch_target": "git",
        "raw_command_text": "git status",
        "browser_intent_json": None,
        "created_at": "2026-09-25T12:00:00+00:00",
        "last_seen_at": "2026-09-25T12:00:00+00:00",
        "dedupe_count": 1,
        "guard_version": "3.0.0",
        "first_seen_guard_version": "3.0.0",
        "last_seen_guard_version": "3.0.0",
        "policy_action": "review",
        "recommended_scope": "artifact",
        "source_scope": "artifact",
        "decision_v2_json": {"action": "review"},
        "resolution_action": None,
        "resolution_scope": None,
    }


class _Store:
    def __init__(self, request: dict[str, object]):
        self.request = request
        self.sync_payloads: dict[str, object] = {}

    def get_approval_request(self, request_id: str) -> dict[str, object] | None:
        if request_id != self.request["request_id"]:
            return None
        return copy.deepcopy(self.request)

    def get_sync_payload(self, state_key: str) -> dict[str, object] | list[object] | None:
        return cast(dict[str, object] | list[object] | None, self.sync_payloads.get(state_key))

    def resolve_native_workspace_review_request(self, request_id: str, **kwargs: object) -> dict[str, object]:
        assert request_id == self.request["request_id"]
        expected = cast(dict[str, object], kwargs["expected_request"])
        assert expected["status"] == "pending"
        action = kwargs["resolution_action"]
        self.request["status"] = "resolved"
        self.request["resolution_action"] = action
        self.request["resolution_scope"] = "artifact"
        return {"resolved": True, "resolved_request": copy.deepcopy(self.request), "replayed": False}


def _status() -> SimpleNamespace:
    return SimpleNamespace(
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=Path("/native/hol-guard-runtime")),
        capabilities=SimpleNamespace(features=("resident-protocol-v2", "native-workspace-review-decision-v1")),
    )


def _staged_digest(guard_home: Path, request_id: str) -> str:
    path = guard_home / "native-runtime" / "workspace-review-requests" / f"{request_id}.json"
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_staging_uses_only_persisted_request_material(tmp_path: Path) -> None:
    store = _Store(_request())
    staged = native.stage_workspace_review_request(store, tmp_path, "request-1")
    assert staged["action_identity"] == "action-1"
    path = tmp_path / "native-runtime" / "workspace-review-requests" / "request-1.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["action"]["action_identity"] == "action-1"
    assert "decision" not in payload
    assert "dpop" not in json.dumps(payload).lower()


def test_apply_reconciles_native_claim_into_local_queue(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _Store(_request())
    monkeypatch.setattr(native, "native_runtime_status", _status)
    monkeypatch.setattr(native, "_isolated_environment", lambda: {})
    monkeypatch.setattr(
        native,
        "native_resident_client_request",
        lambda **kwargs: json.dumps(
            {
                "status": "verified",
                "replayed": False,
                "request_id": "request-1",
                "decision": "allow",
                "claim_id": "a" * 64,
                "envelope_digest": "b" * 64,
                "request_snapshot_digest": _staged_digest(cast(Path, kwargs["guard_home"]), "request-1"),
            }
        ).encode("utf-8"),
    )
    result = native.apply_native_workspace_review_decision(
        store,
        tmp_path,
        "request-1",
        {"signed": "native-envelope"},
    )
    assert result["status"] == "verified"
    assert result["decision"] == "allow"
    assert result["resolution_action"] == "allow"
    assert store.request["status"] == "resolved"


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
    monkeypatch.setattr(native, "native_runtime_status", _status)
    monkeypatch.setattr(native, "_isolated_environment", lambda: {})
    monkeypatch.setattr(
        native,
        "native_resident_client_request",
        lambda **kwargs: json.dumps(
            {
                "status": "verified",
                "replayed": False,
                "request_id": "request-deny",
                "decision": "deny",
                "claim_id": "a" * 64,
                "authority_record_digest": "c" * 64,
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


def test_staged_snapshot_substitution_is_rejected_before_sqlite_application(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _Store(_request())
    monkeypatch.setattr(native, "native_runtime_status", _status)
    monkeypatch.setattr(native, "_isolated_environment", lambda: {})

    def substitute_and_respond(**kwargs: object) -> bytes:
        guard_home = cast(Path, kwargs["guard_home"])
        path = guard_home / "native-runtime" / "workspace-review-requests" / "request-1.json"
        substituted = json.loads(path.read_text(encoding="utf-8"))
        substituted["action"]["raw_command_text"] = "git log --oneline"
        path.write_bytes(native._canonical_json_bytes(substituted))
        return json.dumps(
            {
                "status": "verified",
                "replayed": False,
                "request_id": "request-1",
                "decision": "allow",
                "claim_id": "a" * 64,
                "envelope_digest": "b" * 64,
                "request_snapshot_digest": _staged_digest(guard_home, "request-1"),
            }
        ).encode("utf-8")

    monkeypatch.setattr(native, "native_resident_client_request", substitute_and_respond)
    with pytest.raises(native.NativeWorkspaceReviewError) as error:
        native.apply_native_workspace_review_decision(
            store,
            tmp_path,
            "request-1",
            {"signed": "native-envelope"},
        )
    assert error.value.code == "native_workspace_review_response_invalid"
    assert store.request["status"] == "pending"


def test_request_selector_rejects_path_traversal(tmp_path: Path) -> None:
    with pytest.raises(native.NativeWorkspaceReviewError) as error:
        native.stage_workspace_review_request(_Store(_request("../escape")), tmp_path, "../escape")
    assert error.value.code == "native_workspace_review_request_invalid"


def test_native_apply_is_reachable_from_cloud_review_cli() -> None:
    parser = _build_parser("hol-guard", program_mode="combined")
    args = parser.parse_args(["guard", "cloud-review", "native-apply", "--request-id", "request-1", "--json"])
    assert args.cloud_review_command == "native-apply"
    assert args.request_id == "request-1"


def test_native_apply_fails_closed_after_local_cloud_review_disable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    store = _Store(_request())
    store.sync_payloads[EXACT_CLOUD_REVIEW_REVOCATION_STATE_KEY] = {"revoked": True}
    monkeypatch.setattr(
        native,
        "apply_native_workspace_review_decision",
        lambda *args, **kwargs: pytest.fail("native apply must be gated after local disable"),
    )
    args = _build_parser("hol-guard", program_mode="combined").parse_args(
        ["guard", "cloud-review", "native-apply", "--request-id", "request-1", "--json"]
    )
    result = _run_guard_cloud_review_command(
        args,
        guard_home=tmp_path,
        store=cast(GuardStore, cast(object, store)),
        input_text="{}",
    )
    assert result == 2
    assert "native_workspace_review_cloud_review_disabled" in capsys.readouterr().out


def test_native_runtime_rejects_local_disable_before_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _Store(_request())
    store.sync_payloads[EXACT_CLOUD_REVIEW_REVOCATION_STATE_KEY] = {"revoked": True}
    monkeypatch.setattr(native, "_native_response", lambda **kwargs: pytest.fail("verification must not run"))
    with pytest.raises(native.NativeWorkspaceReviewError) as error:
        native.apply_native_workspace_review_decision(store, tmp_path, "request-1", {})
    assert error.value.code == "native_workspace_review_cloud_review_disabled"


def test_native_sqlite_application_rechecks_local_disable(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_payload(EXACT_CLOUD_REVIEW_REVOCATION_STATE_KEY, {"revoked": True}, "2026-09-26T00:00:00Z")
    result = store.resolve_native_workspace_review_request(
        "request-1",
        resolution_action="allow",
        expected_request=_request(),
        resolved_at="2026-09-26T00:00:00Z",
        native_replayed=False,
    )
    assert result == {"resolved": False, "error": "native_workspace_review_cloud_review_disabled"}
