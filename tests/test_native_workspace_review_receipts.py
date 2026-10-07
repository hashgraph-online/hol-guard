from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import native_workspace_review as native
from codex_plugin_scanner.guard.runtime.exact_cloud_review import EXACT_CLOUD_REVIEW_REVOCATION_STATE_KEY
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_native_workspace_review import NATIVE_WORKSPACE_REVIEW_RECEIPT_STATE_PREFIX
from tests.guard_exact_cloud_review_support import add_review_request, review_request


def _receipt() -> dict[str, object]:
    fields = (
        "claim_id",
        "workspace_binding",
        "device_binding",
        "installation_binding",
        "scope_binding",
        "request_binding",
        "action_binding",
        "intent_binding",
        "revision_binding",
        "policy_binding",
        "retry_scope_binding",
        "request_snapshot_digest",
        "authority_record_digest",
        "envelope_digest",
    )
    return {
        **{field: hashlib.sha256(field.encode()).hexdigest() for field in fields},
        "request_id": "request-1",
        "decision": "allow",
        "status": "verified",
        "replayed": False,
    }


def _store(tmp_path: Path) -> tuple[GuardStore, dict[str, object]]:
    store = GuardStore(tmp_path / "guard-home")
    add_review_request(store, review_request("request-1"))
    request = store.get_approval_request("request-1")
    assert isinstance(request, dict)
    return store, request


def _resolve(store: GuardStore, request: dict[str, object], receipt: dict[str, object]) -> dict[str, object]:
    return store.resolve_native_workspace_review_request(
        "request-1",
        resolution_action="allow",
        expected_request=request,
        resolved_at="2026-09-27T00:00:00+00:00",
        native_replayed=receipt.get("replayed") is True,
        native_receipt=receipt,
    )


def test_native_receipt_and_resolution_commit_together(tmp_path: Path) -> None:
    store, request = _store(tmp_path)
    receipt = _receipt()
    assert _resolve(store, request, receipt)["resolved"] is True
    assert store.get_sync_payload(NATIVE_WORKSPACE_REVIEW_RECEIPT_STATE_PREFIX + "request-1") == receipt
    resolved = store.get_approval_request("request-1")
    assert resolved is not None and resolved["resolution_action"] == "allow"


def test_receipt_write_failure_rolls_back_resolution_then_replay_completes(tmp_path: Path) -> None:
    store, request = _store(tmp_path)
    with store._connect() as connection:
        connection.execute(
            """create trigger fail_native_receipt before insert on sync_state
            when NEW.state_key like 'native_workspace_review.receipt:%'
            begin select raise(abort, 'injected receipt write failure'); end"""
        )
    with pytest.raises(sqlite3.IntegrityError, match="injected receipt write failure"):
        _resolve(store, request, _receipt())
    pending = store.get_approval_request("request-1")
    assert pending is not None and pending["status"] == "pending"
    assert store.get_sync_payload(NATIVE_WORKSPACE_REVIEW_RECEIPT_STATE_PREFIX + "request-1") is None
    with store._connect() as connection:
        connection.execute("drop trigger fail_native_receipt")
    replay = {**_receipt(), "status": "replayed", "replayed": True}
    assert _resolve(store, request, replay)["resolved"] is True
    assert store.get_sync_payload(NATIVE_WORKSPACE_REVIEW_RECEIPT_STATE_PREFIX + "request-1") == replay


def test_renewed_consumed_decision_preserves_original_application_receipt(tmp_path: Path) -> None:
    store, request = _store(tmp_path)
    original = _receipt()
    assert _resolve(store, request, original)["resolved"] is True
    renewed = {
        **original,
        "status": "replayed",
        "replayed": True,
        "authority_record_digest": "a" * 64,
        "envelope_digest": "b" * 64,
    }
    result = _resolve(store, request, renewed)
    assert result["resolved"] is True and result["replayed"] is True
    assert store.get_sync_payload(NATIVE_WORKSPACE_REVIEW_RECEIPT_STATE_PREFIX + "request-1") == original


@pytest.mark.parametrize("field", ["claim_id", "action_binding", "policy_binding", "request_snapshot_digest"])
def test_different_consumed_decision_is_not_reported_as_applied(tmp_path: Path, field: str) -> None:
    store, request = _store(tmp_path)
    original = _receipt()
    assert _resolve(store, request, original)["resolved"] is True
    altered = {**original, "status": "replayed", "replayed": True, field: "0" * 64}
    assert _resolve(store, request, altered) == {
        "resolved": False,
        "error": "native_workspace_review_request_resolved",
    }
    assert store.get_sync_payload(NATIVE_WORKSPACE_REVIEW_RECEIPT_STATE_PREFIX + "request-1") == original


def test_local_resolution_does_not_invent_a_native_receipt(tmp_path: Path) -> None:
    store, request = _store(tmp_path)
    local = store.resolve_native_workspace_review_request(
        "request-1",
        resolution_action="allow",
        expected_request=request,
        resolved_at="2026-09-27T00:00:00+00:00",
        native_replayed=False,
    )
    assert local["resolved"] is True
    assert _resolve(store, request, {**_receipt(), "status": "replayed", "replayed": True}) == {
        "resolved": False,
        "error": "native_workspace_review_request_resolved",
    }


@pytest.mark.parametrize(
    "field,value", [("decision", "deny"), ("request_id", "other"), ("claim_id", "bad"), ("replayed", True)]
)
def test_invalid_native_receipt_cannot_resolve_request(tmp_path: Path, field: str, value: object) -> None:
    store, request = _store(tmp_path)
    assert _resolve(store, request, {**_receipt(), field: value}) == {
        "resolved": False,
        "error": "native_workspace_review_receipt_invalid",
    }
    current = store.get_approval_request("request-1")
    assert current is not None and current["status"] == "pending"


def test_native_receipt_does_not_bypass_local_disable(tmp_path: Path) -> None:
    store, request = _store(tmp_path)
    store.set_sync_payload(EXACT_CLOUD_REVIEW_REVOCATION_STATE_KEY, {"revoked": True}, "2026-09-27T00:00:00Z")
    assert _resolve(store, request, _receipt()) == {
        "resolved": False,
        "error": "native_workspace_review_cloud_review_disabled",
    }


def test_resolved_native_delivery_is_reverified_without_restaging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _ = _store(tmp_path)
    calls: list[dict[str, object]] = []

    def native_response(**kwargs: object) -> dict[str, object]:
        calls.append(kwargs)
        return {
            **_receipt(),
            "request_snapshot_digest": kwargs["request_snapshot_digest"],
            "status": "verified" if len(calls) == 1 else "replayed",
            "replayed": len(calls) > 1,
            "envelope_digest": "a" * 64 if len(calls) == 1 else "b" * 64,
        }

    monkeypatch.setattr(
        native,
        "matching_workspace_review_snapshot",
        lambda _store, _home, _request_id, _decision, current: dict(current),
    )
    monkeypatch.setattr(native, "_native_response", native_response)
    native.apply_native_workspace_review_decision(store, tmp_path / "guard-home", "request-1", {})
    staged = tmp_path / "guard-home/native-runtime/workspace-review-requests/request-1.json"
    original_snapshot = staged.read_bytes()
    original_receipt = store.get_sync_payload(NATIVE_WORKSPACE_REVIEW_RECEIPT_STATE_PREFIX + "request-1")
    result = native.apply_native_workspace_review_decision(store, tmp_path / "guard-home", "request-1", {})
    assert len(calls) == 2 and calls[0]["request_snapshot_digest"] == calls[1]["request_snapshot_digest"]
    assert result["status"] == "already_resolved" and result["native_replayed"] is True
    assert staged.read_bytes() == original_snapshot
    assert store.get_sync_payload(NATIVE_WORKSPACE_REVIEW_RECEIPT_STATE_PREFIX + "request-1") == original_receipt


def test_resolved_row_does_not_bypass_native_verification(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store, request = _store(tmp_path)
    assert _resolve(store, request, _receipt())["resolved"] is True

    def rejected(**_kwargs: object) -> dict[str, object]:
        raise native.NativeWorkspaceReviewError("native_workspace_review_decision_signature_invalid")

    monkeypatch.setattr(native, "_native_response", rejected)
    with pytest.raises(native.NativeWorkspaceReviewError, match="native_workspace_review_decision_signature_invalid"):
        native.apply_native_workspace_review_decision(store, tmp_path / "guard-home", "request-1", {"forged": True})


def test_resolved_native_result_must_match_original_consumption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, request = _store(tmp_path)
    assert _resolve(store, request, _receipt())["resolved"] is True
    changed = {**_receipt(), "status": "replayed", "replayed": True, "action_binding": "0" * 64}
    monkeypatch.setattr(native, "_native_response", lambda **_kwargs: changed)
    with pytest.raises(native.NativeWorkspaceReviewError, match="native_workspace_review_request_resolved"):
        native.apply_native_workspace_review_decision(store, tmp_path / "guard-home", "request-1", {})
