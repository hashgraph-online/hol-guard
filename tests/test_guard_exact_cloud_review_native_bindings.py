from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.review_contracts import (
    GuardReviewContractError,
    build_local_review_request_claim,
    compute_legacy_local_review_request_claim_hash,
    local_review_request_claim_hash_matches,
    validate_local_review_request_claim,
    validate_remote_approval_request_binding,
)
from codex_plugin_scanner.guard.review_native_claim_bindings import native_review_claim_bindings
from codex_plugin_scanner.guard.runtime.exact_cloud_review import ExactCloudReviewError, _oauth_metadata
from codex_plugin_scanner.guard.runtime.exact_cloud_review_apply import apply_exact_cloud_review
from tests.guard_exact_cloud_review_support import remote_approval as _remote_approval
from tests.test_guard_exact_cloud_review_transport import _exact_job


def test_native_policy_binding_covers_resident_policy_fields(tmp_path: Path) -> None:
    store, _job_payload = _exact_job(tmp_path)
    request = store.get_approval_request("exact-transport")
    assert isinstance(request, dict)
    request.update(
        {
            "recommended_scope": "artifact",
            "decision_v2_json": {"policyVersion": "policy-1", "approval_scopes": ["artifact", "workspace"]},
        }
    )
    original = native_review_claim_bindings(request)["nativePolicyBinding"]
    changed_scope = {**request, "recommended_scope": "workspace"}
    changed_approval_scopes = {
        **request,
        "decision_v2_json": {"policyVersion": "policy-1", "approval_scopes": ["artifact"]},
    }
    assert native_review_claim_bindings(changed_scope)["nativePolicyBinding"] != original
    assert native_review_claim_bindings(changed_approval_scopes)["nativePolicyBinding"] != original


def test_v1_claim_hash_remains_compatible_without_native_fields(tmp_path: Path) -> None:
    store, _job_payload = _exact_job(tmp_path)
    request = store.get_approval_request("exact-transport")
    assert isinstance(request, dict)
    oauth = _oauth_metadata(store)
    current = build_local_review_request_claim(request_row=request, oauth=oauth, store=store)
    legacy = {
        key: value
        for key, value in current.items()
        if key
        not in {
            "nativeActionBinding",
            "nativeIntentBinding",
            "nativePolicyBinding",
            "nativeBindingVersion",
            "nativeBindingDigest",
        }
    }
    legacy["claimHash"] = compute_legacy_local_review_request_claim_hash(legacy)
    assert legacy["claimHash"] != current["claimHash"]
    assert validate_local_review_request_claim(legacy) == legacy


def test_native_binding_digest_rejects_tampered_binding(tmp_path: Path) -> None:
    store, _job_payload = _exact_job(tmp_path)
    request = store.get_approval_request("exact-transport")
    assert isinstance(request, dict)
    current = build_local_review_request_claim(request_row=request, oauth=_oauth_metadata(store), store=store)
    tampered = {**current, "nativePolicyBinding": "f" * 64}
    with pytest.raises(GuardReviewContractError, match="native_binding_digest_mismatch"):
        validate_local_review_request_claim(tampered)


def test_v2_claim_does_not_match_legacy_hash_without_explicit_compatibility(tmp_path: Path) -> None:
    store, _job_payload = _exact_job(tmp_path)
    request = store.get_approval_request("exact-transport")
    assert isinstance(request, dict)
    current = build_local_review_request_claim(request_row=request, oauth=_oauth_metadata(store), store=store)
    legacy_hash = compute_legacy_local_review_request_claim_hash(current)

    assert not local_review_request_claim_hash_matches(current, legacy_hash)
    assert local_review_request_claim_hash_matches(current, legacy_hash, allow_legacy=True)


def test_markerless_legacy_approval_rejects_changed_native_commitment(tmp_path: Path) -> None:
    store, _job_payload = _exact_job(tmp_path)
    request = store.get_approval_request("exact-transport")
    assert isinstance(request, dict)
    oauth = _oauth_metadata(store)
    current = build_local_review_request_claim(request_row=request, oauth=oauth, store=store)
    legacy = {
        key: value
        for key, value in current.items()
        if key
        not in {
            "nativeActionBinding",
            "nativeIntentBinding",
            "nativePolicyBinding",
            "nativeBindingVersion",
            "nativeBindingDigest",
        }
    }
    legacy["claimHash"] = compute_legacy_local_review_request_claim_hash(legacy)
    approval = _remote_approval(store, "exact-transport", receipt_id="legacy-changed", source_claim=legacy)
    with store._connect() as connection:
        connection.execute(
            "update approval_requests set action_envelope_json = ? where request_id = ?",
            (json.dumps({"action_type": "shell_command", "command": "changed-command"}), "exact-transport"),
        )

    with pytest.raises(ExactCloudReviewError, match="remote_exact_request_stale"):
        apply_exact_cloud_review(store, remote_approval=approval)


@pytest.mark.parametrize("snapshot_read_fails", [False, True])
def test_markerless_legacy_approval_requires_retained_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    snapshot_read_fails: bool,
) -> None:
    store, _job_payload = _exact_job(tmp_path)
    request = store.get_approval_request("exact-transport")
    assert isinstance(request, dict)
    oauth = _oauth_metadata(store)
    current = build_local_review_request_claim(request_row=request, oauth=oauth, store=store)
    legacy = {
        key: value
        for key, value in current.items()
        if key
        not in {
            "nativeActionBinding",
            "nativeIntentBinding",
            "nativePolicyBinding",
            "nativeBindingVersion",
            "nativeBindingDigest",
        }
    }
    legacy["claimHash"] = compute_legacy_local_review_request_claim_hash(legacy)
    if snapshot_read_fails:

        def fail_snapshot_read(_request_id: str) -> list[dict[str, object]]:
            raise OSError("snapshot store unavailable")

        monkeypatch.setattr(store, "list_review_event_snapshots", fail_snapshot_read)
    else:
        monkeypatch.setattr(store, "list_review_event_snapshots", lambda _request_id: [])

    with pytest.raises(ExactCloudReviewError, match="remote_exact_request_stale"):
        apply_exact_cloud_review(
            store,
            remote_approval=_remote_approval(
                store,
                "exact-transport",
                receipt_id=f"legacy-compacted-{snapshot_read_fails}",
                source_claim=legacy,
            ),
        )


def test_markerless_legacy_approval_rejects_ambiguous_newer_native_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, _job_payload = _exact_job(tmp_path)
    original = store.get_approval_request("exact-transport")
    assert isinstance(original, dict)
    oauth = _oauth_metadata(store)
    original_claim = build_local_review_request_claim(request_row=original, oauth=oauth, store=store)
    legacy = {
        key: value
        for key, value in original_claim.items()
        if key
        not in {
            "nativeActionBinding",
            "nativeIntentBinding",
            "nativePolicyBinding",
            "nativeBindingVersion",
            "nativeBindingDigest",
        }
    }
    legacy["claimHash"] = compute_legacy_local_review_request_claim_hash(legacy)
    newer = {
        **original,
        "browser_intent_json": json.dumps({"intent": "browser.navigation", "target_domain": "hol.org"}),
    }
    newer_claim = build_local_review_request_claim(request_row=newer, oauth=oauth, store=store)
    assert compute_legacy_local_review_request_claim_hash(newer_claim) == legacy["claimHash"]
    with store._connect() as connection:
        connection.execute(
            "update approval_requests set browser_intent_json = ? where request_id = ?",
            (newer["browser_intent_json"], "exact-transport"),
        )
    monkeypatch.setattr(store, "list_review_event_snapshots", lambda _request_id: [newer, original])

    with pytest.raises(ExactCloudReviewError, match="remote_exact_request_stale"):
        apply_exact_cloud_review(
            store,
            remote_approval=_remote_approval(
                store,
                "exact-transport",
                receipt_id="legacy-ambiguous-native-snapshot",
                source_claim=legacy,
            ),
        )


def test_v2_signed_envelope_rejects_legacy_source_hash(tmp_path: Path) -> None:
    store, _job_payload = _exact_job(tmp_path)
    request = store.get_approval_request("exact-transport")
    assert isinstance(request, dict)
    oauth = _oauth_metadata(store)
    current = build_local_review_request_claim(request_row=request, oauth=oauth, store=store)
    envelope = _remote_approval(store, "exact-transport", receipt_id="v2-legacy-hash")
    envelope["sourceClaimHash"] = compute_legacy_local_review_request_claim_hash(current)

    with pytest.raises(GuardReviewContractError, match="remote_approval_claim_hash_mismatch"):
        validate_remote_approval_request_binding(
            envelope=envelope,
            request_row=request,
            claim_request_row=request,
            oauth=oauth,
            store=store,
        )


@pytest.mark.parametrize("digest", [None, "f" * 64])
def test_v2_signed_envelope_requires_current_native_binding_digest(tmp_path: Path, digest: str | None) -> None:
    store, _job_payload = _exact_job(tmp_path)
    request = store.get_approval_request("exact-transport")
    assert isinstance(request, dict)
    oauth = _oauth_metadata(store)
    envelope = _remote_approval(store, "exact-transport", receipt_id=f"v2-digest-{digest}")
    if digest is None:
        envelope.pop("nativeBindingDigest", None)
    else:
        envelope["nativeBindingDigest"] = digest

    with pytest.raises(GuardReviewContractError, match="remote_approval_claim_hash_mismatch"):
        validate_remote_approval_request_binding(
            envelope=envelope,
            request_row=request,
            claim_request_row=request,
            oauth=oauth,
            store=store,
        )


def test_exact_apply_uses_persisted_claim_after_outbox_compaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _job_payload = _exact_job(tmp_path)
    request = store.get_approval_request("exact-transport")
    raw_request = store.get_raw_approval_request_snapshot("exact-transport")
    assert isinstance(request, dict) and isinstance(raw_request, dict)
    oauth = _oauth_metadata(store)
    displayed_claim = build_local_review_request_claim(request_row=request, oauth=oauth, store=store)
    persisted_claim = build_local_review_request_claim(request_row=raw_request, oauth=oauth, store=store)
    assert displayed_claim["nativePolicyBinding"] != persisted_claim["nativePolicyBinding"]
    monkeypatch.setattr(store, "list_review_event_snapshots", lambda _request_id: [])

    resolution = apply_exact_cloud_review(
        store,
        remote_approval=_remote_approval(
            store, "exact-transport", receipt_id="raw-claim-after-ack", source_claim=persisted_claim
        ),
    )
    assert resolution.action == "allow"


def test_exact_apply_rejects_policy_change_after_persisted_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _job_payload = _exact_job(tmp_path)
    raw_request = store.get_raw_approval_request_snapshot("exact-transport")
    assert isinstance(raw_request, dict)
    claim = build_local_review_request_claim(request_row=raw_request, oauth=_oauth_metadata(store), store=store)
    approval = _remote_approval(store, "exact-transport", receipt_id="raw-claim-drift", source_claim=claim)
    monkeypatch.setattr(store, "list_review_event_snapshots", lambda _request_id: [])
    with store._connect() as connection:
        connection.execute(
            "update approval_requests set recommended_scope = ? where request_id = ?",
            ("workspace", "exact-transport"),
        )

    with pytest.raises(ExactCloudReviewError, match="remote_exact_request_stale"):
        apply_exact_cloud_review(store, remote_approval=approval)


def test_exact_apply_rejects_raw_policy_change_between_validation_and_resolution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _job_payload = _exact_job(tmp_path)
    raw_request = store.get_raw_approval_request_snapshot("exact-transport")
    assert isinstance(raw_request, dict)
    claim = build_local_review_request_claim(request_row=raw_request, oauth=_oauth_metadata(store), store=store)
    approval = _remote_approval(store, "exact-transport", receipt_id="raw-policy-race", source_claim=claim)
    normalized_before = store.get_approval_request("exact-transport")
    original_resolve = store.resolve_one_request_with_signed_remote_exact_result

    def race_before_resolution(request_id: str, **kwargs: Any) -> dict[str, object]:
        decision = json.loads(str(raw_request["decision_v2_json"]))
        decision["approval_scopes"] = ["artifact"]
        with store._connect() as connection:
            connection.execute(
                "update approval_requests set decision_v2_json = ? where request_id = ?",
                (json.dumps(decision), request_id),
            )
        assert store.get_approval_request(request_id) == normalized_before
        return original_resolve(request_id, **kwargs)

    monkeypatch.setattr(store, "resolve_one_request_with_signed_remote_exact_result", race_before_resolution)
    with pytest.raises(ExactCloudReviewError, match="remote_exact_request_stale"):
        _ = apply_exact_cloud_review(store, remote_approval=approval)
    unresolved = store.get_approval_request("exact-transport")
    assert isinstance(unresolved, dict) and unresolved["status"] == "pending"


def test_exact_apply_accepts_legacy_claim_without_native_bindings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _job_payload = _exact_job(tmp_path)
    request = store.get_approval_request("exact-transport")
    assert isinstance(request, dict)
    oauth = _oauth_metadata(store)
    current = build_local_review_request_claim(request_row=request, oauth=oauth, store=store)
    legacy = {
        key: value
        for key, value in current.items()
        if key
        not in {
            "nativeActionBinding",
            "nativeIntentBinding",
            "nativePolicyBinding",
            "nativeBindingVersion",
            "nativeBindingDigest",
        }
    }
    legacy["claimHash"] = compute_legacy_local_review_request_claim_hash(legacy)
    monkeypatch.setattr(store, "list_review_event_snapshots", lambda _request_id: [request])
    resolution = apply_exact_cloud_review(
        store,
        remote_approval=_remote_approval(store, "exact-transport", receipt_id="legacy-claim", source_claim=legacy),
    )
    assert resolution.action == "allow"
