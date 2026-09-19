"""Signed memory must remain bound to the active named OAuth authority."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from threading import Event

import pytest

from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.runtime.review_policy_memory_executor import execute_review_policy_memory
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_review_policy_memory_command import _bundle, _resign_bundle, _store


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _apply(store: GuardStore, bundle: dict[str, object]) -> dict[str, object]:
    return execute_review_policy_memory({"decisionMemoryBundle": bundle}, store=store, generated_at=_now())


def _decision(store: GuardStore, artifact_id: str = "plugin:hol/deploy", *, workspace: str = "/workspace/repo"):
    return store.resolve_policy("cursor", artifact_id, artifact_hash="b" * 64, workspace=workspace, now=_now())


def _replace_binding(store: GuardStore, **changes: str) -> None:
    credentials = store.get_oauth_local_credentials(allow_primary=False)
    assert credentials is not None
    keys = (
        "issuer",
        "client_id",
        "refresh_token",
        "dpop_private_key_pem",
        "dpop_public_jwk",
        "dpop_public_jwk_thumbprint",
        "device_id",
        "grant_id",
        "machine_id",
        "workspace_id",
        "runtime_id",
    )
    kwargs = {key: credentials[key] for key in keys if key in credentials}
    kwargs.update(changes)
    store.set_oauth_local_credentials(**kwargs, now=_now())


@pytest.mark.parametrize(
    "change",
    [
        {"grant_id": "grant-reenrolled"},
        {"workspace_id": "workspace-B"},
        {"machine_id": "sibling-machine"},
        {"device_id": "sibling-device"},
        {"runtime_id": "runtime-replaced"},
    ],
)
def test_memory_permission_stops_after_active_oauth_binding_changes(tmp_path: Path, change: dict[str, str]) -> None:
    store = _store(tmp_path)
    assert _apply(store, _bundle(store))["status"] == "accepted"
    assert _decision(store) == "allow"
    _replace_binding(store, **change)
    assert _decision(store) is None


def test_memory_does_not_cross_named_oauth_source_or_disconnection(tmp_path: Path) -> None:
    store = _store(tmp_path)
    assert _apply(store, _bundle(store))["status"] == "accepted"
    other_source = GuardStore(store.guard_home, source="other-team")
    assert _decision(other_source) is None
    store.clear_oauth_local_credentials()
    assert _decision(store) is None
    assert store.get_sync_payload("guard_review_memory_registry") is None
    assert store.get_sync_payload("guard_review_memory_policy_version") is None


def test_explicit_reconnect_clears_memory_cursor_and_permission(tmp_path: Path) -> None:
    store = _store(tmp_path)
    assert _apply(store, _bundle(store))["status"] == "accepted"
    store.clear_cloud_sync_state_for_reconnect(now=_now())
    assert _decision(store) is None
    assert store.get_sync_payload("guard_review_memory_policy_version") is None


def test_claim_rechecks_memory_binding_after_preview(tmp_path: Path) -> None:
    store = _store(tmp_path)
    assert _apply(store, _bundle(store))["status"] == "accepted"
    preview = store.resolve_policy_decision_lookup(
        "cursor",
        "plugin:hol/deploy",
        artifact_hash="b" * 64,
        workspace="/workspace/repo",
        now=_now(),
        consume_one_shot=False,
    )
    decision = preview["decision"]
    assert decision is not None and decision["action"] == "allow"
    _replace_binding(store, workspace_id="workspace-B")
    assert not store.claim_approval_reuse_decision(decision, now=_now())


@pytest.mark.parametrize("project", ["git-project:v1:" + "ab" * 32, "opaque-unmapped-project"])
def test_unrepresentable_project_allow_is_refused_instead_of_becoming_artifact_wide(
    tmp_path: Path, project: str
) -> None:
    store = _store(tmp_path)
    bundle = _bundle(store, rule_scope="project")
    bundle["memoryRules"][0]["projectIdentity"] = project
    result = _apply(store, _resign_bundle(bundle))
    assert result["status"] in {"rejected", "unsupported"}
    assert _decision(store, workspace="/workspace/sibling") is None
    assert store.list_policy_decisions() == []


def test_memory_source_label_without_authorized_registry_never_grants_permission(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.upsert_policy(
        PolicyDecision(
            harness="cursor",
            scope="artifact",
            action="allow",
            artifact_id="plugin:hol/deploy",
            artifact_hash="b" * 64,
            source="cloud-signed-memory",
        ),
        _now(),
        remote_write_authorized=True,
    )
    assert _decision(store) is None


def test_stale_memory_version_reports_stale_after_revocation_without_resurrection(tmp_path: Path) -> None:
    store = _store(tmp_path)
    first = _bundle(store)
    first["policyVersion"] = "policy-version-1"
    _resign_bundle(first)
    assert _apply(store, first)["status"] == "accepted"
    revoked = _bundle(store)
    revoked.update(policyVersion="policy-version-2", memoryRules=[], revocations=["review-memory:receipt-1"])
    assert _apply(store, _resign_bundle(revoked))["status"] == "accepted"
    result = _apply(store, first)
    assert result["status"] == "stale"
    assert result["decisionMemoryAck"]["reason"] == "decision_memory_policy_version_stale"
    assert _decision(store) is None


def test_delayed_memory_apply_cannot_overwrite_a_newer_transaction(tmp_path: Path, monkeypatch) -> None:
    first_store = _store(tmp_path)
    second_store = GuardStore(first_store.guard_home)
    first = _bundle(first_store)
    first["policyVersion"] = "policy-version-1"
    second = _bundle(first_store)
    second["policyVersion"] = "policy-version-2"
    second["memoryRules"][0].update(ruleId="rule-second", artifactId="plugin:hol/second")
    entered = Event()
    resume = Event()
    original = first_store.apply_review_policy_memory_state

    def delayed(*args, **kwargs):
        entered.set()
        assert resume.wait(10), "newer transaction did not complete"
        return original(*args, **kwargs)

    monkeypatch.setattr(first_store, "apply_review_policy_memory_state", delayed)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(_apply, first_store, _resign_bundle(first))
        try:
            assert entered.wait(10), "delayed transaction was not reached"
            assert _apply(second_store, _resign_bundle(second))["status"] == "accepted"
        finally:
            resume.set()
        assert pending.result(timeout=10)["status"] == "stale"
    assert _decision(first_store) is None
    assert _decision(first_store, "plugin:hol/second") == "allow"


def test_tampered_saved_oauth_binding_cannot_reauthorize_signed_rows(tmp_path: Path) -> None:
    store = _store(tmp_path)
    assert _apply(store, _bundle(store))["status"] == "accepted"
    saved = store.get_sync_payload("guard_review_memory_registry")
    saved_version = store.get_sync_payload("guard_review_memory_policy_version")
    assert isinstance(saved, dict)
    _replace_binding(store, grant_id="grant-reenrolled")
    saved["oauthBinding"]["grantId"] = "grant-reenrolled"
    store.set_sync_payload("guard_review_memory_registry", saved, _now())
    store.set_sync_payload("guard_review_memory_policy_version", saved_version, _now())
    # Model a stale/forged materialized row without invoking any Cloud mutation.
    store.upsert_policy(
        PolicyDecision(
            harness="cursor",
            scope="artifact",
            action="allow",
            artifact_id="plugin:hol/deploy",
            artifact_hash="b" * 64,
            reason="Approved in cloud.",
            source="cloud-signed-memory",
            expires_at=saved["bundles"][next(iter(saved["bundles"]))]["expiresAt"],
        ),
        _now(),
        remote_write_authorized=True,
    )
    assert _decision(store) is None


def test_local_project_permission_matches_only_its_real_workspace_path(tmp_path: Path) -> None:
    store = _store(tmp_path)
    bundle = _bundle(store, rule_scope="project")
    bundle["memoryRules"][0]["projectIdentity"] = "/workspace/approved"
    assert _apply(store, _resign_bundle(bundle))["status"] == "accepted"
    assert _decision(store, workspace="/workspace/approved") == "allow"
    assert _decision(store, workspace="/workspace/sibling") is None


def test_memory_integrity_failure_rolls_back_rows_registry_cursor_and_ack(tmp_path: Path, monkeypatch) -> None:
    from codex_plugin_scanner.guard import review_memory_authority

    store = _store(tmp_path)
    assert _apply(store, _bundle(store))["status"] == "accepted"
    state_keys = ("guard_review_memory_registry", "guard_review_memory_policy_version", "guard_review_memory_last_ack")
    before_state = {key: store.get_sync_payload(key) for key in state_keys}
    before_rows = store.list_policy_decisions()
    next_bundle = _bundle(store)
    next_bundle["policyVersion"] = "policy-version-next"

    def fail_integrity(*args, **kwargs):
        raise RuntimeError("injected memory integrity failure")

    monkeypatch.setattr(review_memory_authority, "sign_local_authority_payload", fail_integrity)
    with pytest.raises(RuntimeError, match="injected memory integrity failure"):
        _apply(store, _resign_bundle(next_bundle))
    assert {key: store.get_sync_payload(key) for key in state_keys} == before_state
    assert store.list_policy_decisions() == before_rows
    assert _decision(store) == "allow"
