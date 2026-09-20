"""The scoped producer reconstructs complete current authority before encoding."""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.managed_controls_policy_bundle import (
    MANAGED_CONTROLS_ACTIVE_STATE_KEY,
    MANAGED_CONTROLS_REVISION_STATE_KEY,
)
from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.native_policy_authority_read import read_native_policy_authority_inputs
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth
from tests.test_canonical_policy_row_authority import _ARTIFACT, _NOW, _activated_store
from tests.test_guard_review_policy_memory_command import _bundle, _resign_bundle, _store

_TIME = datetime.fromisoformat(_NOW.replace("Z", "+00:00")).timestamp()


def test_reader_uses_one_captured_source_and_omits_private_credentials(tmp_path: Path, monkeypatch) -> None:
    store = _activated_store(tmp_path, action="block")

    def forbidden(*args, **kwargs):
        pytest.fail("compilation must use the captured transaction")

    monkeypatch.setattr(store, "get_sync_payload", forbidden)
    monkeypatch.setattr(store, "get_device_metadata", forbidden)
    result = read_native_policy_authority_inputs(store, now=_TIME)
    assert len(result.authority.rows) == 1
    assert result.authority.rows[0].artifact_id == _ARTIFACT
    assert result.authority.rows[0].action.value == "block"
    assert result.sources[0]["revision"] == 8
    assert result.defaults["defaultAction"] == "warn"
    assert "workspace-alpha" not in repr(result)
    assert "key_material" not in repr(result)


@pytest.mark.parametrize("mutation", ["delete", "action", "recency", "identity"])
def test_cached_signed_rows_cannot_remove_or_rewrite_compiled_authority(tmp_path: Path, mutation: str) -> None:
    store = _activated_store(tmp_path, action="block")
    expected = read_native_policy_authority_inputs(store, now=_TIME)
    with store._connect() as connection:
        if mutation == "delete":
            connection.execute("delete from policy_decisions where source = 'policy-bundle-canonical'")
        else:
            assignment = {
                "action": "action = 'allow'", "recency": "updated_at = '2030-01-01T00:00:00Z'",
                "identity": "artifact_id = 'synthetic-other'",
            }[mutation]
            connection.execute(f"update policy_decisions set {assignment} where source = 'policy-bundle-canonical'")
    result = read_native_policy_authority_inputs(store, now=_TIME)
    assert result.authority.content_digest == expected.authority.content_digest
    assert result.sources == expected.sources


def test_local_and_signed_exact_selector_authority_both_survive_local_replacement(tmp_path: Path) -> None:
    store = _activated_store(tmp_path, action="block")
    store.upsert_policy(
        PolicyDecision(harness="codex", scope="artifact", action="allow", artifact_id=_ARTIFACT, source="local"),
        "2026-09-17T00:00:01Z",
    )
    result = read_native_policy_authority_inputs(store, now=_TIME + 2)
    assert {(row.source_kind.value, row.action.value) for row in result.authority.rows} == {
        ("signed-bundle", "block"), ("local", "allow"),
    }
    local = next(row for row in result.authority.rows if row.source_kind.value == "local")
    signed = next(row for row in result.authority.rows if row.source_kind.value == "signed-bundle")
    assert local.updated_at_us > signed.updated_at_us


@pytest.mark.parametrize("mutation", ["timestamp", "mac", "key", "pending"])
def test_local_rows_require_current_protected_authority(tmp_path: Path, monkeypatch, mutation: str) -> None:
    store = _activated_store(tmp_path, action="block")
    store.upsert_policy(
        PolicyDecision(
            harness="codex", scope="artifact", action="allow", artifact_id="synthetic-local", source="local",
        ),
        _NOW,
    )
    if mutation in {"timestamp", "mac"}:
        column = "updated_at" if mutation == "timestamp" else "payload_mac"
        with store._connect() as connection:
            connection.execute(f"update policy_decisions set {column} = 'invalid' where source = 'local'")
    elif mutation == "key":
        monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda **kwargs: (None, None))
    else:
        state = store._load_policy_integrity_control_state(create=False)
        monkeypatch.setattr(store, "_load_policy_integrity_control_state", lambda **kwargs: {
            **state, "pending_generation": state["generation"] + 1,
        })
    with pytest.raises(NativePolicySnapshotError, match="local_unavailable"):
        read_native_policy_authority_inputs(store, now=_TIME)


def test_bundle_revocation_stops_compilation_even_with_untouched_cached_rows(tmp_path: Path) -> None:
    store = _activated_store(tmp_path)
    keyring = store.get_sync_payload("policy_bundle_keyring")
    keyring["keys"][0]["state"] = "revoked"
    store.set_sync_payload("policy_bundle_keyring", keyring, _NOW)
    with pytest.raises(NativePolicySnapshotError, match="bundle_unavailable"):
        read_native_policy_authority_inputs(store, now=_TIME)


def test_signed_memory_is_reconstructed_without_exporting_oauth_secrets(tmp_path: Path) -> None:
    store = _store(tmp_path)
    now = datetime.now(timezone.utc)
    assert store.apply_review_policy_memory_state(_bundle(store), now=now.isoformat())["status"] == "accepted"
    before = read_native_policy_authority_inputs(store, now=now.timestamp())
    with store._connect() as connection:
        connection.execute("delete from policy_decisions where source = 'cloud-signed-memory'")
    result = read_native_policy_authority_inputs(store, now=now.timestamp())
    assert result.authority.content_digest == before.authority.content_digest
    assert {row.source_kind.value for row in result.authority.rows} == {"signed-memory"}
    assert result.sources[0]["revision"] == "policy-version-current"
    visible = json.dumps(result.sources) + repr(result) + repr(result.authority)
    assert "refresh-token" not in visible
    assert "PRIVATE KEY" not in visible
    assert "dpop_private_key_pem" not in visible


def test_exported_mappings_cannot_mutate_the_verified_input(tmp_path: Path) -> None:
    result = read_native_policy_authority_inputs(_activated_store(tmp_path), now=_TIME)
    result.sources[0]["revision"] = "forged"
    result.defaults["defaultAction"] = "allow"
    assert result.sources[0]["revision"] == 8
    assert result.defaults["defaultAction"] == "warn"


def test_targeted_rules_do_not_appear_for_a_different_installation(tmp_path: Path) -> None:
    store = _activated_store(tmp_path, action="block")
    assert len(read_native_policy_authority_inputs(store, now=_TIME).authority.rows) == 1
    with store._connect() as connection:
        connection.execute(
            "update guard_devices set installation_id = '00000000-0000-4000-8000-000000000099' "
            "where device_key = 'local-device'"
        )
    result = read_native_policy_authority_inputs(store, now=_TIME)
    assert result.authority.rows == ()
    assert result.defaults["defaultAction"] == "warn"


def test_materialization_recency_must_authenticate_before_source_reconstruction(tmp_path: Path) -> None:
    store = _activated_store(tmp_path)
    binding = store.get_sync_payload("policy_bundle_materialization")
    binding["materializedAt"] = "2026-09-17T01:00:00+00:00"
    store.set_sync_payload("policy_bundle_materialization", binding, _NOW)
    with pytest.raises(NativePolicySnapshotError, match="materialization_unavailable"):
        read_native_policy_authority_inputs(store, now=_TIME)


def test_one_shot_grants_are_neither_consumed_nor_copied_into_reusable_output(tmp_path: Path) -> None:
    from tests.test_guard_approval_reuse import _approval_context_token

    store = _activated_store(tmp_path)
    artifact = "codex:project:tool-action:synthetic-single-use"
    digest = _approval_context_token(content="sha256:synthetic-single-use")
    approval = store.record_local_once_approval(
        request_id="synthetic-request", harness="codex", artifact_id=artifact, artifact_hash=digest,
        workspace=str(tmp_path), publisher=None, action="allow", created_at=_NOW,
        expires_at="2026-09-17T01:00:00+00:00",
    )
    assert approval is not None
    before = read_native_policy_authority_inputs(store, now=_TIME)
    after = read_native_policy_authority_inputs(store, now=_TIME)
    assert before.authority.content_digest == after.authority.content_digest
    assert artifact not in {row.artifact_id for row in after.authority.rows}
    selected = store.resolve_policy_decision(
        "codex", artifact, artifact_hash=digest, workspace=str(tmp_path), now=_NOW, consume_one_shot=False,
    )
    assert selected is not None and selected["approval_id"] == approval
    assert store.claim_approval_reuse_decision(selected, now=_NOW)
    assert not store.claim_approval_reuse_decision(selected, now=_NOW)


def test_protected_state_change_during_capture_invalidates_the_result(tmp_path: Path, monkeypatch) -> None:
    store = _activated_store(tmp_path)
    store.upsert_policy(
        PolicyDecision(harness="codex", scope="artifact", action="block", artifact_id="synthetic-local"), _NOW,
    )
    trusted = store._load_policy_integrity_control_state(create=False)
    reads = 0

    def changing_control(*, create, connection=None):
        nonlocal reads
        assert not create
        reads += 1
        return trusted if reads == 1 else {**trusted, "generation": trusted["generation"] + 1}

    monkeypatch.setattr(store, "_load_policy_integrity_control_state", changing_control)
    with pytest.raises(NativePolicySnapshotError, match="changed_during_read"):
        read_native_policy_authority_inputs(store, now=_TIME)


def test_signed_source_expiry_remains_a_whole_input_bound(tmp_path: Path) -> None:
    store = _activated_store(tmp_path)
    result = read_native_policy_authority_inputs(store, now=_TIME)
    assert result.expires_at_ms is not None and result.expires_at_ms > _TIME * 1_000
    with pytest.raises(NativePolicySnapshotError, match="bundle_unavailable"):
        read_native_policy_authority_inputs(store, now=result.expires_at_ms / 1_000 + 1)


@pytest.mark.parametrize("state_key", [MANAGED_CONTROLS_ACTIVE_STATE_KEY, MANAGED_CONTROLS_REVISION_STATE_KEY])
def test_unauthenticated_managed_residue_refuses_the_whole_publication(
    tmp_path: Path, state_key: str,
) -> None:
    store = _activated_store(tmp_path)
    store.set_sync_payload(state_key, {}, _NOW)
    view = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    assert view.health is AuthorityHealth.TAMPERED
    with pytest.raises(NativePolicySnapshotError, match=r"^native_policy_authority_managed_unavailable$"):
        read_native_policy_authority_inputs(store, now=_TIME)


def test_authenticated_memory_rule_expiry_preserves_other_live_authority(tmp_path: Path) -> None:
    store = _store(tmp_path)
    now = datetime.now(timezone.utc)
    bundle = _bundle(store)
    retained = deepcopy(bundle["memoryRules"][0])
    retained.update(ruleId="synthetic-retained-memory", artifactId="plugin:hol/retained")
    bundle["memoryRules"][0]["expiresAt"] = (now + timedelta(seconds=2)).isoformat()
    bundle["memoryRules"].append(retained)
    assert store.apply_review_policy_memory_state(_resign_bundle(bundle), now=now.isoformat())["status"] == "accepted"
    before = read_native_policy_authority_inputs(store, now=now.timestamp())
    assert len(before.authority.rows) == 2
    after = read_native_policy_authority_inputs(store, now=now.timestamp() + 3)
    assert [row.artifact_id for row in after.authority.rows] == ["plugin:hol/retained"]
    assert after.input_digest != before.input_digest


def test_expired_memory_bundle_becomes_empty_without_becoming_new_authority(tmp_path: Path) -> None:
    store = _store(tmp_path)
    now = datetime.now(timezone.utc)
    bundle = _bundle(store)
    assert store.apply_review_policy_memory_state(bundle, now=now.isoformat())["status"] == "accepted"
    expiry = datetime.fromisoformat(bundle["expiresAt"]).timestamp()
    before = read_native_policy_authority_inputs(store, now=now.timestamp())
    after = read_native_policy_authority_inputs(store, now=expiry + 1)
    assert before.authority.rows and after.authority.rows == ()
    assert after.sources == before.sources
    assert after.input_digest != before.input_digest


@pytest.mark.parametrize("mutation", ["revoked-live-key", "forged-expiry"])
def test_missing_live_memory_authority_cannot_be_discarded_as_expired(tmp_path: Path, mutation: str) -> None:
    store = _store(tmp_path)
    now = datetime.now(timezone.utc)
    bundle = _bundle(store)
    assert store.apply_review_policy_memory_state(bundle, now=now.isoformat())["status"] == "accepted"
    if mutation == "revoked-live-key":
        state_key = "policy_bundle_keyring"
        state = store.get_sync_payload(state_key)
        state[0]["state"] = "revoked"
    else:
        state_key = "guard_review_memory_registry"
        state = store.get_sync_payload(state_key)
        state["bundles"][bundle["bundleHash"]]["expiresAt"] = (now - timedelta(seconds=1)).isoformat()
    store.set_sync_payload(state_key, state, now.isoformat())
    with pytest.raises(NativePolicySnapshotError, match="memory_unavailable"):
        read_native_policy_authority_inputs(store, now=now.timestamp())
