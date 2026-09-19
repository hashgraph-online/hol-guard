"""Frozen native inputs retain original selectors and authenticated provenance."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import datetime, timezone

import pytest

from codex_plugin_scanner.guard.exact_command import exact_command_sha256
from codex_plugin_scanner.guard.native_policy_authority_read import read_native_policy_authority_inputs
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from codex_plugin_scanner.guard.review_memory_application import validated_memory_application
from codex_plugin_scanner.guard.review_oauth_binding import guard_review_oauth_metadata
from tests.test_exact_command_hook_policy import _publish
from tests.test_guard_review_policy_memory_command import _bundle, _resign_bundle, _store

_COMMAND = "\tprintf 'Synthetic  frozen source'\r\n"
_ARTIFACT = "codex:project:synthetic-frozen-source"


@pytest.mark.parametrize("source", ["canonical", "memory"])
def test_actual_signed_exact_selector_survives_frozen_reconstruction(tmp_path, source):
    store = _store(tmp_path)
    _publish(store, _ARTIFACT, source, command=_COMMAND, harness="codex")
    now = datetime.now(timezone.utc).timestamp()
    result = read_native_policy_authority_inputs(store, now=now)
    assert len(result.authority.rows) == 1
    row = result.authority.rows[0]
    assert row.artifact_id == _ARTIFACT
    assert row.exact_command_sha256 == exact_command_sha256(_COMMAND)
    assert row.exact_command_sha256 != exact_command_sha256(_COMMAND.strip())
    with store._connect() as connection:
        connection.execute("update policy_decisions set exact_command_sha256 = ?", ("f" * 64,))
    reread = read_native_policy_authority_inputs(store, now=now)
    assert reread.authority == result.authority
    assert reread.input_digest == result.input_digest
    assert (len(result.rule_identities) == 1) is (source == "canonical")


def test_frozen_canonical_identity_survives_current_source_deletion(tmp_path):
    store = _store(tmp_path)
    _publish(store, _ARTIFACT, "canonical", command=_COMMAND, harness="codex")
    result = read_native_policy_authority_inputs(store, now=datetime.now(timezone.utc).timestamp())
    decision_id, identity = result.rule_identities[0]
    assert decision_id == result.authority.rows[0].decision_id
    assert identity.to_dict() == {
        "policyId": "synthetic-policy", "ruleId": "synthetic-rule", "policyVersion": "8",
    }
    assert identity.publication is not None
    bundle = store.get_sync_payload("policy_bundle")
    assert identity.publication.bundle_hash == bundle["bundleHash"]
    assert identity.publication.bundle_version == bundle["bundleVersion"]
    store.set_sync_payload("policy_bundle", {}, datetime.now(timezone.utc).isoformat())
    assert result.rule_identities == ((decision_id, identity),)
    with pytest.raises(FrozenInstanceError):
        identity.policy_version = "9"
    replacement = read_native_policy_authority_inputs(store, now=datetime.now(timezone.utc).timestamp())
    assert replacement.rule_identities == () and replacement.authority.rows == ()
    assert replacement.input_digest != result.input_digest


def _registered_memory(store):
    now = datetime.now(timezone.utc).isoformat()
    credentials = store.get_oauth_local_credentials()
    credentials["machine_id"] = store.get_device_metadata()["installation_id"]
    store.set_oauth_local_credentials(**{
        key: credentials[key] for key in (
            "issuer", "client_id", "refresh_token", "dpop_private_key_pem", "dpop_public_jwk",
            "dpop_public_jwk_thumbprint", "device_id", "grant_id", "machine_id", "workspace_id",
        )
    }, now=now)
    oauth = guard_review_oauth_metadata(store, require_device_dpop_binding=True)
    registered = "00000000-0000-4000-8000-000000000099"
    bundle = _bundle(store)
    rule = bundle["memoryRules"][0]
    rule.update(artifactId=_ARTIFACT, harnessId="codex", exactCommand={
        "contractVersion": "guard.exact-command.v1", "sha256": exact_command_sha256(_COMMAND),
    })
    rule.pop("artifactHash")
    rule.pop("projectIdentity")
    rule["target"]["machineIds"] = [registered]
    bundle = _resign_bundle(bundle)
    expected = {
        **{name: bundle[name] for name in ("bundleHash", "bundleVersion", "policyVersion", "workspaceId")},
        "deviceId": oauth.device_id, "machineId": oauth.machine_id, "machineInstallationId": registered,
    }
    job = {
        "targetMachineInstallationId": registered, "targetDeviceId": oauth.machine_id,
        "targetGrantId": oauth.grant_id, "workspaceId": oauth.workspace_id,
    }
    application = validated_memory_application(
        {"expectedApplication": expected, "decisionMemoryBundle": bundle}, job, store=store,
    )
    assert store.apply_review_policy_memory_state(bundle, now=now, application=application)["status"] == "accepted"
    return now


def test_frozen_reader_retains_verified_registered_memory_target_map(tmp_path):
    store = _store(tmp_path)
    now = _registered_memory(store)
    result = read_native_policy_authority_inputs(store, now=datetime.fromisoformat(now).timestamp())
    assert [(row.artifact_id, row.exact_command_sha256) for row in result.authority.rows] == [
        (_ARTIFACT, exact_command_sha256(_COMMAND)),
    ]
    assert result.rule_identities == ()


@pytest.mark.parametrize("mutation", ["registered-target", "grant"])
def test_frozen_reader_refuses_unbound_registered_memory(tmp_path, mutation):
    store = _store(tmp_path)
    now = _registered_memory(store)
    key = "guard_review_memory_registry" if mutation == "registered-target" else "oauth_local_credentials"
    state = store.get_sync_payload(key)
    if mutation == "registered-target":
        state["registeredInstallations"] = {
            digest: "00000000-0000-4000-8000-000000000098" for digest in state["registeredInstallations"]
        }
    else:
        state["grant_id"] = "synthetic-different-grant"
    store.set_sync_payload(key, state, now)
    with pytest.raises((NativePolicySnapshotError, ValueError), match=r"memory|binding"):
        read_native_policy_authority_inputs(store, now=datetime.fromisoformat(now).timestamp())
