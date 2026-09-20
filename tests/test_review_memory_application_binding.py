"""Real signed memory distinguishes registered delivery IDs from local identities."""

from __future__ import annotations

import copy
from datetime import datetime, timezone

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.exact_command import EXACT_COMMAND_CONTRACT, exact_command_sha256
from codex_plugin_scanner.guard.review_memory_application import validated_memory_application
from codex_plugin_scanner.guard.review_oauth_binding import guard_review_oauth_metadata
from codex_plugin_scanner.guard.runtime.command_executors import execute_guard_command_job
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_review_policy_memory_command import _bundle, _resign_bundle, _store

_REGISTERED = "11111111-1111-4111-8111-111111111111"
_COMMAND = "\tprintf 'Synthetic  Value'\r\n"
_NOW = datetime.now(timezone.utc).isoformat()


def _connected(tmp_path):
    store = _store(tmp_path)
    credentials = store.get_oauth_local_credentials(allow_primary=False)
    credentials["machine_id"] = store.get_or_create_installation_id()
    store.set_oauth_local_credentials(
        **{
            key: credentials[key]
            for key in (
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
            )
        },
        now=_NOW,
    )
    return store


def _job(store):
    oauth = guard_review_oauth_metadata(store, require_device_dpop_binding=True)
    bundle = _bundle(store)
    rule = bundle["memoryRules"][0]
    rule.pop("projectIdentity", None)
    rule.pop("artifactHash", None)
    rule["target"]["machineIds"] = [_REGISTERED]
    rule["exactCommand"] = {"contractVersion": EXACT_COMMAND_CONTRACT, "sha256": exact_command_sha256(_COMMAND)}
    bundle = _resign_bundle(bundle)
    expected = {key: bundle[key] for key in ("bundleHash", "bundleVersion", "policyVersion", "workspaceId")}
    expected.update(deviceId=oauth.device_id, machineId=oauth.machine_id, machineInstallationId=_REGISTERED)
    return {
        "operation": "guard.review.syncPolicyMemory",
        "workspaceId": oauth.workspace_id,
        "targetDeviceId": oauth.machine_id,
        "targetGrantId": oauth.grant_id,
        "targetMachineInstallationId": _REGISTERED,
        "payload": {"decisionMemoryBundle": bundle, "expectedApplication": expected},
    }


def _execute(store, job):
    return execute_guard_command_job(
        job,
        context=HarnessContext(home_dir=store.guard_home.parent, workspace_dir=None, guard_home=store.guard_home),
        store=store,
        now=lambda: _NOW,
    )


def _selected(store, command=_COMMAND):
    return store.resolve_policy_decision(
        "cursor", "plugin:hol/deploy", exact_command_sha256=exact_command_sha256(command), consume_one_shot=False
    )


def test_registered_delivery_is_applied_reconstructed_and_acknowledged_exactly(tmp_path):
    store = _connected(tmp_path)
    job = _job(store)
    result = _execute(store, job)
    assert "failureCode" not in result, result
    ack = result["data"]["decisionMemoryAck"]
    assert ack["status"] == "accepted" and ack["appliedRuleCount"] == 1 and ack["rejectedRuleIds"] == []
    assert all(ack[key] == value for key, value in job["payload"]["expectedApplication"].items())
    assert ack["machineId"] != ack["machineInstallationId"]
    assert _selected(store)["action"] == "allow"
    assert _selected(store, _COMMAND.strip()) is None
    assert (
        store.resolve_policy_decision(
            "cursor", "different:artifact", exact_command_sha256=exact_command_sha256(_COMMAND)
        )
        is None
    )
    assert _selected(GuardStore(store.guard_home))["action"] == "allow"
    original_rows = store.list_policy_decisions()
    assert _execute(store, job)["data"]["decisionMemoryAck"] == ack
    assert store.list_policy_decisions() == original_rows
    assert store.claim_approval_reuse_decision(_selected(store))


@pytest.mark.parametrize("field", ["targetDeviceId", "targetGrantId", "targetMachineInstallationId", "workspaceId"])
def test_outer_authenticated_target_mismatch_cannot_apply_memory(tmp_path, field):
    store = _connected(tmp_path)
    job = _job(store)
    job[field] = "22222222-2222-4222-8222-222222222222"
    assert _execute(store, job)["failureCode"] == "decision_memory_application_target_mismatch"
    assert store.list_policy_decisions() == []


@pytest.mark.parametrize(
    "field",
    ["bundleHash", "bundleVersion", "policyVersion", "workspaceId", "deviceId", "machineId", "machineInstallationId"],
)
def test_complete_expected_application_is_independently_bound(tmp_path, field):
    store = _connected(tmp_path)
    job = _job(store)
    job["payload"]["expectedApplication"][field] = "22222222-2222-4222-8222-222222222222"
    assert "failureCode" in _execute(store, job)
    assert store.list_policy_decisions() == []


def test_registered_projection_is_authenticated_in_durable_registry(tmp_path):
    store = _connected(tmp_path)
    job = _job(store)
    assert _execute(store, job)["data"]["status"] == "accepted"
    registry = store.get_sync_payload("guard_review_memory_registry")
    registry["registeredInstallations"][job["payload"]["decisionMemoryBundle"]["bundleHash"]] = (
        "22222222-2222-4222-8222-222222222222"
    )
    store.set_sync_payload("guard_review_memory_registry", registry, _NOW)
    assert _selected(store) is None


def test_binding_is_rechecked_under_apply_credential_lock(tmp_path):
    store = _connected(tmp_path)
    job = _job(store)
    application = validated_memory_application(job["payload"], job, store=store)
    store.rotate_installation_id(_NOW)
    with pytest.raises(ValueError, match="application_binding_mismatch"):
        store.apply_review_policy_memory_state(
            job["payload"]["decisionMemoryBundle"], now=_NOW, application=application
        )
    assert store.list_policy_decisions() == []


def test_duplicate_cannot_echo_a_different_registered_target(tmp_path):
    store = _connected(tmp_path)
    job = _job(store)
    assert _execute(store, job)["data"]["status"] == "accepted"
    changed = copy.deepcopy(job)
    changed["targetMachineInstallationId"] = "22222222-2222-4222-8222-222222222222"
    changed["payload"]["expectedApplication"]["machineInstallationId"] = changed["targetMachineInstallationId"]
    assert _execute(store, changed)["failureCode"] == "decision_memory_application_binding_mismatch"


def test_authenticated_workspace_change_invalidates_registered_memory(tmp_path):
    store = _connected(tmp_path)
    job = _job(store)
    assert _execute(store, job)["data"]["status"] == "accepted"
    credentials = store.get_oauth_local_credentials(allow_primary=False)
    credentials["workspace_id"] = "different-workspace"
    store.set_oauth_local_credentials(
        **{
            key: credentials[key]
            for key in (
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
            )
        },
        now=_NOW,
    )
    assert _selected(store) is None
    assert _execute(store, job)["failureCode"] == "decision_memory_application_target_mismatch"


def test_legacy_and_registered_signed_rules_keep_their_own_target_binding(tmp_path):
    store = _connected(tmp_path)
    legacy = _bundle(store)
    assert store.apply_review_policy_memory_state(legacy, now=_NOW)["status"] == "accepted"
    job = _job(store)
    bundle = job["payload"]["decisionMemoryBundle"]
    bundle["policyVersion"] = "policy-version-next"
    bundle["bundleVersion"] = "review-memory-receipt-2"
    bundle["memoryRules"][0].update(ruleId="registered-second", artifactId="plugin:hol/second")
    bundle = _resign_bundle(bundle)
    job["payload"]["decisionMemoryBundle"] = bundle
    job["payload"]["expectedApplication"].update(
        {key: bundle[key] for key in ("bundleHash", "bundleVersion", "policyVersion")}
    )
    assert _execute(store, job)["data"]["status"] == "accepted"
    assert store.resolve_policy("cursor", "plugin:hol/deploy", "b" * 64) == "allow"
    assert (
        store.resolve_policy("cursor", "plugin:hol/second", exact_command_sha256=exact_command_sha256(_COMMAND))
        == "allow"
    )
    assert len(store.list_policy_decisions()) == 2
