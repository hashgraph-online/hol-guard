"""Genuine signed expressions retain selectors and snapshot-local associations."""

from __future__ import annotations

import base64
import copy
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.native_policy_authority_read import read_native_policy_authority_inputs
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from codex_plugin_scanner.guard.policy_bundle_materialization import bind_policy_bundle_materialization
from codex_plugin_scanner.guard.policy_bundle_parser import policy_bundle_acceptance_checkpoint
from codex_plugin_scanner.guard.policy_bundle_trusted_keys import policy_bundle_keyring_payload
from codex_plugin_scanner.guard.policy_bundle_v2 import (
    canonical_policy_bundle_v2_payload,
    computed_policy_bundle_v2_hash,
    payload_hash_for_policy_bundle_v2,
)
from codex_plugin_scanner.guard.policy_document_types import PolicyCompilationError
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_policy_bundle_v2 import _signed_bundle, _verification_key

_NOW = "2026-09-17T00:00:00Z"
_TIME = datetime(2026, 9, 17, tzinfo=timezone.utc).timestamp()
_WORKSPACE = "00000000-0000-4000-8000-000000000061"


def _store(tmp_path: Path, *, changes: dict[str, object] | None = None) -> GuardStore:
    store = GuardStore(tmp_path / "guard-home")
    device = store.get_device_metadata()
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key = _verification_key(private, workspace_id=_WORKSPACE)
    condition: dict[str, object] = {
        "field": "command",
        "operator": "startsWith",
        "value": "printf",
        "caseSensitive": True,
    }
    expression_match: dict[str, object] = {
        "harnesses": ["codex"],
        "artifacts": ["synthetic-command"],
        "workspaces": ["/synthetic/project"],
        "commands": {"combinator": "all", "conditions": [condition]},
    }
    if changes:
        expression_match.update(changes)
        if expression_match.get("devices") == ["local-installation"]:
            expression_match["devices"] = [device["installation_id"]]
    generic: dict[str, object] = {
        "id": "generic.rule",
        "enabled": True,
        "effect": "allow",
        "match": {"harnesses": ["codex"], "artifacts": ["synthetic-generic"]},
        "lifetime": {"mode": "permanent", "expiresAt": None},
        "provenance": {"source": "cloud", "createdAt": _NOW},
    }
    command: dict[str, object] = {
        "id": "command.rule",
        "enabled": True,
        "effect": "block",
        "match": expression_match,
        "lifetime": {"mode": "until", "expiresAt": "2026-09-18T00:00:00Z"},
        "provenance": {"source": "cloud", "createdAt": _NOW},
    }
    payload: dict[str, object] = {
        "apiVersion": "guard.hashgraphonline.com/v1alpha1",
        "kind": "GuardPolicy",
        "metadata": {"id": "synthetic.commands", "name": "Synthetic commands", "revision": 7},
        "spec": {"defaults": {"mode": "enforce", "defaultAction": "warn"}, "rules": [generic, command]},
    }
    bundle = _signed_bundle(private, key, payload_base=payload, rollout_state="enforcing", bundle_version=9)
    bundle["workspaceId"] = _WORKSPACE
    bundle["bundleHash"] = computed_policy_bundle_v2_hash(bundle)
    verifier = bundle["verifier"]
    assert isinstance(verifier, dict)
    verifier["signature"] = base64.b64encode(
        private.sign(
            canonical_policy_bundle_v2_payload(bundle),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    ).decode("ascii")
    store.set_sync_payload("oauth_local_credentials", {"workspace_id": _WORKSPACE}, _NOW)
    # Stage the genuine complete signed source at the existing atomic storage
    # boundary. Only the independent generic row enters its ordinary cache.
    # This fixture does not claim the sync runner admits expressions yet.
    applied = store.apply_policy_bundle_authority(
        [
            PolicyDecision(
                harness="codex",
                scope="artifact",
                action="allow",
                artifact_id="synthetic-generic",
                owner="generic.rule",
                source="policy-bundle-canonical",
            )
        ],
        _NOW,
        policy_bundle=bundle,
        policy_bundle_keyring=policy_bundle_keyring_payload((key,), workspace_id=_WORKSPACE),
        cloud_exceptions=[],
        policy_bundle_ack={"bundleHash": bundle["bundleHash"], "bundleVersion": 9, "status": "validated"},
        policy_bundle_checkpoint=policy_bundle_acceptance_checkpoint(bundle),
        update_last_good=True,
        remote_write_authorized=True,
    )
    assert applied is not None
    return store


def test_signed_source_reconstructs_expression_without_selector_only_cache_rows(tmp_path: Path) -> None:
    store = _store(tmp_path)
    captured = read_native_policy_authority_inputs(store, now=_TIME)
    assert len(captured.authority.rows) == 2 and len(captured.authority.command_expressions) == 1
    binding = captured.authority.command_expressions[0]
    row = next(row for row in captured.authority.rows if row.decision_id == binding.decision_id)
    expected_workspace = store._normalized_policy_keys(
        PolicyDecision(
            harness="codex",
            scope="workspace",
            action="block",
            artifact_id="synthetic-command",
            workspace="/synthetic/project",
        )
    )[2]
    assert (row.artifact_id, row.workspace, row.action.value) == ("synthetic-command", expected_workspace, "block")
    assert row.expires_at_ms == 1789689600000
    identity = dict(captured.rule_identities)[row.decision_id]
    assert identity.rule_id == "command.rule" and identity.policy_version == "7"
    assert identity.publication is not None and identity.publication.bundle_version == 9
    assert all(row["artifact_id"] != "synthetic-command" for row in store.list_policy_decisions())
    with store._connect() as connection:
        connection.execute("delete from policy_decisions where source='policy-bundle-canonical'")
    assert read_native_policy_authority_inputs(store, now=_TIME).authority == captured.authority


def test_ast_and_provenance_follow_id_remap_and_authenticated_expiry(tmp_path: Path) -> None:
    store = _store(tmp_path)
    before = read_native_policy_authority_inputs(store, now=_TIME)
    store.upsert_policy(
        PolicyDecision(harness="codex", scope="artifact", action="allow", artifact_id="aaa-local", source="local"), _NOW
    )
    after = read_native_policy_authority_inputs(store, now=_TIME)
    assert before.input_digest != after.input_digest
    binding = after.authority.command_expressions[0]
    selected = next(row for row in after.authority.rows if row.decision_id == binding.decision_id)
    assert selected.artifact_id == "synthetic-command"
    assert dict(after.rule_identities)[binding.decision_id].rule_id == "command.rule"
    assert binding.expression_json == before.authority.command_expressions[0].expression_json
    expired = read_native_policy_authority_inputs(store, now=_TIME + 86_400)
    assert expired.authority.command_expressions == ()
    assert all(row.artifact_id != "synthetic-command" for row in expired.authority.rows)


@pytest.mark.parametrize("mutation", ["signature", "key", "materialization"])
def test_expression_capture_requires_current_signed_source_and_mac(tmp_path: Path, mutation: str) -> None:
    store = _store(tmp_path)
    state_key = {
        "signature": "policy_bundle",
        "key": "policy_bundle_keyring",
        "materialization": "policy_bundle_materialization",
    }[mutation]
    value = store.get_sync_payload(state_key)
    assert isinstance(value, dict)
    changed = copy.deepcopy(value)
    if mutation == "signature":
        verifier = changed["verifier"]
        assert isinstance(verifier, dict)
        verifier["signature"] = "invalid"
    elif mutation == "key":
        keys = changed["keys"]
        assert isinstance(keys, list) and isinstance(keys[0], dict)
        keys[0]["state"] = "revoked"
    else:
        changed["materializedAt"] = "2026-09-17T01:00:00+00:00"
    store.set_sync_payload(state_key, changed, _NOW)
    with pytest.raises(NativePolicySnapshotError):
        read_native_policy_authority_inputs(store, now=_TIME)


@pytest.mark.parametrize("target,matched", [("local-installation", True), ("synthetic-other-installation", False)])
def test_device_target_uses_exact_mac_bound_canonical_installation(
    tmp_path: Path,
    target: str,
    matched: bool,
) -> None:
    store = _store(tmp_path, changes={"devices": [target]})
    captured = read_native_policy_authority_inputs(store, now=_TIME)
    assert bool(captured.authority.command_expressions) is matched
    with store._connect() as connection:
        connection.execute(
            "update guard_devices set installation_id='changed-installation' where device_key='local-device'"
        )
    with pytest.raises(NativePolicySnapshotError, match="materialization_unavailable"):
        read_native_policy_authority_inputs(store, now=_TIME)


@pytest.mark.parametrize("operator,case_sensitive", [("glob", True), ("regex", True), ("exact", False)])
def test_unsupported_expression_refuses_whole_source(tmp_path: Path, operator: str, case_sensitive: bool) -> None:
    store = _store(tmp_path)
    # Stage a valid source first. Then model hostile durable replacement by a
    # different genuinely signed source. Ordinary staging now refuses this
    # dialect earlier; the reader must independently reject it too.
    bundle = copy.deepcopy(store.get_sync_payload("policy_bundle"))
    assert isinstance(bundle, dict)
    payload = bundle["payload"]
    assert isinstance(payload, dict)
    spec = payload["spec"]
    assert isinstance(spec, dict)
    rules = spec["rules"]
    assert isinstance(rules, list) and isinstance(rules[1], dict)
    match = rules[1]["match"]
    assert isinstance(match, dict)
    match.update(
        {
            "devices": ["off-target"],
            "commands": {
                "combinator": "all",
                "conditions": [
                    {
                        "field": "command",
                        "operator": operator,
                        "value": "printf",
                        "caseSensitive": case_sensitive,
                    }
                ],
            },
        }
    )
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key = _verification_key(private, workspace_id=_WORKSPACE)
    replacement = _signed_bundle(private, key, payload_base=payload, rollout_state="enforcing", bundle_version=10)
    replacement["workspaceId"] = _WORKSPACE
    replacement["payloadHash"] = payload_hash_for_policy_bundle_v2(replacement)
    replacement["bundleHash"] = computed_policy_bundle_v2_hash(replacement)
    verifier = replacement["verifier"]
    assert isinstance(verifier, dict)
    verifier["signature"] = base64.b64encode(
        private.sign(
            canonical_policy_bundle_v2_payload(replacement),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    ).decode("ascii")
    with store._connect() as connection:
        _, materialization = bind_policy_bundle_materialization(
            store,
            connection,
            bundle=replacement,
            rows=[],
            now=_NOW,
            require_source_binding=True,
        )
        for name, value in {
            "policy_bundle": replacement,
            "policy_bundle_keyring": policy_bundle_keyring_payload((key,), workspace_id=_WORKSPACE),
            "policy_bundle_materialization": materialization,
        }.items():
            connection.execute("update sync_state set payload_json=? where state_key=?", (json.dumps(value), name))
    with pytest.raises(PolicyCompilationError, match=r"command\.rule"):
        read_native_policy_authority_inputs(store, now=_TIME)
