"""A workspace selector and a retained hash condition remain conjunctive."""

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.policy_bundle_parser import policy_bundle_acceptance_checkpoint
from codex_plugin_scanner.guard.policy_bundle_trusted_keys import policy_bundle_keyring_payload
from codex_plugin_scanner.guard.runtime.canonical_policy_decisions import build_canonical_policy_bundle_decisions
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_canonical_policy_row_authority import _NOW
from tests.test_policy_bundle_v2 import _signed_bundle, _verification_key


def _store_with_workspace_rule(tmp_path: Path, *, source: str, digest: str | None) -> GuardStore:
    store = GuardStore(tmp_path / "guard-home")
    if source == "local":
        store.upsert_policy(
            PolicyDecision(
                harness="codex",
                scope="workspace",
                action="allow",
                workspace="synthetic-workspace",
                artifact_hash=digest,
                source="local",
            ),
            _NOW,
        )
        return store
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key = _verification_key(private_key, workspace_id="workspace-alpha")
    bundle = _signed_bundle(
        private_key,
        key,
        rollout_state="enforcing",
        payload_base={
            "apiVersion": "guard.hashgraphonline.com/v1alpha1",
            "kind": "GuardPolicy",
            "metadata": {"id": "synthetic.workspace", "name": "Synthetic workspace rule", "revision": 8},
            "spec": {
                "defaults": {"mode": "enforce", "defaultAction": "warn"},
                "rules": [
                    {
                        "id": "synthetic.hash",
                        "enabled": True,
                        "effect": "allow",
                        "match": {"harnesses": ["codex"], "workspaces": ["synthetic-workspace"]},
                        "x-hol-local": {"scope": "workspace", "artifactHash": digest},
                        "lifetime": {"mode": "permanent", "expiresAt": None},
                        "provenance": {"source": "cloud", "createdAt": _NOW},
                    }
                ],
            },
        },
    )
    device = store.get_device_metadata()
    decisions = build_canonical_policy_bundle_decisions(
        bundle,
        device_id=device["installation_id"],
        device_name=device["device_label"],
    )
    assert len(decisions) == 1 and decisions[0].artifact_hash == digest and decisions[0].artifact_id is None
    store.set_sync_payload("oauth_local_credentials", {"workspace_id": "workspace-alpha"}, _NOW)
    store.apply_policy_bundle_authority(
        decisions,
        _NOW,
        policy_bundle=bundle,
        policy_bundle_keyring=policy_bundle_keyring_payload((key,), workspace_id="workspace-alpha"),
        cloud_exceptions=[],
        policy_bundle_ack={},
        policy_bundle_checkpoint=policy_bundle_acceptance_checkpoint(bundle),
        update_last_good=True,
        remote_write_authorized=True,
    )
    return store


@pytest.mark.parametrize("source", ["local", "signed"])
@pytest.mark.parametrize("consume", [False, True])
@pytest.mark.parametrize("request_hash", ["synthetic-approved-hash", "synthetic-other-hash", None])
def test_workspace_hash_condition_is_enforced_without_an_artifact_selector(
    tmp_path: Path,
    source: str,
    consume: bool,
    request_hash: str | None,
) -> None:
    store = _store_with_workspace_rule(tmp_path, source=source, digest="synthetic-approved-hash")
    decision = store.resolve_policy_decision(
        "codex",
        "synthetic-artifact",
        artifact_hash=request_hash,
        workspace="synthetic-workspace",
        now=_NOW,
        consume_one_shot=consume,
    )
    if request_hash == "synthetic-approved-hash":
        assert decision is not None and decision["action"] == "allow"
        if not consume:
            assert store.claim_approval_reuse_decision(decision, now=_NOW)
    else:
        assert decision is None


@pytest.mark.parametrize("source", ["local", "signed"])
def test_workspace_rule_without_a_hash_retains_its_explicit_broad_scope(tmp_path: Path, source: str) -> None:
    store = _store_with_workspace_rule(tmp_path, source=source, digest=None)
    for request_hash in (None, "synthetic-other-hash"):
        for consume in (False, True):
            decision = store.resolve_policy_decision(
                "codex",
                "synthetic-artifact",
                artifact_hash=request_hash,
                workspace="synthetic-workspace",
                now=_NOW,
                consume_one_shot=consume,
            )
            assert decision is not None and decision["action"] == "allow"
