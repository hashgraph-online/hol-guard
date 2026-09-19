"""Consecutive signed publications retain exact source and recency binding."""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from codex_plugin_scanner.guard.policy_bundle_decisions import build_policy_bundle_decisions
from codex_plugin_scanner.guard.policy_bundle_materialization import POLICY_BUNDLE_MATERIALIZATION_KEY
from codex_plugin_scanner.guard.policy_bundle_parser import policy_bundle_acceptance_checkpoint
from codex_plugin_scanner.guard.policy_bundle_trusted_keys import policy_bundle_keyring_payload
from codex_plugin_scanner.guard.runtime.canonical_policy_decisions import build_canonical_policy_bundle_decisions
from codex_plugin_scanner.guard.store import GuardStore
from tests.policy_bundle_signing_helpers import policy_bundle_test_keyring, sign_policy_bundle
from tests.test_policy_bundle_trust_regressions import _unsigned_policy_bundle
from tests.test_policy_bundle_v2 import _signed_bundle, _verification_key


def _publications(version: int) -> tuple[list[dict[str, object]], dict[str, object]]:
    if version == 1:
        bundles = []
        for revision in (8, 9):
            unsigned = _unsigned_policy_bundle(bundle_version=f"{revision}.0.0")
            unsigned["rules"] = [
                {
                    "ruleId": "synthetic-rule",
                    "action": "block",
                    "reason": "Synthetic rule",
                    "artifactType": "package_request",
                    "matcherFamilies": ["package-request"],
                    "scope": {"harnesses": ["codex"]},
                }
            ]
            bundles.append(sign_policy_bundle(unsigned))
        return bundles, policy_bundle_test_keyring()
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key = _verification_key(private_key, workspace_id="workspace-alpha")
    payload: dict[str, object] = {
        "apiVersion": "guard.hashgraphonline.com/v1alpha1",
        "kind": "GuardPolicy",
        "metadata": {"id": "synthetic.policy", "name": "Synthetic policy", "revision": 8},
        "spec": {
            "defaults": {"mode": "enforce", "defaultAction": "warn"},
            "rules": [
                {
                    "id": "synthetic.rule",
                    "enabled": True,
                    "effect": "block",
                    "match": {"harnesses": ["codex"], "artifacts": ["synthetic-artifact"]},
                    "lifetime": {"mode": "permanent", "expiresAt": None},
                    "provenance": {"source": "cloud", "createdAt": "2026-07-18T00:00:00Z"},
                }
            ],
        },
    }
    bundles = [
        _signed_bundle(private_key, key, bundle_version=revision, payload_base=payload, rollout_state="enforcing")
        for revision in (8, 9)
    ]
    assert bundles[0]["payloadHash"] == bundles[1]["payloadHash"]
    return bundles, policy_bundle_keyring_payload((key,), workspace_id="workspace-alpha")


@pytest.mark.parametrize("version", [1, 2])
@pytest.mark.parametrize("tampered_previous", [False, True])
def test_consecutive_signed_publications_rebind_only_from_authenticated_previous_state(
    tmp_path: Path, version: int, tampered_previous: bool
) -> None:
    bundles, keyring = _publications(version)
    assert bundles[0]["bundleHash"] != bundles[1]["bundleHash"]
    assert type(bundles[0]["bundleVersion"]) is (str if version == 1 else int)
    store = GuardStore(tmp_path / "guard-home")
    device = store.get_device_metadata()
    store.set_sync_payload(
        "oauth_local_credentials", {"workspace_id": bundles[0]["workspaceId"]}, "2026-09-17T00:00:00Z"
    )
    compiler = build_policy_bundle_decisions if version == 1 else build_canonical_policy_bundle_decisions
    previous_record = None
    previous_rows = None
    for index, bundle in enumerate(bundles):
        now = f"2026-09-17T00:0{index}:00Z"
        decisions = compiler(bundle, device_id=device["installation_id"], device_name=device["device_label"])
        assert decisions
        result = store.apply_policy_bundle_authority(
            decisions,
            now,
            policy_bundle=bundle,
            policy_bundle_keyring=keyring,
            cloud_exceptions=[],
            policy_bundle_ack={
                "bundleHash": bundle["bundleHash"],
                "bundleVersion": bundle["bundleVersion"],
                "status": "validated",
            },
            policy_bundle_checkpoint=policy_bundle_acceptance_checkpoint(bundle),
            update_last_good=True,
            remote_write_authorized=True,
        )
        if index == 1 and tampered_previous:
            assert result is None
            assert store.list_policy_decisions() == previous_rows
            assert store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY) == previous_record
            assert store.get_sync_payload("policy_bundle") == bundles[0]
            continue
        assert result is not None
        record = store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY)
        assert isinstance(record, dict)
        assert record["bundleHash"] == bundle["bundleHash"]
        assert record["bundleVersion"] == bundle["bundleVersion"]
        assert record["materializedAt"] == f"2026-09-17T00:0{index}:00.000000+00:00"
        if index == 0:
            if tampered_previous:
                record["materializedAt"] = "2026-09-17T00:00:30.000000+00:00"
                store.set_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY, record, now)
            previous_record = record
            previous_rows = store.list_policy_decisions()
        else:
            assert record != previous_record
