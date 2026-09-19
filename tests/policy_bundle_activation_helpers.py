"""Activate signed test policy through the production validation and store boundary."""

from __future__ import annotations

from datetime import datetime

from codex_plugin_scanner.guard.policy_bundle_decisions import build_policy_bundle_decisions
from codex_plugin_scanner.guard.policy_bundle_parser import (
    policy_bundle_acceptance_checkpoint,
    validated_policy_bundle_payload,
)
from codex_plugin_scanner.guard.policy_bundle_trusted_keys import load_policy_bundle_verification_keys
from codex_plugin_scanner.guard.store import GuardStore


def activate_signed_policy_bundle(
    store: GuardStore,
    bundle: dict[str, object],
    *,
    keyring: dict[str, object],
    now: str,
) -> None:
    credentials = store.get_sync_payload("oauth_local_credentials")
    assert isinstance(credentials, dict)
    workspace_id = credentials.get("workspace_id")
    assert isinstance(workspace_id, str)
    verification_keys = load_policy_bundle_verification_keys(keyring)
    validated, reason = validated_policy_bundle_payload(
        bundle,
        trusted_verification_keys=verification_keys,
        anchored_verification_keys=verification_keys,
        expected_workspace_id=workspace_id,
        now=datetime.fromisoformat(now.replace("Z", "+00:00")).timestamp(),
    )
    assert validated is not None, reason
    device = store.get_device_metadata()
    decisions = build_policy_bundle_decisions(
        validated,
        device_id=device["installation_id"],
        device_name=device["device_label"],
    )
    result = store.apply_policy_bundle_authority(
        decisions,
        now,
        policy_bundle=validated,
        policy_bundle_keyring=keyring,
        cloud_exceptions=[],
        policy_bundle_ack={
            "bundleHash": validated["bundleHash"],
            "bundleVersion": validated["bundleVersion"],
            "status": "validated",
        },
        policy_bundle_checkpoint=policy_bundle_acceptance_checkpoint(validated),
        update_last_good=True,
        remote_write_authorized=True,
    )
    assert result is not None
