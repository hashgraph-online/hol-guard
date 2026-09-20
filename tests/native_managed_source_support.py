"""Real signed and locally authorized inputs for native capture regressions."""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from codex_plugin_scanner.guard.approval_gate import update_settings
from codex_plugin_scanner.guard.managed_controls_policy_bundle import (
    parsed_managed_controls_from_validated_policy_bundle,
)
from codex_plugin_scanner.guard.policy_bundle_parser import policy_bundle_acceptance_checkpoint
from codex_plugin_scanner.guard.policy_bundle_trusted_keys import policy_bundle_keyring_payload
from codex_plugin_scanner.guard.runtime.canonical_policy_decisions import build_canonical_policy_bundle_decisions
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.store import GuardStore
from tests.managed_controls_activation_support import CAPABILITIES
from tests.test_canonical_policy_row_authority import _ARTIFACT, _NOW, _activated_store
from tests.test_guard_extension_control_authority import (
    _PASSWORD,
    MemorySecretStore,
    _commit_enabled_permission,
    _enroll,
)
from tests.test_policy_bundle_v2 import _signed_bundle, _verification_key

PERMISSION = "command.git.permission.force-push"


def managed_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    cloud: bool = True,
    lockdown: bool = False,
    targeted: bool = False,
    custom: bool = False,
    scoped: bool = True,
    workspace_id: str = "workspace-alpha",
) -> GuardStore:
    store = _activated_store(tmp_path, action="block", workspace_id=workspace_id)
    store._extension_control_authority_secret_store = MemorySecretStore()
    update_settings(
        store.guard_home,
        {
            "enabled": True,
            "new_password": _PASSWORD,
            "confirm_password": _PASSWORD,
            "cooldown_seconds": 0,
        },
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof._require_local_terminal_confirmation",
        lambda _enrollment: None,
    )
    _enroll(store)
    _commit_enabled_permission(store, PERMISSION, key="synthetic-local-enable")
    if cloud:
        device = store.get_device_metadata()
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        verifier = _verification_key(key, workspace_id=workspace_id)
        rule: dict[str, object] = {
            "id": "synthetic.rule",
            "enabled": True,
            "effect": "block",
            "match": {"harnesses": ["codex"], "artifacts": [_ARTIFACT], "devices": [device["installation_id"]]},
            "lifetime": {"mode": "permanent", "expiresAt": None},
            "provenance": {"source": "cloud", "createdAt": _NOW},
        }
        if targeted:
            rule["x-hol-extension-targets"] = {
                "schemaVersion": "guard.policy-extension-targets.v1",
                "extensionIds": ["command.git"],
                "permissionIds": [PERMISSION],
            }
        payload: dict[str, object] = {
            "apiVersion": "guard.hashgraphonline.com/v1alpha1",
            "kind": "GuardPolicy",
            "metadata": {"id": "synthetic.policy", "name": "Synthetic policy", "revision": 9},
            "spec": {"defaults": {"mode": "enforce", "defaultAction": "warn"}, "rules": [rule] if scoped else []},
            "x-hol-extension-controls": {
                "schemaVersion": "guard.extension-controls.v1",
                "authorityMode": "managed-restrictive",
                **({"globalLockdown": True} if lockdown else {}),
                "controls": [{"targetKind": "permission", "targetId": PERMISSION, "state": "disabled"}],
            },
        }
        if custom:
            payload["x-hol-custom-extension-continuity"] = {"schemaVersion": "unsupported-synthetic.v1"}
        bundle = _signed_bundle(
            key,
            verifier,
            payload_base=payload,
            rollout_state="enforcing",
            bundle_version=9,
            workspace_id=workspace_id,
        )
        parsed = parsed_managed_controls_from_validated_policy_bundle(
            bundle,
            registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
            negotiated_capabilities=CAPABILITIES,
        )
        decisions = build_canonical_policy_bundle_decisions(
            bundle,
            device_id=device["installation_id"],
            device_name=device["device_label"],
        )
        assert (
            store.apply_policy_bundle_authority(
                decisions,
                _NOW,
                policy_bundle=bundle,
                policy_bundle_keyring=policy_bundle_keyring_payload((verifier,), workspace_id=workspace_id),
                cloud_exceptions=[],
                policy_bundle_ack={"bundleHash": bundle["bundleHash"], "status": "validated"},
                policy_bundle_checkpoint=policy_bundle_acceptance_checkpoint(bundle),
                update_last_good=True,
                managed_controls_policy=parsed,
                managed_controls_negotiated_capabilities=CAPABILITIES,
                remote_write_authorized=True,
            )
            is not None
        )
    store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    return store
