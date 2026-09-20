"""Signed command-only source fixtures for complete publisher verification."""

from __future__ import annotations

from collections.abc import Callable

from cryptography.hazmat.primitives.asymmetric import rsa

from codex_plugin_scanner.guard.managed_controls_policy_bundle import (
    parsed_managed_controls_from_validated_policy_bundle,
)
from codex_plugin_scanner.guard.policy_bundle_parser import policy_bundle_acceptance_checkpoint
from codex_plugin_scanner.guard.policy_bundle_trusted_keys import policy_bundle_keyring_payload
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import ExtensionControlAuthorityView
from codex_plugin_scanner.guard.store import GuardStore
from tests.managed_controls_activation_support import CAPABILITIES
from tests.test_canonical_policy_row_authority import _NOW
from tests.test_policy_bundle_v2 import _signed_bundle, _verification_key


def activate_signed_command_controls(
    store: GuardStore,
    *,
    revision: int = 9,
    managed_controls_publish: Callable[[ExtensionControlAuthorityView, Callable[[], None]], object] | None = None,
) -> bool:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verifier = _verification_key(private_key, workspace_id="workspace-alpha")
    payload: dict[str, object] = {
        "apiVersion": "guard.hashgraphonline.com/v1alpha1",
        "kind": "GuardPolicy",
        "metadata": {"id": "synthetic.controls", "name": "Synthetic controls", "revision": revision},
        "spec": {"defaults": {"mode": "enforce", "defaultAction": "warn"}, "rules": []},
        "x-hol-extension-controls": {
            "schemaVersion": "guard.extension-controls.v1",
            "authorityMode": "managed-restrictive",
            "controls": [
                {"targetKind": "permission", "targetId": "command.git.permission.force-push", "state": "disabled"}
            ],
        },
    }
    bundle = _signed_bundle(
        private_key, verifier, payload_base=payload, rollout_state="enforcing", bundle_version=revision
    )
    parsed = parsed_managed_controls_from_validated_policy_bundle(
        bundle, registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY, negotiated_capabilities=CAPABILITIES
    )
    store.set_sync_payload("oauth_local_credentials", {"workspace_id": "workspace-alpha"}, _NOW)
    return (
        store.apply_policy_bundle_authority(
            [],
            _NOW,
            policy_bundle=bundle,
            policy_bundle_keyring=policy_bundle_keyring_payload((verifier,), workspace_id="workspace-alpha"),
            cloud_exceptions=[],
            policy_bundle_ack={"bundleHash": bundle["bundleHash"], "status": "validated"},
            policy_bundle_checkpoint=policy_bundle_acceptance_checkpoint(bundle),
            update_last_good=True,
            managed_controls_policy=parsed,
            managed_controls_negotiated_capabilities=CAPABILITIES,
            managed_controls_publish=managed_controls_publish,
            remote_write_authorized=True,
        )
        is not None
    )
