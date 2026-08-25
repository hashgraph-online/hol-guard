from __future__ import annotations

import copy
import json
from collections.abc import Callable, Sequence
from pathlib import Path

from codex_plugin_scanner.guard.managed_controls_policy_bundle import (
    parsed_managed_controls_from_validated_policy_bundle,
)
from codex_plugin_scanner.guard.managed_controls_policy_fields import (
    EXTENSION_CONTROL_LAYER_CAPABILITY,
    MANAGED_CONTROLS_ATOMIC_APPLY_CAPABILITY,
    POLICY_EXTENSION_TARGETS_CAPABILITY,
)
from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.policy_bundle_parser import policy_bundle_acceptance_checkpoint
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.store import GuardStore

_ROOT = Path(__file__).resolve().parents[1]
_VECTOR = json.loads(
    (_ROOT / "contracts/managed-controls/v1/policy-bundle-v2-extension-signature-vector.json").read_text()
)
CAPABILITIES = frozenset(
    {
        EXTENSION_CONTROL_LAYER_CAPABILITY,
        POLICY_EXTENSION_TARGETS_CAPABILITY,
        MANAGED_CONTROLS_ATOMIC_APPLY_CAPABILITY,
    }
)


def managed_bundle() -> dict[str, object]:
    return copy.deepcopy(_VECTOR["bundle"])


def parse_managed_bundle(bundle: dict[str, object]):
    return parsed_managed_controls_from_validated_policy_bundle(
        bundle,
        registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        negotiated_capabilities=CAPABILITIES,
    )


def activate_managed_bundle(
    store: GuardStore,
    bundle: dict[str, object],
    *,
    decisions: Sequence[PolicyDecision] = (),
    managed_controls_publish: (Callable[[ExtensionControlAuthorityView, Callable[[], None]], object] | None) = None,
) -> bool:
    base = store.read_extension_control_authority(catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest)
    if base.health is AuthorityHealth.UNENROLLED:
        store._bootstrap_extension_control_authority(  # pyright: ignore[reportPrivateUsage]
            BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
            key=None,
        )
    parsed = parse_managed_bundle(bundle)
    result = store.apply_policy_bundle_authority(
        list(decisions),
        "2026-08-23T12:00:00Z",
        policy_bundle=bundle,
        policy_bundle_keyring={"keys": []},
        cloud_exceptions=[],
        policy_bundle_ack={"bundleHash": bundle["bundleHash"], "status": "applied"},
        policy_bundle_checkpoint=policy_bundle_acceptance_checkpoint(bundle),
        update_last_good=True,
        managed_controls_policy=parsed,
        managed_controls_negotiated_capabilities=CAPABILITIES,
        managed_controls_publish=managed_controls_publish,
        remote_write_authorized=True,
    )
    return result is not None
