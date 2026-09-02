"""Focused rejection checks for atomic policy-bundle activation."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Mapping, Sequence

from .policy_bundle_parser import policy_bundle_acceptance_checkpoint, policy_bundle_is_version_downgrade
from .store_custom_extension_continuity import (
    CustomExtensionContinuityMutation,
    apply_custom_extension_continuity_mutation_locked,
)


def encoded_policy_activation_payloads(
    policy_bundle: Mapping[str, object],
    policy_bundle_keyring: Mapping[str, object],
    cloud_exceptions: Sequence[Mapping[str, object]],
    policy_bundle_ack: Mapping[str, object],
    policy_bundle_checkpoint: Mapping[str, object],
    policy_bundle_last_error: Mapping[str, object] | None,
    *,
    update_last_good: bool,
) -> tuple[str | None, dict[str, str]]:
    """Validate and encode bundle state before entering the write transaction."""

    normalized_checkpoint = policy_bundle_acceptance_checkpoint(dict(policy_bundle))
    if dict(policy_bundle_checkpoint) != normalized_checkpoint:
        return "policy_bundle_checkpoint_mismatch", {}
    state_payloads: dict[str, object] = {
        "cloud_exceptions": [dict(item) for item in cloud_exceptions],
        "policy": {},
        "policy_bundle": dict(policy_bundle),
        "policy_bundle_ack": dict(policy_bundle_ack),
        "policy_bundle_acceptance_checkpoint": normalized_checkpoint,
        "policy_bundle_keyring": dict(policy_bundle_keyring),
        "policy_bundle_last_error": dict(policy_bundle_last_error or {}),
        "team_policy_pack": {},
    }
    if update_last_good:
        state_payloads["policy_bundle_last_good"] = dict(policy_bundle)
    return None, {state_key: json.dumps(payload, allow_nan=False) for state_key, payload in state_payloads.items()}


def continuity_activation_rejection(
    mutation: CustomExtensionContinuityMutation | None,
    *,
    protected_authority: bool,
    negotiated_capabilities: frozenset[str],
) -> str | None:
    """Return the v2 prerequisite rejection without changing state."""

    if mutation is None:
        return None
    if mutation.requires_protected_extension_authority and not protected_authority:
        return "custom_extension_continuity_authority_unprotected"
    required = mutation.required_negotiated_capability
    if required is not None and required not in negotiated_capabilities:
        return "custom_extension_continuity_capability_not_negotiated"
    return None


def policy_checkpoint_rejection(
    connection: sqlite3.Connection,
    policy_bundle: Mapping[str, object],
) -> str | None:
    """Validate the persisted anti-downgrade checkpoint under the write lock."""

    row = connection.execute(
        "select payload_json from sync_state where state_key = ?",
        ("policy_bundle_acceptance_checkpoint",),
    ).fetchone()
    if row is None:
        return None
    try:
        existing = json.loads(str(row["payload_json"]))
    except json.JSONDecodeError:
        return "policy_bundle_checkpoint_invalid"
    if not isinstance(existing, dict) or not existing:
        return "policy_bundle_checkpoint_invalid"
    if policy_bundle_is_version_downgrade(existing, dict(policy_bundle)):
        return "bundle_version_downgrade"
    return None


def apply_continuity_rejection(
    connection: sqlite3.Connection,
    mutation: CustomExtensionContinuityMutation | None,
    *,
    boundary: Callable[[str], None],
) -> str | None:
    """Apply continuity inside the caller transaction or return its rejection."""

    if mutation is None:
        return None
    try:
        _ = apply_custom_extension_continuity_mutation_locked(connection, mutation, boundary=boundary)
    except ValueError:
        return "custom_extension_continuity_changed_during_activation"
    return None
