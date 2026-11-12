"""Prepares and commits signed custom-Extension continuity in one call for tests.

Production prepares the commit inside the managed-controls sync transaction;
these tests drive the same prepare and store transaction directly.
"""

from __future__ import annotations

from collections.abc import Mapping

from codex_plugin_scanner.guard.runtime import custom_extension_continuity
from codex_plugin_scanner.guard.runtime.custom_extension_continuity import CustomExtensionContinuityError
from codex_plugin_scanner.guard.store import GuardStore


def apply_verified_custom_extension_continuity(
    store: GuardStore,
    validated_policy_bundle: Mapping[str, object],
    *,
    device_id: str | None = None,
    now: str,
) -> dict[str, object]:
    """Consume continuity only after the production caller verified the bundle signature."""

    mutation, state = custom_extension_continuity.prepare_verified_custom_extension_continuity(
        store,
        validated_policy_bundle,
        device_id=device_id,
        now=now,
    )
    if mutation is None:
        return state
    try:
        _ = store.apply_custom_extension_continuity_transaction(
            expected_revision=mutation.expected_revision,
            authority_updates=mutation.authority_updates,
            sync_payloads=mutation.sync_payloads,
            events=mutation.events,
            updated_at=mutation.updated_at,
            sync_preconditions=mutation.sync_preconditions,
            observation_preconditions=mutation.observation_preconditions,
        )
    except ValueError as error:
        raise CustomExtensionContinuityError("local continuity authority changed during apply") from error
    return state
