"""Build a policy bundle trust-row view from a fake store's sync payloads."""

from __future__ import annotations

from collections.abc import Callable

from codex_plugin_scanner.guard.store_policy_trust_rows import PolicyBundleTrustRows


def trust_rows_from_payloads(
    get_payload: Callable[[str], object],
    workspace_id: str | None = None,
) -> PolicyBundleTrustRows:
    """The view the native store would return for rows held under their sync keys."""

    return PolicyBundleTrustRows.from_native(
        {
            "policy_bundle": get_payload("policy_bundle"),
            "policy_bundle_keyring": get_payload("policy_bundle_keyring"),
            "acceptance_checkpoint": get_payload("policy_bundle_acceptance_checkpoint"),
            "managed_keyring_provenance": get_payload("managed_policy_bundle_keyring_provenance"),
            "supply_chain_keyring": get_payload("supply_chain_bundle_keyring"),
            "review_verification_keyring": get_payload("guard_review_verification_keyring"),
            "policy_bundle_ack": get_payload("policy_bundle_ack"),
            "sync_summary": get_payload("sync_summary"),
            "policy_bundle_last_error": get_payload("policy_bundle_last_error"),
            "workspace_id": workspace_id,
        }
    )
