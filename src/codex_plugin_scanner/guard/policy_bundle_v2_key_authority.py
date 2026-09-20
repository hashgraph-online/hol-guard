"""Resolve V2 signing authority without trusting advertised validity metadata."""

from __future__ import annotations

from .policy_bundle_trusted_keys import (
    POLICY_BUNDLE_KEY_PURPOSE,
    PolicyBundleVerificationKey,
    resolve_policy_bundle_signing_key,
    signing_key_is_current,
    signing_key_is_trusted,
)


def authorized_v2_signing_key(
    key_id: str,
    *,
    trusted_keys: tuple[PolicyBundleVerificationKey, ...],
    anchored_keys: tuple[PolicyBundleVerificationKey, ...],
    workspace_id: object,
    now: float | None,
) -> PolicyBundleVerificationKey | None:
    """Keep V2 overlap compatibility, but take lifetime and state from its anchor."""

    advertised = resolve_policy_bundle_signing_key(key_id, trusted_keys)
    anchor = resolve_policy_bundle_signing_key(key_id, anchored_keys)
    if advertised is None or anchor is None or not signing_key_is_trusted(advertised, (anchor,)):
        return None
    if anchor.purpose != POLICY_BUNDLE_KEY_PURPOSE:
        return None
    if anchor.workspace_id is not None and anchor.workspace_id != workspace_id:
        return None
    if not signing_key_is_current(anchor, now=now):
        return None
    return anchor
