"""Validity windows for an already resolved policy signing key."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from .policy_bundle_validity import comparison_unix_seconds
from .runtime.supply_chain_bundle_base import SupplyChainBundleMalformedError, _parse_iso_timestamp

if TYPE_CHECKING:
    from .policy_bundle_trusted_keys import PolicyBundleVerificationKey


def signing_key_is_current(
    signing_key: PolicyBundleVerificationKey,
    *,
    now: float | None = None,
    require_active: bool = False,
) -> bool:
    if signing_key.state == "revoked" or (require_active and signing_key.state != "active"):
        return False
    current_time = comparison_unix_seconds(now, default=time.time())
    if signing_key.valid_from is not None:
        try:
            valid_from = _parse_iso_timestamp(signing_key.valid_from, field_name="validFrom")
        except (SupplyChainBundleMalformedError, TypeError, ValueError):
            return False
        if current_time < valid_from:
            return False
    if signing_key.valid_until is None:
        return True
    try:
        expiry = _parse_iso_timestamp(signing_key.valid_until, field_name="validUntil")
    except (SupplyChainBundleMalformedError, TypeError, ValueError):
        return False
    return current_time <= expiry
