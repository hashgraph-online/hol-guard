"""HOL Guard supply-chain bundle errors and keyring loading.

Reading and verifying a bundle belong to the native runtime
(``guard_command::supply_chain_bundle``); what is left here is the error
family callers already distinguish and the saved keyring's wire form.
"""

from __future__ import annotations

from .supply_chain_bundle_base import (
    SupplyChainBundleError,
    SupplyChainBundleExpiredError,
    SupplyChainBundleKeyringError,
    SupplyChainBundleMalformedError,
    SupplyChainBundlePayloadHashError,
    SupplyChainBundleRollbackError,
    SupplyChainBundleSignatureError,
)
from .supply_chain_verification_keys import SupplyChainVerificationKey, load_supply_chain_verification_keys

__all__ = [
    "SupplyChainBundleError",
    "SupplyChainBundleExpiredError",
    "SupplyChainBundleKeyringError",
    "SupplyChainBundleMalformedError",
    "SupplyChainBundlePayloadHashError",
    "SupplyChainBundleRollbackError",
    "SupplyChainBundleSignatureError",
    "SupplyChainVerificationKey",
    "load_supply_chain_verification_keys",
]
