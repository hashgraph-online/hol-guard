"""Read a supply-chain bundle response and its canonical payload.

Verifying one, and deciding what it says about a package, belong to the native
runtime: ``guard_command::supply_chain_bundle``. What is left here reads the
wire form onto the transport types the sync path carries and recomputes the
canonical payload bytes, neither of which is a verdict.
"""

from __future__ import annotations

import hashlib
import json
import re

from .supply_chain_bundle_base import (
    SupplyChainBundleMalformedError,
    _require_string,
)
from .supply_chain_bundle_models import SupplyChainBundle, SupplyChainBundleResponse
from .supply_chain_verification_keys import load_supply_chain_verification_keys

_LONE_SURROGATE = re.compile("[\ud800-\udfff]")


def canonical_supply_chain_bundle_payload(bundle: SupplyChainBundle | dict[str, object]) -> bytes:
    """Return the canonical payload used for payloadHash and RSA-PSS signing.

    Keys sort by code point, separators are compact, and non-ASCII text stays UTF-8
    rather than becoming unicode escape sequences, because that is how the signing side
    writes the bytes it signs. A lone surrogate is escaped the way a well-formed JSON
    writer escapes it, so malformed text fails the hash check instead of raising.
    """

    payload = bundle.to_dict() if isinstance(bundle, SupplyChainBundle) else bundle
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return _LONE_SURROGATE.sub(lambda match: f"\\u{ord(match.group()):04x}", text).encode("utf-8")


def payload_hash_for_supply_chain_bundle(bundle: SupplyChainBundle | dict[str, object]) -> str:
    return hashlib.sha256(canonical_supply_chain_bundle_payload(bundle)).hexdigest()


def load_supply_chain_bundle_response(raw_json: str | dict[str, object]) -> SupplyChainBundleResponse:
    """Parse and validate a raw supply-chain bundle response."""

    if isinstance(raw_json, str):
        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError as exc:
            raise SupplyChainBundleMalformedError(f"Bundle JSON is invalid: {exc}") from exc
    else:
        data = raw_json
    if not isinstance(data, dict):
        raise SupplyChainBundleMalformedError("Bundle root must be a JSON object")
    raw_bundle = data.get("bundle")
    if not isinstance(raw_bundle, dict):
        raise SupplyChainBundleMalformedError("Bundle response missing bundle object")
    signature_algorithm = _require_string(data, "signatureAlgorithm")
    if signature_algorithm != "rsa-pss-sha256":
        raise SupplyChainBundleMalformedError("Unsupported bundle signature algorithm")
    verification_keys = load_supply_chain_verification_keys(data.get("verificationKeys"))
    if not verification_keys:
        raise SupplyChainBundleMalformedError("Bundle response must include verification keys")
    return SupplyChainBundleResponse(
        bundle=SupplyChainBundle.from_dict(raw_bundle),
        signed_bundle=raw_bundle,
        payload_hash=_require_string(data, "payloadHash"),
        signature=_require_string(data, "signature"),
        signature_algorithm=signature_algorithm,
        verification_keys=verification_keys,
    )
