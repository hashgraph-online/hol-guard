"""Resident bridge for the ``supply_chain_bundle_verify`` op.

Rust owns whether a signed supply-chain bundle holds: the canonical payload
hash, rollback against the version already cached, freshness, the keyring the
signing key must anchor to, that key's rotation state, and the RSA-PSS
signature. This module ships the response as it was fetched or cached together
with the caller's trusted keyring, binds the reply by ``request_id`` plus
``request_sha256`` and re-raises the refusal class the resident named. Nothing
is re-decided here, so a resident that cannot answer leaves the bundle
unverified rather than accepted.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4

from .native_context import _resolve_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_store_policy import _payload
from .runtime.supply_chain_bundle_base import (
    SupplyChainBundleError,
    SupplyChainBundleExpiredError,
    SupplyChainBundleKeyringError,
    SupplyChainBundleMalformedError,
    SupplyChainBundlePayloadHashError,
    SupplyChainBundleRollbackError,
    SupplyChainBundleSignatureError,
)
from .runtime.supply_chain_verification_keys import SupplyChainVerificationKey, load_supply_chain_verification_keys

SUPPLY_CHAIN_BUNDLE_VERIFY_FEATURE = "supply-chain-bundle-verify-v1"
_REQUEST_SCHEMA = "guard-supply-chain-bundle-verify-request.v1"
_RESULT_SCHEMA = "guard-supply-chain-bundle-verify-result.v1"
_TIMEOUT_SECONDS = 15.0
_MAX_REQUEST_BYTES = 6 * 1024 * 1024
# What the envelope costs beyond the response itself: the saved keyring, the
# request id, the cached version and the clock. Generous, so a response that
# fits this budget still fits the request the resident will read.
_ENVELOPE_ALLOWANCE_BYTES = 64 * 1024
#: The largest bundle response that can reach the verifier. A fetch that stops
#: at this size fails where the caller can say why, rather than producing a
#: response no verifier in the product can be asked about.
MAX_SUPPLY_CHAIN_BUNDLE_RESPONSE_BYTES = _MAX_REQUEST_BYTES - _ENVELOPE_ALLOWANCE_BYTES

_REFUSAL_CLASSES: dict[str, type[SupplyChainBundleError]] = {
    "signature": SupplyChainBundleSignatureError,
    "expired": SupplyChainBundleExpiredError,
    "rollback": SupplyChainBundleRollbackError,
    "malformed": SupplyChainBundleMalformedError,
    "payload_hash": SupplyChainBundlePayloadHashError,
    "keyring": SupplyChainBundleKeyringError,
}


@dataclass(frozen=True, slots=True)
class VerifiedSupplyChainBundle:
    """A bundle response the resident verified, in the forms the sync path saves.

    ``response`` is the wire form the cache keeps and later re-verifies;
    ``verification_keys`` is the keyring it advertised; ``summary`` is the
    resident's reading of the bundle: version, key, policy hash, tier, feed
    snapshot hash and the advisory and package counts.
    """

    response: dict[str, object]
    verification_keys: tuple[SupplyChainVerificationKey, ...]
    summary: dict[str, object]


class SupplyChainBundleUnavailableError(SupplyChainBundleError):
    """The verifier could not be reached, so the bundle is not verified.

    A ``SupplyChainBundleError``, because every caller already treats a failed
    verification that way and an unreachable verifier must not read as a pass.
    """

    def __init__(self) -> None:
        super().__init__("Supply-chain bundle verification is unavailable")


class SupplyChainBundleTooLargeError(SupplyChainBundleError):
    """The bundle is larger than the verifier can be asked about.

    Distinct from an unavailable verifier, which is a resident that cannot be
    reached. Here the resident is reachable and the request itself is the
    problem, so the message names both sizes: an operator reading a failed sync
    can tell a bundle that has outgrown the transport from a runtime that is
    missing or wedged, and the fix is a partitioned sync, not a reinstall.
    """

    def __init__(self, size_bytes: int, limit_bytes: int) -> None:
        super().__init__(
            f"Supply-chain bundle verification request is {size_bytes} bytes, "
            f"over the {limit_bytes}-byte limit the native runtime accepts"
        )


def native_verify_supply_chain_bundle_response(
    response: Mapping[str, object],
    *,
    trusted_keys: Sequence[Mapping[str, object]] | None = None,
    cached_bundle_version: str | None = None,
    now: float | None = None,
    guard_home: Path | None = None,
    store: Any | None = None,
) -> VerifiedSupplyChainBundle:
    """Return the bundle the resident verified; raise when it did not.

    ``response`` is the bundle response in its wire form, unaltered, because
    the resident recomputes the canonical payload over it. ``trusted_keys``
    carries the saved keyring in the same wire form; ``None`` accepts the
    keyring the response advertises, which only a caller that has not saved
    one yet should send. An empty keyring is not that case and the resident
    refuses it.

    ``store`` is the already-open store the caller is verifying for. The
    resident's prerequisite key is derived from the policy-integrity master,
    so provisioning it has to read the caller's own secret store rather than
    whatever a freshly opened default store resolves.
    """

    home = Path(_resolve_digest_home(guard_home))
    if not ensure_resident_prerequisite(home, store=store):
        raise SupplyChainBundleUnavailableError
    wire: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"supply-chain-bundle-verify-{uuid4().hex}",
        "response": dict(response),
        "trusted_keys": [dict(key) for key in trusted_keys] if trusted_keys is not None else None,
        "cached_bundle_version": cached_bundle_version,
        "now": now,
    }
    # The transport drops an oversized request without saying so, which reads
    # as an unreachable verifier and leaves the workspace on a stale bundle
    # with nothing to act on. Measure it here instead and name the size. The
    # bytes measured are the bytes the transport sends: the same envelope, the
    # same separators. A compact encoding of the request alone is smaller than
    # what goes over the wire, so a bundle that passed it could still be
    # dropped and reported as an unreachable verifier.
    envelope = {
        "operation": "supply_chain_bundle_verify",
        "request": wire,
        "deadline_budget_ms": max(1, int(_TIMEOUT_SECONDS * 1000)),
    }
    try:
        encoded_bytes = len(json.dumps(envelope).encode("utf-8"))
    except (TypeError, ValueError):
        raise SupplyChainBundleUnavailableError from None
    if encoded_bytes > _MAX_REQUEST_BYTES:
        raise SupplyChainBundleTooLargeError(encoded_bytes, _MAX_REQUEST_BYTES)
    try:
        reply = _resident_request(
            operation="supply_chain_bundle_verify",
            request=wire,
            guard_home=home,
            timeout_seconds=_TIMEOUT_SECONDS,
            required_feature=SUPPLY_CHAIN_BUNDLE_VERIFY_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_REQUEST_BYTES,
            record_success=False,
        )
    except (TypeError, ValueError, OSError, RuntimeError):
        raise SupplyChainBundleUnavailableError from None
    answer = _payload(reply, wire, home)
    if not isinstance(answer, dict):
        raise SupplyChainBundleUnavailableError
    outcome = answer.get("outcome")
    if outcome == "refused":
        kind = answer.get("kind")
        message = answer.get("message")
        error_class = _REFUSAL_CLASSES.get(kind if isinstance(kind, str) else "", SupplyChainBundleError)
        raise error_class(message if isinstance(message, str) else "Supply-chain bundle is refused")
    if outcome != "verified":
        raise SupplyChainBundleUnavailableError
    return _verified(response, answer.get("summary"))


def _verified(response: Mapping[str, object], summary: object) -> VerifiedSupplyChainBundle:
    keys = tuple(load_supply_chain_verification_keys(response.get("verificationKeys")))
    cached = {name: response.get(name) for name in ("bundle", "payloadHash", "signature", "signatureAlgorithm")}
    cached["verificationKeys"] = [key.to_dict() for key in keys]
    if not isinstance(summary, dict):
        raise SupplyChainBundleUnavailableError
    return VerifiedSupplyChainBundle(response=cached, verification_keys=keys, summary=summary)
