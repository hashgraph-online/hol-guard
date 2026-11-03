"""Resident bridge for the ``network_protection_verify`` op.

Rust owns whether a signed network protection bundle holds: the canonical
payload hash, the contract version, the workspace it was cut for, freshness,
rollback against the bundle already saved, the keyring the signing key must
anchor to, that key's rotation state, and the RSA-PSS signature. This module
ships the response as it was fetched together with the caller's saved keyring
in its stored wire form, binds the reply by ``request_id`` plus
``request_sha256``, and returns the saved form the resident produced, with the
bundle object this call shipped put back under it. Nothing is re-decided here,
so a resident that cannot answer leaves the bundle unverified rather than
accepted.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from uuid import uuid4

from .native_context import _resolve_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_store_policy import _payload
from .runtime.network_protection_bundle import NetworkProtectionBundleError

NETWORK_PROTECTION_VERIFY_FEATURE = "network-protection-verify-v1"
_REQUEST_SCHEMA = "guard-network-protection-verify-request.v1"
_RESULT_SCHEMA = "guard-network-protection-verify-result.v1"
_TIMEOUT_SECONDS = 15.0
_MAX_REQUEST_BYTES = 6 * 1024 * 1024


class NetworkProtectionBundleUnavailableError(NetworkProtectionBundleError):
    """The verifier could not be reached, so the bundle is not verified.

    A ``NetworkProtectionBundleError``, because every caller already treats a
    failed verification that way and an unreachable verifier must not read as
    a pass. ``reason`` is one of a short fixed set naming which step gave up,
    so an operator reading a failed sync can tell a resident that is missing
    the feature from a request it would not take or a reply it did not bind.
    It never carries the underlying text, which may name local paths.
    """

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"Network protection bundle verification is unavailable ({reason})")


def native_verify_network_protection_response(
    response: Mapping[str, object],
    *,
    workspace_id: str,
    trusted_keys: object = None,
    cached_bundle_version: str | None = None,
    now: float | None = None,
    guard_home: Path | None = None,
) -> dict[str, object]:
    """Return the saved form the resident verified; raise when it did not.

    ``response`` is the bundle response in its wire form, unaltered, because
    the resident recomputes the canonical payload over it. ``trusted_keys`` is
    the saved keyring exactly as it was stored -- a list of keys or the
    ``{"keys": [...]}`` envelope -- which the resident parses itself;
    ``None`` means no keyring has been saved yet.
    """

    home = Path(_resolve_digest_home(guard_home))
    if not ensure_resident_prerequisite(home):
        raise NetworkProtectionBundleUnavailableError("resident_unavailable")
    wire: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"network-protection-verify-{uuid4().hex}",
        "response": dict(response),
        "workspace_id": workspace_id,
        "trusted_keys": trusted_keys,
        "cached_bundle_version": cached_bundle_version,
        "now": now,
    }
    try:
        reply = _resident_request(
            operation="network_protection_verify",
            request=wire,
            guard_home=home,
            timeout_seconds=_TIMEOUT_SECONDS,
            required_feature=NETWORK_PROTECTION_VERIFY_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_REQUEST_BYTES,
            record_success=False,
        )
    except (TypeError, ValueError, OSError, RuntimeError):
        raise NetworkProtectionBundleUnavailableError("request_refused") from None
    answer = _payload(reply, wire, home, failure_reason="native_network_protection_verify_binding")
    if not isinstance(answer, dict):
        raise NetworkProtectionBundleUnavailableError("reply_unbound")
    outcome = answer.get("outcome")
    if outcome == "refused":
        message = answer.get("message")
        raise NetworkProtectionBundleError(
            message if isinstance(message, str) else "Network protection bundle is refused"
        )
    saved = answer.get("saved")
    if outcome != "verified" or not isinstance(saved, dict):
        raise NetworkProtectionBundleUnavailableError("reply_malformed")
    # A bundle response may run to several megabytes, more than a reply may
    # carry, so the resident names the bundle it verified by ``payloadHash``
    # instead of sending it back. The object below is the one this call
    # shipped and the one that hash covers, so putting it back rebuilds the
    # saved form without judging anything.
    return {"bundle": response.get("bundle"), **saved}
