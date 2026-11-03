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

import hashlib
import json
import os
import tempfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

from .native_context import _resolve_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_runtime import native_runtime_status
from .native_store_policy import _payload
from .runtime.network_protection_bundle import NetworkProtectionBundleError

NETWORK_PROTECTION_VERIFY_FEATURE = "network-protection-verify-v1"
# A request frame caps every JSON array at 4,096 items and a real bundle's
# threat feeds run far past that, so a runtime advertising this takes the
# response as text instead.
NETWORK_PROTECTION_VERIFY_RESPONSE_JSON_FEATURE = "network-protection-verify-response-json-v1"
# The frame also bounds every string at 4 MiB, and a production bundle's text
# sits close to that, so a runtime advertising this reads the response from a
# private file the request names by path and digest.
NETWORK_PROTECTION_VERIFY_RESPONSE_FILE_FEATURE = "network-protection-verify-response-file-v1"
_REQUEST_SCHEMA = "guard-network-protection-verify-request.v1"
_RESULT_SCHEMA = "guard-network-protection-verify-result.v1"
_TIMEOUT_SECONDS = 15.0
_MAX_REQUEST_BYTES = 6 * 1024 * 1024
# The frame parser bounds every string at 4 MiB of decoded text, the response
# text included.
_MAX_RESPONSE_JSON_BYTES = 4 * 1024 * 1024


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
    status = native_runtime_status()
    features = set(status.capabilities.features) if status.capabilities is not None else set()
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
        with _response_carrier(wire, response, features, home):
            reply = _resident_request(
                operation="network_protection_verify",
                request=wire,
                guard_home=home,
                timeout_seconds=_TIMEOUT_SECONDS,
                required_feature=NETWORK_PROTECTION_VERIFY_FEATURE,
                response_schema=_RESULT_SCHEMA,
                max_request_bytes=_MAX_REQUEST_BYTES,
                record_success=False,
                status=status,
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


@contextmanager
def _response_carrier(
    wire: dict[str, object],
    response: Mapping[str, object],
    features: set[str],
    home: Path,
) -> Iterator[None]:
    """Move the response into the widest form the runtime takes.

    A file when the runtime reads one, removed once the reply is in; text when
    it only takes text; otherwise the value as it stands. The file is written
    privately inside the Guard home and named together with the digest of its
    bytes, so the request hash the reply is bound to covers what the resident
    read.
    """

    if NETWORK_PROTECTION_VERIFY_RESPONSE_FILE_FEATURE in features:
        data = _compact(response).encode("utf-8")
        descriptor, name = tempfile.mkstemp(dir=home, prefix=".network-protection-response-", suffix=".json")
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data)
            wire["response"] = None
            wire["response_path"] = name
            wire["response_sha256"] = f"sha256:{hashlib.sha256(data).hexdigest()}"
            yield
        finally:
            Path(name).unlink(missing_ok=True)
        return
    if NETWORK_PROTECTION_VERIFY_RESPONSE_JSON_FEATURE in features:
        text = _compact(response)
        if len(text.encode("utf-8")) > _MAX_RESPONSE_JSON_BYTES:
            raise NetworkProtectionBundleUnavailableError("response_too_large")
        wire["response"] = None
        wire["response_json"] = text
    yield


def _compact(response: Mapping[str, object]) -> str:
    return json.dumps(dict(response), separators=(",", ":"), ensure_ascii=False, allow_nan=False)
