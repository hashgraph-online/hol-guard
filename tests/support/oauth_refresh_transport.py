"""The urllib OAuth refresh exchange the Python runner sent before the native one.

The native ``cloud-event-sync`` command's ``oauth_refresh`` action now signs and
sends the refresh-token exchange (``rust/crates/guard-runtime/src/cloud_oauth_refresh.rs``).
Unit tests that check what the runner does with each outcome still fake
``urllib``; this copy turns the faked answer into the outcome the native action
reports. Production code never imports it.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping

from codex_plugin_scanner.guard.cli.oauth_client import GuardDpopKeyMaterial
from codex_plugin_scanner.guard.mdm import network
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.runtime.sync_retry_delay import parse_retry_after_header

_TIMEOUT_SECONDS = 20
_MAX_NONCE_RETRIES = 3


def _invalid_grant(payload: object) -> bool:
    if not isinstance(payload, dict):
        return False
    code = payload.get("error")
    description = payload.get("error_description")
    return code == "invalid_grant" or (
        isinstance(description, str) and "missing, expired, or already consumed" in description.lower()
    )


def _error_body(error: urllib.error.HTTPError) -> str:
    try:
        return error.read().decode("utf-8")
    except OSError:
        return ""


def _error_reason(error: urllib.error.HTTPError, raw_body: str) -> str:
    try:
        payload = json.loads(raw_body) if raw_body else None
    except json.JSONDecodeError:
        payload = None
    if isinstance(payload, dict):
        for field in ("error_description", "error"):
            value = payload.get(field)
            if isinstance(value, str) and value.strip():
                return value
    if raw_body.strip():
        return raw_body.strip()
    return f"HTTP Error {error.code}: {error.reason}"


def _key(call: Mapping[str, object]) -> GuardDpopKeyMaterial:
    key = call["dpopKey"]
    assert isinstance(key, dict)
    return GuardDpopKeyMaterial(
        algorithm=str(key["algorithm"]),
        private_key_pem=str(key["privateKeyPem"]),
        public_jwk=dict(key["publicJwk"]),
        public_jwk_thumbprint="",
    )


def cloud_oauth_refresh_over_urllib(call: Mapping[str, object]) -> dict[str, object]:
    """Send one refresh exchange through the urllib a test fakes."""

    token_endpoint = str(call["tokenEndpoint"])
    body = urllib.parse.urlencode(
        {"grant_type": "refresh_token", "client_id": call["clientId"], "refresh_token": call["refreshToken"]}
    ).encode("utf-8")
    key = _key(call)
    nonce: str | None = None
    nonce_retries = 0
    while True:
        try:
            proof = runner._sign_guard_dpop_proof(
                request_url=token_endpoint, method="POST", dpop_key_material=key, nonce=nonce
            )
        except runner.GuardSyncNotAvailableError:
            raise
        except (RuntimeError, TypeError, ValueError) as error:
            return {"outcome": "unusable", "reason": str(error)}
        request = urllib.request.Request(
            token_endpoint,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "User-Agent": runner._GUARD_SYNC_USER_AGENT,
                "DPoP": proof,
            },
        )
        try:
            with network.managed_urlopen(request, timeout=_TIMEOUT_SECONDS) as response:
                raw = response.read()
        except urllib.error.HTTPError as error:
            raw_body = _error_body(error)
            try:
                payload = json.loads(raw_body) if raw_body else None
            except json.JSONDecodeError:
                payload = None
            challenge = runner._dpop_nonce_from_http_error(error, payload)
            if challenge is not None and challenge != nonce and nonce_retries < _MAX_NONCE_RETRIES:
                nonce = challenge
                nonce_retries += 1
                continue
            if error.code == 429:
                return {
                    "outcome": "rate_limited",
                    "retryAfterSeconds": min(parse_retry_after_header(error), 120),
                    "retryAfter": error.headers.get("Retry-After") if error.headers else None,
                }
            if error.code in {400, 401, 403}:
                if _invalid_grant(payload):
                    return {"outcome": "dead_grant"}
                return {"outcome": "rejected", "reason": _error_reason(error, raw_body)}
            if error.code in {502, 503, 504}:
                return {"outcome": "unreachable", "reason": _error_reason(error, raw_body)}
            return {"outcome": "failed", "reason": _error_reason(error, raw_body)}
        except OSError as error:
            if runner._is_guard_cloud_unreachable_error(error):
                return {"outcome": "unreachable", "reason": str(error)}
            return {"outcome": "failed", "reason": runner._sync_url_error_message(error)}
        try:
            payload = json.loads(raw.decode("utf-8"))
        except ValueError:
            return {"outcome": "unusable", "reason": "Guard Cloud token refresh returned a non-JSON response."}
        if not isinstance(payload, dict):
            return {"outcome": "unusable", "reason": "Guard Cloud token refresh returned an unusable token."}
        return {"outcome": "refreshed", "payload": payload}
