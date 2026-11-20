"""Bounded unverified OAuth claim extraction for locally authenticated tokens.

Python only decodes the token's payload segment. The native
``oauth_token_claims`` authority kind reads the identity, binding and expiry
from the decoded claims, so the access token itself never reaches the resident.
"""

from __future__ import annotations

import json
from base64 import urlsafe_b64decode
from datetime import datetime

from .native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

_BINDING_KEYS = ("device_id", "grant_id", "machine_id", "workspace_id")


def decode_oauth_access_token_claims(access_token: str) -> dict[str, object]:
    parts = access_token.split(".")
    if len(parts) != 3:
        return {}
    try:
        padding = "=" * (-len(parts[1]) % 4)
        payload = json.loads(urlsafe_b64decode(parts[1] + padding).decode("utf-8"))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def oauth_claim_string(claims: dict[str, object], *path: str) -> str | None:
    current: object = claims
    for segment in path:
        if not isinstance(current, dict):
            return None
        current = current.get(segment)
    return current.strip() if isinstance(current, str) and current.strip() else None


def _claims(access_token: str | None) -> dict[str, object] | None:
    claims = decode_oauth_access_token_claims(access_token) if access_token else {}
    return claims or None


def _native(op: str, **args: object) -> dict[str, object] | None:
    try:
        answer = native_runner_authority("oauth_token_claims", {"op": op, **args})
    except NativeRunnerAuthorityError:
        return None
    return answer if isinstance(answer, dict) else None


def _strings(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(key): item for key, item in value.items() if isinstance(item, str)}


def oauth_token_identity(access_token: str) -> dict[str, str | None]:
    """The grant, machine, workspace and device claims, each ``None`` when absent.

    Raises ``NativeRunnerAuthorityError`` when the runtime cannot answer, so a
    token exchange never saves a credential row whose binding was never read.
    """

    answer = native_runner_authority("oauth_token_claims", {"op": "identity", "claims": _claims(access_token)})
    identity = _strings(answer.get("identity") if isinstance(answer, dict) else None)
    return {key: identity.get(key) for key in ("grant_id", "machine_id", "workspace_id", "device_id")}


def oauth_binding_metadata(access_token: str, *, issuer: str | None = None) -> dict[str, str]:
    """The token's binding, or ``{}`` when it has none or the runtime cannot answer.

    Callers use this to recover a credential row whose metadata is missing.
    Recovering the row without its binding keeps the refresh token usable, and
    the next sync recovers the binding again through
    ``oauth_binding_from_credentials`` once the runtime answers.
    """

    answer = _native("binding", claims=_claims(access_token), issuer=issuer) or {}
    return _strings(answer.get("binding"))


def oauth_binding_from_credentials(credentials: dict[str, object]) -> dict[str, str]:
    """The saved token's binding when it agrees with every saved field."""

    answer = _native(
        "credential_binding",
        claims=_claims(_text(credentials.get("access_token"))),
        issuer=_text(credentials.get("issuer")),
        credentials=_saved_binding(credentials),
    )
    return _strings((answer or {}).get("binding"))


def oauth_effective_binding(
    credentials: dict[str, object],
    *,
    access_token: str | None,
    issuer: str | None,
) -> dict[str, str | None]:
    """The binding a rotated credential row keeps.

    A freshly issued ``access_token`` replaces the saved fields; otherwise the
    saved fields stay and the saved token only fills gaps. When the native
    answer is unavailable the rotated refresh token is still saved, so a
    refresh never loses it over a claim lookup. The saved fields stay only when
    no new token arrived: a new token's binding was never read, so its fields
    stay empty and the next sync recovers them through
    ``oauth_binding_from_credentials`` rather than pairing the new token with
    the previous token's binding.
    """

    refreshed = access_token is not None
    token = access_token if refreshed else _text(credentials.get("access_token"))
    answer = _native(
        "effective_binding",
        claims=_claims(token),
        issuer=issuer,
        credentials=_saved_binding(credentials),
        refreshed=refreshed,
    )
    if answer is None:
        saved = {} if refreshed else _saved_binding(credentials)
        return {key: saved.get(key) for key in _BINDING_KEYS}
    binding = _strings(answer.get("binding"))
    return {key: binding.get(key) for key in _BINDING_KEYS}


def oauth_access_token_expires_at(access_token: str, *, expires_in: object, now: datetime) -> str | None:
    """The token's own ``exp``, else ``now + expires_in``, else ``None``.

    Raises ``NativeRunnerAuthorityError`` when the runtime cannot answer, so
    the caller decides whether a missing expiry is acceptable.
    """

    answer = native_runner_authority(
        "oauth_token_claims",
        {
            "op": "expires_at",
            "claims": _claims(access_token),
            "expires_in": expires_in if isinstance(expires_in, (int, float, str)) else None,
            "now": now.isoformat(),
        },
    )
    expires_at = answer.get("expires_at") if isinstance(answer, dict) else None
    return expires_at if isinstance(expires_at, str) else None


def _saved_binding(credentials: dict[str, object]) -> dict[str, str]:
    return {key: value for key in _BINDING_KEYS if (value := _text(credentials.get(key))) is not None}


def _text(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


__all__ = [
    "decode_oauth_access_token_claims",
    "oauth_access_token_expires_at",
    "oauth_binding_from_credentials",
    "oauth_binding_metadata",
    "oauth_claim_string",
    "oauth_effective_binding",
    "oauth_token_identity",
]
