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
    """The grant, machine, workspace and device claims, each ``None`` when absent."""

    answer = _native("identity", claims=_claims(access_token)) or {}
    identity = _strings(answer.get("identity"))
    return {key: identity.get(key) for key in ("grant_id", "machine_id", "workspace_id", "device_id")}


def oauth_binding_metadata(access_token: str, *, issuer: str | None = None) -> dict[str, str]:
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
    answer is unavailable the saved fields stay as they are, so a refresh never
    loses the rotated refresh token over a claim lookup.
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
        saved = _saved_binding(credentials)
        return {key: saved.get(key) for key in _BINDING_KEYS}
    binding = _strings(answer.get("binding"))
    return {key: binding.get(key) for key in _BINDING_KEYS}


def oauth_access_token_expires_at(access_token: str, *, expires_in: object, now: datetime) -> str | None:
    """The token's own ``exp``, else ``now + expires_in``, else ``None``."""

    answer = _native(
        "expires_at",
        claims=_claims(access_token),
        expires_in=expires_in if isinstance(expires_in, (int, float, str)) else None,
        now=now.isoformat(),
    )
    expires_at = (answer or {}).get("expires_at")
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
