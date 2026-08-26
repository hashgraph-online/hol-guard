"""Bounded unverified OAuth claim extraction for locally authenticated tokens."""

from __future__ import annotations

import json
from base64 import urlsafe_b64decode


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


def oauth_device_id(claims: dict[str, object]) -> str | None:
    return (
        oauth_claim_string(claims, "deviceId")
        or oauth_claim_string(claims, "device", "deviceId")
        or oauth_claim_string(claims, "machine", "deviceId")
    )


def oauth_binding_metadata(access_token: str, *, issuer: str | None = None) -> dict[str, str]:
    claims = decode_oauth_access_token_claims(access_token)
    token_issuer = oauth_claim_string(claims, "iss")
    if issuer is not None and token_issuer is not None and token_issuer.rstrip("/") != issuer.rstrip("/"):
        return {}
    binding = {
        "grant_id": oauth_claim_string(claims, "grant", "grantId"),
        "machine_id": oauth_claim_string(claims, "machine", "machineId"),
        "workspace_id": oauth_claim_string(claims, "workspace", "workspaceId"),
    }
    if not all(binding.values()):
        return {}
    result = {key: str(value) for key, value in binding.items()}
    if device_id := oauth_device_id(claims):
        result["device_id"] = device_id
    return result


def oauth_refresh_binding(
    credentials: dict[str, object],
    recovered: dict[str, str],
    *,
    refreshed: bool,
) -> dict[str, str | None]:
    """Prefer explicit refreshed claims while retaining honest recovery fallback."""

    return {
        key: recovered.get(key) if refreshed else _text(credentials.get(key)) or recovered.get(key)
        for key in ("device_id", "grant_id", "machine_id", "workspace_id")
    }


def oauth_binding_from_credentials(credentials: dict[str, object]) -> dict[str, str]:
    access_token = _text(credentials.get("access_token"))
    issuer = _text(credentials.get("issuer"))
    if access_token is None or issuer is None:
        return {}
    claimed = oauth_binding_metadata(access_token, issuer=issuer)
    if any(_text(credentials.get(key)) not in {None, value} for key, value in claimed.items()):
        return {}
    return claimed


def _text(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


__all__ = [
    "decode_oauth_access_token_claims",
    "oauth_binding_from_credentials",
    "oauth_binding_metadata",
    "oauth_claim_string",
    "oauth_device_id",
    "oauth_refresh_binding",
]
