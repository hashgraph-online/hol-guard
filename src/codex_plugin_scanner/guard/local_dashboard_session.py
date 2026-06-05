"""Signed local browser session tokens for Guard daemon surfaces."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from typing import Any

LOCAL_DASHBOARD_SESSION_VERSION = "guard-local-daemon-session.v1"
LOCAL_DASHBOARD_SESSION_PREFIX = "gld1"
DEFAULT_LOCAL_DASHBOARD_SESSION_TTL_SECONDS = 12 * 60 * 60
_PROTECTED_LOCAL_DASHBOARD_SESSION_CLAIMS = frozenset({"version", "surface", "expires_at"})


def build_local_dashboard_session_token(
    *,
    auth_token: str,
    surface: str,
    expires_in_seconds: int = DEFAULT_LOCAL_DASHBOARD_SESSION_TTL_SECONDS,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=max(1, expires_in_seconds))
    payload_data: dict[str, Any] = {
        "version": LOCAL_DASHBOARD_SESSION_VERSION,
        "surface": surface,
        "expires_at": expires_at.isoformat(),
    }
    if extra_claims:
        payload_data.update(
            {
                key: value
                for key, value in extra_claims.items()
                if key not in _PROTECTED_LOCAL_DASHBOARD_SESSION_CLAIMS
            }
        )
    payload_json = json.dumps(payload_data, separators=(",", ":"))
    encoded_payload = base64.urlsafe_b64encode(payload_json.encode("utf-8")).decode("ascii").rstrip("=")
    signature = hmac.new(auth_token.encode("utf-8"), encoded_payload.encode("utf-8"), hashlib.sha256).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    return f"{LOCAL_DASHBOARD_SESSION_PREFIX}.{encoded_payload}.{encoded_signature}"
