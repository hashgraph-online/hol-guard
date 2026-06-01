"""OAuth client configuration helpers for HOL Guard runtimes."""

from __future__ import annotations

import base64
import hashlib
import secrets
import urllib.parse
from dataclasses import dataclass
from functools import lru_cache

PRODUCTION_GUARD_OAUTH_CLIENT_ID = "guard-local-daemon"
STAGING_GUARD_OAUTH_CLIENT_ID = "guard-local-daemon-staging"
LOCAL_GUARD_OAUTH_CLIENT_ID = "guard-local-daemon-local"

PRODUCTION_GUARD_ISSUER = "https://hol.org"
STAGING_GUARD_ISSUER = "https://staging.hol.org"
LOCAL_GUARD_ISSUER = "http://127.0.0.1:3000"

_PKCE_ALLOWED_CHARACTERS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
)


@dataclass(frozen=True)
class GuardOAuthClientConfig:
    issuer: str
    authorize_endpoint: str
    token_endpoint: str
    device_authorization_endpoint: str
    jwks_endpoint: str
    client_id: str


@lru_cache(maxsize=64)
def _issuer_origin(issuer: str) -> str:
    parsed = urllib.parse.urlparse(issuer)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Guard OAuth issuer must be an absolute http(s) URL.")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


def _oauth_endpoints(origin: str) -> GuardOAuthClientConfig:
    environment = detect_guard_oauth_environment(origin)
    client_id = {
        "production": PRODUCTION_GUARD_OAUTH_CLIENT_ID,
        "staging": STAGING_GUARD_OAUTH_CLIENT_ID,
        "local": LOCAL_GUARD_OAUTH_CLIENT_ID,
    }[environment]
    return GuardOAuthClientConfig(
        issuer=origin,
        authorize_endpoint=f"{origin}/api/guard/oauth/authorize",
        token_endpoint=f"{origin}/api/guard/oauth/token",
        device_authorization_endpoint=f"{origin}/api/guard/oauth/device/authorize",
        jwks_endpoint=f"{origin}/api/guard/oauth/jwks",
        client_id=client_id,
    )


def detect_guard_oauth_environment(issuer: str) -> str:
    origin = _issuer_origin(issuer).lower()
    host = urllib.parse.urlparse(origin).hostname or ""
    if host in {"127.0.0.1", "localhost", "::1"}:
        return "local"
    if host.startswith("staging."):
        return "staging"
    return "production"


def resolve_guard_oauth_client_config(issuer: str) -> GuardOAuthClientConfig:
    return _oauth_endpoints(_issuer_origin(issuer))


def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def generate_pkce_verifier(length: int = 64) -> str:
    if length < 43 or length > 128:
        raise ValueError("PKCE verifier length must be between 43 and 128 characters.")
    verifier = _base64url_encode(secrets.token_bytes(length))[:length]
    return verifier


def build_pkce_s256_challenge(verifier: str) -> str:
    if not verifier:
        raise ValueError("PKCE verifier is required.")
    if not set(verifier).issubset(_PKCE_ALLOWED_CHARACTERS):
        raise ValueError("PKCE verifier contains unsupported characters.")
    return _base64url_encode(hashlib.sha256(verifier.encode("ascii")).digest())
