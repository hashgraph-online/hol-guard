"""OAuth client configuration helpers for HOL Guard runtimes."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import urllib.parse
from dataclasses import dataclass
from functools import lru_cache

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

PRODUCTION_GUARD_OAUTH_CLIENT_ID = "guard-local-daemon"
STAGING_GUARD_OAUTH_CLIENT_ID = "guard-local-daemon-staging"
LOCAL_GUARD_OAUTH_CLIENT_ID = "guard-local-daemon-local"

PRODUCTION_GUARD_ISSUER = "https://hol.org"
STAGING_GUARD_ISSUER = "https://staging.hol.org"
LOCAL_GUARD_ISSUER = "http://127.0.0.1:3000"

_ALLOWED_PRODUCTION_GUARD_ORIGINS = frozenset({PRODUCTION_GUARD_ISSUER})
_ALLOWED_STAGING_GUARD_ORIGINS = frozenset({STAGING_GUARD_ISSUER})
_LOOPBACK_GUARD_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_DOCKER_LAB_GUARD_HOSTS = frozenset({"host.docker.internal"})

_PKCE_ALLOWED_CHARACTERS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~")


@dataclass(frozen=True)
class GuardOAuthClientConfig:
    issuer: str
    authorize_endpoint: str
    token_endpoint: str
    device_authorization_endpoint: str
    jwks_endpoint: str
    client_id: str


@dataclass(frozen=True)
class GuardDpopKeyMaterial:
    algorithm: str
    private_key_pem: str
    public_jwk: dict[str, str]
    public_jwk_thumbprint: str


@lru_cache(maxsize=64)
def _issuer_origin(issuer: str) -> str:
    parsed = urllib.parse.urlparse(issuer)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Guard OAuth issuer must be an absolute http(s) URL.")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


def _issuer_host(origin: str) -> str:
    return (urllib.parse.urlparse(origin).hostname or "").lower()


def _is_loopback_guard_origin(origin: str) -> bool:
    return _issuer_host(origin) in _LOOPBACK_GUARD_HOSTS


def _is_docker_lab_guard_origin(origin: str) -> bool:
    return _issuer_host(origin) in _DOCKER_LAB_GUARD_HOSTS


def _is_local_guard_origin(origin: str) -> bool:
    return _is_loopback_guard_origin(origin) or _is_docker_lab_guard_origin(origin)


def is_guard_oauth_origin_allowed(issuer: str) -> bool:
    try:
        origin = _issuer_origin(issuer)
    except ValueError:
        return False
    return (
        origin in _ALLOWED_PRODUCTION_GUARD_ORIGINS
        or origin in _ALLOWED_STAGING_GUARD_ORIGINS
        or _is_local_guard_origin(origin)
    )


def _require_allowlisted_guard_oauth_origin(issuer: str) -> str:
    origin = _issuer_origin(issuer)
    if (
        origin in _ALLOWED_PRODUCTION_GUARD_ORIGINS
        or origin in _ALLOWED_STAGING_GUARD_ORIGINS
        or _is_local_guard_origin(origin)
    ):
        return origin
    raise ValueError("Guard OAuth issuer must use an allowlisted HOL origin, local loopback, or docker-lab host.")


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
    origin = _require_allowlisted_guard_oauth_origin(issuer).lower()
    if _is_local_guard_origin(origin):
        return "local"
    if origin in _ALLOWED_STAGING_GUARD_ORIGINS:
        return "staging"
    return "production"


def resolve_guard_oauth_client_config(issuer: str) -> GuardOAuthClientConfig:
    return _oauth_endpoints(_require_allowlisted_guard_oauth_origin(issuer))


def validate_guard_sync_endpoint(sync_url: str, *, issuer: str | None = None) -> str:
    parsed = urllib.parse.urlsplit(sync_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Guard Cloud sync URL must be an absolute http(s) URL.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Guard Cloud sync URL userinfo is not allowed.")
    if parsed.fragment:
        raise ValueError("Guard Cloud sync URL fragments are not allowed.")
    origin = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
    if parsed.scheme != "https" and not _is_local_guard_origin(origin):
        raise ValueError("Guard Cloud sync URL must use HTTPS.")
    if issuer is not None:
        oauth_client = resolve_guard_oauth_client_config(issuer)
        if origin != oauth_client.issuer:
            raise ValueError("Guard Cloud sync origin no longer matches the configured issuer.")
        return sync_url
    if not is_guard_oauth_origin_allowed(origin):
        raise ValueError("Guard Cloud sync URL must use an allowlisted HOL origin or local loopback.")
    return sync_url


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


def generate_dpop_key_pair() -> GuardDpopKeyMaterial:
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_numbers = private_key.private_numbers()
    public_numbers = private_numbers.public_numbers
    public_jwk = {
        "crv": "P-256",
        "kty": "EC",
        "x": _base64url_encode(public_numbers.x.to_bytes(32, byteorder="big")),
        "y": _base64url_encode(public_numbers.y.to_bytes(32, byteorder="big")),
    }
    thumbprint_payload = {
        "crv": public_jwk["crv"],
        "kty": public_jwk["kty"],
        "x": public_jwk["x"],
        "y": public_jwk["y"],
    }
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    return GuardDpopKeyMaterial(
        algorithm="ES256",
        private_key_pem=private_key_pem,
        public_jwk=public_jwk,
        public_jwk_thumbprint=_base64url_encode(
            hashlib.sha256(
                json.dumps(thumbprint_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).digest()
        ),
    )
