"""Validation helpers for persisted DPoP key bindings."""

from __future__ import annotations

import base64
import hashlib
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


def verified_dpop_jwk_thumbprint(
    *,
    private_key_pem: object,
    public_jwk: object,
) -> str:
    """Return the RFC 7638 JKT only when the active P-256 keypair is consistent."""

    if not isinstance(private_key_pem, str) or not isinstance(public_jwk, dict):
        raise ValueError("invalid_dpop_key_material")
    try:
        private_key = serialization.load_pem_private_key(private_key_pem.encode("ascii"), password=None)
    except (TypeError, ValueError) as error:
        raise ValueError("invalid_dpop_private_key") from error
    if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(private_key.curve, ec.SECP256R1):
        raise ValueError("invalid_dpop_private_key")
    numbers = private_key.public_key().public_numbers()
    expected = {
        "crv": "P-256",
        "kty": "EC",
        "x": _base64url(numbers.x.to_bytes(32, byteorder="big")),
        "y": _base64url(numbers.y.to_bytes(32, byteorder="big")),
    }
    if public_jwk != expected:
        raise ValueError("dpop_public_private_key_mismatch")
    canonical = json.dumps(expected, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _base64url(hashlib.sha256(canonical).digest())


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


__all__ = ["verified_dpop_jwk_thumbprint"]
