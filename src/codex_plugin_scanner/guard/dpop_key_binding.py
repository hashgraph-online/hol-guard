"""Transport for the native DPoP key-binding verdict."""

from __future__ import annotations

from .native_policy_bundle import policy_bundle_verdict

_INVALID_MATERIAL = "invalid_dpop_key_material"


def verified_dpop_jwk_thumbprint(
    *,
    private_key_pem: object,
    public_jwk: object,
) -> str:
    """Return the RFC 7638 JKT only when the active P-256 keypair is consistent.

    Rust settles whether the stored JWK still describes the live private key and
    derives the thumbprint; this only shapes the request and reports the answer.
    Every native rejection, an outage included, raises ``ValueError`` so a caller
    that cannot read a thumbprint refuses the binding.
    """

    if not isinstance(private_key_pem, str) or not isinstance(public_jwk, dict):
        raise ValueError(_INVALID_MATERIAL)
    verdict = policy_bundle_verdict(
        "dpop_jwk_thumbprint",
        {"private_key_pem": private_key_pem, "public_jwk": public_jwk},
    )
    thumbprint = verdict.get("thumbprint")
    if not isinstance(thumbprint, str) or not thumbprint:
        raise ValueError(_INVALID_MATERIAL)
    return thumbprint


__all__ = ["verified_dpop_jwk_thumbprint"]
