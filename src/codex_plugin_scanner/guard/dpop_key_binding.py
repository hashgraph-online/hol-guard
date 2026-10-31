"""Transport for the native DPoP key-binding verdict."""

from __future__ import annotations

from .native_policy_bundle import PolicyBundleNativeUnavailableError, policy_bundle_verdict

_INVALID_MATERIAL = "invalid_dpop_key_material"
_SCHEMA_MISMATCH = "native_policy_bundle_authority_schema_mismatch"


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


def signed_dpop_proof(
    *,
    private_key_pem: str,
    algorithm: str,
    public_jwk: dict[str, str],
    request_url: str,
    method: str,
    issued_at: int,
    access_token: str | None = None,
    nonce: str | None = None,
) -> str:
    """Return the DPoP proof (RFC 9449) Rust signs for one Guard Cloud request.

    A rejected key or token raises ``PolicyBundleNativeError`` with Rust's code;
    an outage raises ``PolicyBundleNativeUnavailableError``.
    """

    verdict = policy_bundle_verdict(
        "dpop_proof",
        {
            "private_key_pem": private_key_pem,
            "algorithm": algorithm,
            "public_jwk": public_jwk,
            "request_url": request_url,
            "method": method,
            "issued_at": issued_at,
            "access_token": access_token,
            "nonce": nonce,
        },
    )
    proof = verdict.get("proof")
    if not isinstance(proof, str) or proof.count(".") != 2:
        raise PolicyBundleNativeUnavailableError(_SCHEMA_MISMATCH)
    return proof


__all__ = ["signed_dpop_proof", "verified_dpop_jwk_thumbprint"]
