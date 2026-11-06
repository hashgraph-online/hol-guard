"""The DPoP key binding is settled natively and still reports the same codes."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
from codex_plugin_scanner.guard.dpop_key_binding import verified_dpop_jwk_thumbprint

# Split so that no PEM frame is ever spelled out in the source.
_BEGIN = "-----BEGIN PRIVATE" + " KEY-----"
_END = "-----END PRIVATE" + " KEY-----"
_TRUNCATED_PEM = f"{_BEGIN}\nAAAA\n{_END}\n"


def _p384_pem() -> str:
    """A well-formed PKCS#8 key on the wrong curve: not a DPoP key."""
    key = ec.generate_private_key(ec.SECP384R1())
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


def test_thumbprint_matches_the_generator_for_a_live_keypair() -> None:
    material = generate_dpop_key_pair()
    thumbprint = verified_dpop_jwk_thumbprint(
        private_key_pem=material.private_key_pem,
        public_jwk=dict(material.public_jwk),
    )
    assert thumbprint == material.public_jwk_thumbprint


def test_a_jwk_from_another_key_is_a_mismatch() -> None:
    material = generate_dpop_key_pair()
    other = generate_dpop_key_pair()
    with pytest.raises(ValueError) as caught:
        verified_dpop_jwk_thumbprint(
            private_key_pem=material.private_key_pem,
            public_jwk=dict(other.public_jwk),
        )
    assert str(caught.value) == "dpop_public_private_key_mismatch"


@pytest.mark.parametrize(
    "mutate",
    (
        pytest.param(lambda jwk: {**jwk, "use": "sig"}, id="extra-member"),
        pytest.param(lambda jwk: {key: value for key, value in jwk.items() if key != "y"}, id="missing-member"),
        pytest.param(lambda jwk: {**jwk, "crv": "P-384"}, id="wrong-curve-claim"),
        pytest.param(lambda jwk: {**jwk, "kty": "RSA"}, id="wrong-key-type-claim"),
        pytest.param(lambda jwk: {**jwk, "x": 7}, id="non-text-coordinate"),
    ),
)
def test_a_reshaped_jwk_is_a_mismatch(mutate: object) -> None:
    material = generate_dpop_key_pair()
    with pytest.raises(ValueError) as caught:
        verified_dpop_jwk_thumbprint(
            private_key_pem=material.private_key_pem,
            public_jwk=mutate(dict(material.public_jwk)),  # type: ignore[operator]
        )
    assert str(caught.value) == "dpop_public_private_key_mismatch"


@pytest.mark.parametrize(
    "private_key_pem",
    (
        pytest.param(_p384_pem(), id="another-curve"),
        pytest.param("", id="empty"),
        pytest.param("not a pem at all", id="not-a-pem"),
        pytest.param(_TRUNCATED_PEM, id="truncated-der"),
    ),
)
def test_a_key_that_is_not_a_p256_private_key_is_refused(private_key_pem: str) -> None:
    material = generate_dpop_key_pair()
    with pytest.raises(ValueError) as caught:
        verified_dpop_jwk_thumbprint(
            private_key_pem=private_key_pem,
            public_jwk=dict(material.public_jwk),
        )
    assert str(caught.value) == "invalid_dpop_private_key"


@pytest.mark.parametrize(
    ("private_key_pem", "public_jwk"),
    (
        pytest.param(None, {}, id="missing-pem"),
        pytest.param(_BEGIN.encode("ascii"), {}, id="bytes-pem"),
        pytest.param(_BEGIN, None, id="missing-jwk"),
        pytest.param(_BEGIN, "crv=P-256", id="text-jwk"),
    ),
)
def test_material_that_is_not_key_material_never_reaches_the_runtime(
    private_key_pem: object,
    public_jwk: object,
) -> None:
    with pytest.raises(ValueError) as caught:
        verified_dpop_jwk_thumbprint(private_key_pem=private_key_pem, public_jwk=public_jwk)
    assert str(caught.value) == "invalid_dpop_key_material"
