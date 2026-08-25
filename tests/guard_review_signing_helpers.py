from __future__ import annotations

import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from codex_plugin_scanner.guard import review_contracts as review_contracts_module
from codex_plugin_scanner.guard.policy_bundle_trusted_keys import (
    policy_bundle_verification_key_from_public_key,
)

REVIEW_SIGNING_KEY_ID = "guard-review-test-key"
REVIEW_SIGNING_KEY_PURPOSE = "remote_approval"
_REVIEW_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_REVIEW_PUBLIC_KEY_PEM = (
    _REVIEW_PRIVATE_KEY.public_key()
    .public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    .decode("utf-8")
    .strip()
)


def review_verification_keys(
    *,
    workspace_id: str | None = "workspace-1",
    purpose: str = REVIEW_SIGNING_KEY_PURPOSE,
) -> list[dict[str, object]]:
    return [
        policy_bundle_verification_key_from_public_key(
            key_id=REVIEW_SIGNING_KEY_ID,
            public_key_pem=_REVIEW_PUBLIC_KEY_PEM,
            purpose=purpose,
            workspace_id=workspace_id,
        ).to_dict()
    ]


def review_trusted_keyring_payload(
    *,
    workspace_id: str | None = "workspace-1",
    purpose: str = REVIEW_SIGNING_KEY_PURPOSE,
) -> list[dict[str, object]]:
    return review_verification_keys(workspace_id=workspace_id, purpose=purpose)


def sign_review_payload(payload: dict[str, object]) -> str:
    signature = _REVIEW_PRIVATE_KEY.sign(
        review_contracts_module._canonical_signed_payload(payload).encode("utf-8"),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode("ascii")
