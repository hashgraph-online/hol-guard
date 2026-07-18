"""Process-local, test-only policy-bundle signing fixtures.

The private key is generated in memory and never persisted. It is not used by
production code and cannot be configured as a deployed trust anchor.
"""

from __future__ import annotations

import base64
from copy import deepcopy
from functools import lru_cache

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from codex_plugin_scanner.guard.policy_bundle_parser import (
    canonical_policy_bundle_payload,
    computed_policy_bundle_hash,
    payload_hash_for_policy_bundle,
)
from codex_plugin_scanner.guard.policy_bundle_trusted_keys import (
    POLICY_BUNDLE_KEY_PURPOSE,
    PolicyBundleVerificationKey,
    policy_bundle_keyring_payload,
    policy_bundle_verification_key_from_public_key,
)

TEST_POLICY_BUNDLE_KEY_ID = "guard-policy-bundle-test-only-v1"
TEST_POLICY_BUNDLE_WORKSPACE_ID = "workspace-1"


@lru_cache(maxsize=1)
def _private_key() -> RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def policy_bundle_test_verification_key(
    *,
    key_id: str = TEST_POLICY_BUNDLE_KEY_ID,
    workspace_id: str = TEST_POLICY_BUNDLE_WORKSPACE_ID,
    state: str = "active",
    purpose: str = POLICY_BUNDLE_KEY_PURPOSE,
    valid_from: str | None = None,
    valid_until: str | None = None,
) -> PolicyBundleVerificationKey:
    private_key = _private_key()
    public_key_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    return policy_bundle_verification_key_from_public_key(
        key_id=key_id,
        public_key_pem=public_key_pem,
        state=state,
        purpose=purpose,
        workspace_id=workspace_id,
        valid_from=valid_from,
        valid_until=valid_until,
    )


def policy_bundle_test_keyring(
    *,
    workspace_id: str = TEST_POLICY_BUNDLE_WORKSPACE_ID,
    key: PolicyBundleVerificationKey | None = None,
) -> dict[str, object]:
    resolved_key = key or policy_bundle_test_verification_key(workspace_id=workspace_id)
    return policy_bundle_keyring_payload((resolved_key,), workspace_id=workspace_id)


def sign_policy_bundle(
    policy_bundle: dict[str, object],
    *,
    workspace_id: str = TEST_POLICY_BUNDLE_WORKSPACE_ID,
    key: PolicyBundleVerificationKey | None = None,
    embed_public_key: bool = True,
) -> dict[str, object]:
    """Return a signed copy of ``policy_bundle`` using the test-only anchor."""

    signed_bundle = deepcopy(policy_bundle)
    resolved_key = key or policy_bundle_test_verification_key(workspace_id=workspace_id)
    signed_bundle["workspaceId"] = workspace_id
    verifier: dict[str, object] = {
        "algorithm": "rsa-pss-sha256",
        "fingerprintSha256": resolved_key.fingerprint_sha256,
        "keyId": resolved_key.key_id,
        "signature": None,
    }
    if embed_public_key:
        verifier["publicKeyPem"] = resolved_key.public_key_pem
    signed_bundle["verifier"] = verifier
    signed_bundle["bundleHash"] = computed_policy_bundle_hash(signed_bundle)
    signed_bundle["payloadHash"] = payload_hash_for_policy_bundle(signed_bundle)
    signature = _private_key().sign(
        canonical_policy_bundle_payload(signed_bundle),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
        hashes.SHA256(),
    )
    verifier["signature"] = base64.b64encode(signature).decode("ascii")
    return signed_bundle
