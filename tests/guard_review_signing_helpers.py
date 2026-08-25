from __future__ import annotations

import base64
from typing import cast

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from codex_plugin_scanner.guard import review_contracts as review_contracts_module
from codex_plugin_scanner.guard.policy_bundle_trusted_keys import (
    policy_bundle_verification_key_from_public_key,
)

REVIEW_SIGNING_KEY_ID = "guard-review-test-key"
REVIEW_SIGNING_KEY_PURPOSE = "remote_approval"
_REVIEW_TEST_PRIVATE_KEY_PEM = b"""-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDJwyJpxMtJv8Cu
+o/ap5ex4LKoKzUd75cJiRo/QaRqTaUAWZGV4F2TIQBSxQdJXybus5G1CbRzdJuB
+kKBI8f+y1VGwakF0RPTK3AWkw0dDesq9WpuMxwJnLKcd/Ko/sgZwnvWZKR7cv6R
rPFYWmZ3LHBDxW43qffUBOMTJWl0mUjonwZwliOLD/y9VPDehiHw4Lah/z1T8TQp
o5Ft413QQuweTvz0vxqyvlDfPkRSPZWtlMyehCNLtMTrk40dadcGHABIcvHjJY4s
pv+b/mMGu4VdYaunNZzLBhbhDTbCBQSyrlL6xupBRUO37i0j2Ta109JIrZCZOiKy
ORvPhVxjAgMBAAECggEAHLEIKscBKwVUDvizY6JjkGMQukNys/AcqA7RfF9cVIBN
ejrtLhq66S+kjnYAWZm+EpcsnZ8PWep3gXNSPm+/2BGYQzifovke0EUkFRcSTVMW
Ydnb1GdQ5w5b2U5hY/uJ/x0eDoM/X2LJ+siqMCii252mgAIKcMCrQoDzaFybSNOR
hprbh5kC8QJqReJOrTHBmpnGIe8P1kwlTFFkrUnBBNH5Oq4X865c1/lVXacL1nAO
Qh+bws3Rd2KMPcnCAdBlFtX8I03rl38B+5W1VpZFPyC9HSCFuQYYWNHm/YmYtFUN
Yhj29Rnv0LOJVYst6OPKNBbOKzVFz0JymAoLpGgFoQKBgQDkqNSadS77t8XH5AqX
IGKDvrTnXOrVMI40sb6UAW29EW2mULo5VCqitSHtb92dTkz6leKBcMUNt0sCduni
D/Y9rxAKwsgalToFvbY69HPDtVWqk2ngln78o60d9bVV2B6R0DWATaesvbWbpyft
wvSTeh8zu5nMgpHWish7JtSsswKBgQDh4v2XrCGnY810J/j7U+7Rvr78UUnwy3Wm
tDTEw6k7vG8ygINb66JmN+Bh9hds6i1UUaG+CF9575vv4T82wu1FJE9QMqVZoeKE
6QUyqwNoPcIR5SBSrpmQBc96WW5ldjL8EaBXAosx55C8aJZSBMxqr/1nkT2G9wik
yqkHni3JkQKBgGAyErckQ27MYl10t2vayPcp3MtU0Mp9keXjPQzhCPy4f0uvvJhv
qzwmPa65GB+cmE/3jIHuIkhh6yGPS1e6ZVqP8ozEYxCj5PQTWr20p5sXB4IqYCmG
xsecSDFJdE84C6xGTqu6f6bxbJyeFvM0yFXe04+dBdf+ukHqwurkbCZ3AoGAaUv8
1rUgwvzdCyaPA+luTEvUj539D8hoQZuDda2XuAbw9uO9WB4RiADIEiI7bUQEeWfM
M9+HUjoFwN6JLyfSnwZ8CnBxb8Ts6PQOvj3FytPvIZRjaueFIgPzYZ9KvPVKcwJs
ceL3q/28FHfUiss91wXO5HZp7f4+A0ONY8WypmECgYEA3UkXAKJaCrICiVFu9Bee
qvjiv3xc9HXDMJSYk9lAiR7W41OGZ1/xUIHZk+y1avedM+7wuaFyhU4c/0EHG4on
pgvJpBnvgbpqZZPerCAcmyl00SztAHiAqomdAZLuv5H9J9wtnUN7GJp770zeWpsl
yxirwBi/UcLEYjUv8kChIAQ=
-----END PRIVATE KEY-----
"""
_REVIEW_PRIVATE_KEY = cast(
    rsa.RSAPrivateKey,
    serialization.load_pem_private_key(_REVIEW_TEST_PRIVATE_KEY_PEM, password=None),
)
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
