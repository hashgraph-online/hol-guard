"""The native runtime holds the trust attestation private key."""

from __future__ import annotations

import stat
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from codex_plugin_scanner.guard.mdm import runtime_request
from codex_plugin_scanner.guard.runtime import trust_attestation
from codex_plugin_scanner.guard.runtime.trust_attestation import (
    GUARD_TRUST_ATTESTATION_SIGNATURE_ALGORITHM_ECDSA_P256,
    GuardTrustAttestationSigningConfig,
    resolve_guard_oauth_trust_attestation_signing_config,
    resolve_trust_attestation_signing_config,
    sign_trust_attestation,
)
from tests.trust_attestation_verify_support import build_trust_attestation_verification_key

# Not empty, so the process environment is never read instead.
_ENV = {"GUARD_AIBOM_TRUST_ATTESTATION_KEY_ID": "local-key"}
_UNREADABLE_KEY = "-----BEGIN PRIVATE KEY-----\nsecret-key-material\n-----END PRIVATE KEY-----\n"


def _p256_config(private_key_pem: str | None = None) -> GuardTrustAttestationSigningConfig:
    if private_key_pem is None:
        private_key_pem = (
            ec.generate_private_key(ec.SECP256R1())
            .private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            .decode("ascii")
        )
    return GuardTrustAttestationSigningConfig(
        active_key_id="key-1",
        private_key_pem=private_key_pem,
        signature_algorithm=GUARD_TRUST_ATTESTATION_SIGNATURE_ALGORITHM_ECDSA_P256,
    )


def test_the_persistent_key_is_written_once_and_matches_its_thumbprint(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard"
    config = resolve_trust_attestation_signing_config(_ENV, guard_home=guard_home)
    assert config is not None

    key_path = guard_home / "trust_attestation_key.pem"
    assert key_path.read_text(encoding="utf-8") == f"{config.private_key_pem}\n"
    if sys.platform != "win32":
        assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
    verification_key = build_trust_attestation_verification_key(config)
    assert config.public_jwk_thumbprint == verification_key.fingerprint_sha256
    again = resolve_trust_attestation_signing_config(_ENV, guard_home=guard_home)
    assert again == config


def test_a_key_refusal_comes_before_a_payload_refusal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        trust_attestation,
        "native_runner_authority",
        lambda *_args, **_kwargs: {"refused": "Unknown trust attestation payload fields: extra"},
    )

    with pytest.raises(ValueError, match="must be RSA or EC"):
        sign_trust_attestation(payload={}, config=_p256_config(_UNREADABLE_KEY), signed_at="2026-06-10T12:00:00Z")
    with pytest.raises(ValueError, match="Unknown trust attestation payload fields"):
        sign_trust_attestation(payload={}, config=_p256_config(), signed_at="2026-06-10T12:00:00Z")


def test_without_the_runtime_nothing_is_signed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runtime_request, "runtime_answer", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        trust_attestation,
        "native_runner_authority",
        lambda *_args, **_kwargs: {"payload": {"payloadVersion": "guard-aibom-trust-attestation.v3"}},
    )

    assert resolve_trust_attestation_signing_config(_ENV, guard_home=tmp_path) is None
    assert not (tmp_path / "trust_attestation_key.pem").exists()
    assert (
        resolve_guard_oauth_trust_attestation_signing_config(
            {"dpop_private_key_pem": _p256_config().private_key_pem, "dpop_public_jwk_thumbprint": "thumb"}
        )
        is None
    )
    with pytest.raises(ValueError, match="native_trust_attestation_key_unavailable"):
        sign_trust_attestation(payload={}, config=_p256_config(), signed_at="2026-06-10T12:00:00Z")
