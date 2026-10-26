"""Guard the recorded signature decisions the Rust twin replays.

``rust/crates/guard-command/tests/guard_attestation_signature_parity.rs`` reads
the same fixture. Both sides must agree on every case, so a change to either
verifier that this file does not also record is caught here first.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from codex_plugin_scanner.guard.runtime.trust_attestation import _verify_signature

FIXTURE = Path(__file__).resolve().parents[1] / "tests/fixtures/guard-attestation-signature.v1.json"

NOT_RSA_OR_EC = "Trust attestation public key must be RSA or EC"


def _cases() -> list[dict[str, Any]]:
    document = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert document["schema"] == "guard-attestation-signature-parity.v1"
    return document["cases"]


def _decide(case: dict[str, Any]) -> str:
    """Replay the two steps ``verify_trust_attestation`` performs with the key."""

    try:
        public_key = serialization.load_pem_public_key(case["public_key_pem"].encode("utf-8"))
    except Exception:  # any load failure is the same refusal here
        return NOT_RSA_OR_EC
    if not isinstance(public_key, (RSAPublicKey, EllipticCurvePublicKey)):
        return NOT_RSA_OR_EC
    try:
        _verify_signature(
            public_key=public_key,
            canonical_payload=base64.b64decode(case["canonical_payload_base64"], validate=True),
            signature=base64.b64decode(case["signature_base64"], validate=True),
            signature_algorithm=case["signature_algorithm"],
        )
    except InvalidSignature:
        return "Trust attestation signature verification failed"
    except ValueError as error:
        return str(error)
    return "ok"


@pytest.mark.parametrize("case", _cases(), ids=lambda case: case["name"])
def test_recorded_signature_decision_still_holds(case: dict[str, Any]) -> None:
    assert _decide(case) == case["expected"]


def test_the_fixture_keeps_recording_signatures_that_verify() -> None:
    accepted = [case["name"] for case in _cases() if case["expected"] == "ok"]
    assert len(accepted) >= 2, accepted


def test_the_fixture_keeps_salt_lengths_other_than_the_longest() -> None:
    """Python signs with the longest salt but accepts any length on verify.

    ``padding.PSS.MAX_LENGTH`` means "as long as the modulus allows" when
    signing and "whatever the encoding says" when verifying, so a signer that
    is not this one -- salt-equals-digest is the common default -- still
    verifies here. A verifier that only knew the longest salt would refuse
    these, so the fixture has to keep carrying them.
    """

    accepted = {case["name"] for case in _cases() if case["expected"] == "ok"}
    for name in (
        "rsa-2048-salt-equals-digest",
        "rsa-2048-salt-zero",
        "rsa-2048-salt-sixteen",
        "rsa-3072-salt-equals-digest",
    ):
        assert name in accepted, name
    refused = {case["name"] for case in _cases() if case["expected"] != "ok"}
    assert "rsa-2048-salt-equals-digest-wrong-payload" in refused, refused
