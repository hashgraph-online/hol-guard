"""Guard the recorded end-to-end verifier decisions the Rust twin replays.

``rust/crates/guard-command/tests/guard_trust_attestation_verify_parity.rs``
reads the same fixture. Both sides must agree on every case, so a change to
either verifier that this file does not also record is caught here first.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.runtime.trust_attestation import (
    GuardTrustAttestationVerificationKey,
    GuardTrustAttestationVerificationPolicy,
    verify_trust_attestation,
)

FIXTURE = Path(__file__).resolve().parents[1] / "tests/fixtures/guard-trust-attestation-verify.v1.json"


def _cases() -> list[dict[str, Any]]:
    document = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert document["schema"] == "guard-trust-attestation-verify-parity.v1"
    return document["cases"]


def _keys(records: list[dict[str, Any]] | None):
    if records is None:
        return None
    return tuple(
        GuardTrustAttestationVerificationKey(
            key_id=record["key_id"],
            public_key_pem=record["public_key_pem"],
            fingerprint_sha256=record["fingerprint_sha256"],
            public_jwk_thumbprint=record.get("public_jwk_thumbprint"),
        )
        for record in records
    )


def _policy(record: dict[str, Any]) -> GuardTrustAttestationVerificationPolicy:
    return GuardTrustAttestationVerificationPolicy(
        revoked_key_ids=frozenset(record["revoked_key_ids"]),
        key_not_before=tuple(record["key_not_before"].items()),
        minimum_sequence=record["minimum_sequence"],
        seen_replay_keys=frozenset(record["seen_replay_keys"]),
        now=record["now"],
        require_nonce=record["require_nonce"],
    )


def _verify(case: dict[str, Any]) -> str:
    return verify_trust_attestation(
        payload=case["payload"],
        envelope=case["envelope"],
        trusted_keys=_keys(case["trusted_keys"]),
        policy=_policy(case["policy"]),
        claim=case["claim"],
    )


@pytest.mark.parametrize("case", _cases(), ids=lambda case: case["name"])
def test_recorded_verifier_decision_still_holds(case: dict[str, Any]) -> None:
    if "replay_key" in case:
        assert _verify(case) == case["replay_key"]
        return
    with pytest.raises(ValueError) as refusal:
        _verify(case)
    if "rust_error" in case:
        # These two refusals are a library speaking, not this module: the text
        # moves between releases, so only the exception it raises is recorded.
        # ``attestation_verify`` documents what the Rust twin reports instead.
        assert type(refusal.value).__name__ == case["python_error_type"]
        return
    assert str(refusal.value) == case["error"]


def test_the_fixture_keeps_recording_attestations_that_verify() -> None:
    accepted = [case["name"] for case in _cases() if "replay_key" in case]
    assert len(accepted) >= 4, accepted
