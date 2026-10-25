"""Guard the recorded verifier decisions the Rust twin replays.

``rust/crates/guard-command/tests/guard_attestation_verification_parity.rs``
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

FIXTURE = Path(__file__).resolve().parents[1] / "tests/fixtures/guard-attestation-verification.v1.json"


def _document() -> dict[str, Any]:
    document = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert document["schema"] == "guard-attestation-verification-parity.v1"
    return document


def _cases() -> list[dict[str, Any]]:
    return _document()["cases"]


def _trusted_keys(
    recorded: list[dict[str, Any]] | None,
) -> tuple[GuardTrustAttestationVerificationKey, ...] | None:
    if recorded is None:
        return None
    return tuple(
        GuardTrustAttestationVerificationKey(
            key_id=key["key_id"],
            public_key_pem=key["public_key_pem"],
            fingerprint_sha256=key["fingerprint_sha256"],
            public_jwk_thumbprint=key["public_jwk_thumbprint"],
        )
        for key in recorded
    )


def _policy(recorded: dict[str, Any]) -> GuardTrustAttestationVerificationPolicy:
    return GuardTrustAttestationVerificationPolicy(
        revoked_key_ids=frozenset(recorded["revoked_key_ids"]),
        key_not_before=tuple(sorted(recorded["key_not_before"].items())),
        minimum_sequence=recorded["minimum_sequence"],
        seen_replay_keys=frozenset(recorded["seen_replay_keys"]),
        now=recorded["now"],
        require_nonce=recorded["require_nonce"],
    )


def _verify(case: dict[str, Any]) -> str:
    return verify_trust_attestation(
        payload=case["payload"],
        envelope=case["envelope"],
        trusted_keys=_trusted_keys(case["trusted_keys"]),
        policy=_policy(case["policy"]),
        claim=case["claim"],
    )


def test_the_fixture_still_covers_both_outcomes() -> None:
    cases = _cases()
    assert len(cases) >= 25
    assert sum(1 for case in cases if "replay_key" in case) >= 8
    assert sum(1 for case in cases if "error" in case) >= 15
    assert len({case["name"] for case in cases}) == len(cases)


def test_the_fixture_keeps_an_envelope_that_overrides_the_payloads_signing_time() -> None:
    """A verifier reads the envelope's ``signedAt``, never the payload's own.

    Both runtimes hash the payload the override produced, so a fixture that
    only ever recorded the two times agreeing would let either side read the
    wrong one without a case noticing.
    """

    overridden = [case for case in _cases() if case["envelope"].get("signedAt") != case["payload"].get("signedAt")]
    assert overridden, "no case records an envelope that moves the signing time"
    assert any("replay_key" in case for case in overridden)


@pytest.mark.parametrize("case", _cases(), ids=lambda case: case["name"])
def test_a_recorded_attestation_is_verified_the_way_the_fixture_records(case: dict[str, Any]) -> None:
    if "replay_key" in case:
        assert _verify(case) == case["replay_key"]
        return
    with pytest.raises(ValueError) as refusal:
        _verify(case)
    assert str(refusal.value) == case["error"]
