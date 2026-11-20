"""Pin the attestation payload gate for both runtimes.

``_validate_attestation_payload`` in ``runtime/trust_attestation.py`` and
``rust/crates/guard-command/src/attestation_payload.rs`` decide the shape a
trust attestation has to have before a key signs it and before a verifier
believes it. A builder on one route and a verifier on the other would sign and
then trust payloads neither side had agreed to if the gates drifted, so the
fixture records Python's own verdicts — including the wording of each refusal
— and both sides replay it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.trust_attestation import (
    _validate_attestation_payload,
)

FIXTURE = Path(__file__).parent / "fixtures" / "guard-attestation-payload.v1.json"


def _cases() -> list[dict[str, object]]:
    document = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert document["schema"] == "guard-attestation-payload-parity.v1"
    return document["cases"]


CASES = _cases()


def test_the_fixture_covers_both_verdicts() -> None:
    accepted = [case for case in CASES if "normalized" in case]
    refused = [case for case in CASES if "error" in case]
    assert len(accepted) >= 10
    assert len(refused) >= 30
    assert len(accepted) + len(refused) == len(CASES)
    assert len({case["name"] for case in CASES}) == len(CASES)


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_recorded_payloads_are_accepted_or_refused_as_recorded(case: dict[str, object]) -> None:
    rules = case["rules"]
    if "error" in case:
        with pytest.raises(ValueError) as refusal:
            _validate_attestation_payload(
                case["payload"],
                require_signed_at=rules["require_signed_at"],
                require_nonce=rules["require_nonce"],
                require_subject_bindings=rules["require_subject_bindings"],
            )
        assert str(refusal.value) == case["error"]
        return
    normalized = _validate_attestation_payload(
        case["payload"],
        require_signed_at=rules["require_signed_at"],
        require_nonce=rules["require_nonce"],
        require_subject_bindings=rules["require_subject_bindings"],
    )
    assert normalized == case["normalized"]
