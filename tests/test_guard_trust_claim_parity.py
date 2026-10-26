"""Pin the claim gate and the names it hands out for both runtimes.

``runtime/trust_attestation.py`` and
``rust/crates/guard-command/src/trust_claim.rs`` decide which claims are
locally derived and name the survivors by the SHA-256 of their canonical
payload. A verifier recognizes an attestation it has already seen by that
name, so a gate that admitted one claim more on one route, or a parser that
read one capture time differently, would hand the verifier a name for
something nobody had attested.

The fixture records Python's own verdicts. Both sides replay it, so a change
to either runtime has to move both copies or fail.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.trust_attestation import (
    _parse_attestation_timestamp,
    trust_attestation_replay_key,
    trust_claim_hash,
)

FIXTURE = Path(__file__).parent / "fixtures" / "guard-trust-claim.v1.json"
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _document() -> dict[str, object]:
    document = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert document["schema"] == "guard-trust-claim-parity.v1"
    return document


def _section(name: str) -> list[dict[str, object]]:
    return _document()[name]


def _epoch_microseconds(moment: datetime) -> int:
    delta = moment - EPOCH
    return delta.days * 86_400_000_000 + delta.seconds * 1_000_000 + delta.microseconds


@pytest.mark.parametrize("case", _section("timestamps"), ids=lambda case: case["input"])
def test_recorded_timestamps_parse_to_their_recorded_instant(case: dict[str, object]) -> None:
    parsed = _parse_attestation_timestamp(case["input"])
    if case["epochMicroseconds"] is None:
        assert parsed is None
    else:
        assert parsed is not None
        assert _epoch_microseconds(parsed) == case["epochMicroseconds"]


@pytest.mark.parametrize("case", _section("claims"), ids=lambda case: case["name"])
def test_recorded_claims_hash_to_their_recorded_digest(case: dict[str, object]) -> None:
    if case["claimHash"] is None:
        with pytest.raises((ValueError, AttributeError, TypeError)):
            trust_claim_hash(case["claim"], require_layer_identity=case["requireLayerIdentity"])
        return
    digest = trust_claim_hash(case["claim"], require_layer_identity=case["requireLayerIdentity"])
    assert digest == case["claimHash"]


@pytest.mark.parametrize("case", _section("replayKeys"), ids=lambda case: case["name"])
def test_recorded_payloads_replay_under_their_recorded_key(case: dict[str, object]) -> None:
    assert trust_attestation_replay_key(case["payload"]) == case["replayKey"]


def test_a_prior_attestation_does_not_change_the_claim_name() -> None:
    claim = next(
        case["claim"] for case in _section("claims") if case["name"] == "a complete local claim with layer identity"
    )
    stripped = {
        **claim,
        "metadata": {key: value for key, value in claim["metadata"].items() if not key.startswith("attestation")},
    }
    assert trust_claim_hash(claim, require_layer_identity=True) == trust_claim_hash(
        stripped, require_layer_identity=True
    )


def test_an_absent_replay_field_hashes_as_null() -> None:
    present = {"nonce": "n-1", "itemId": "item-1"}
    explicit = {
        **present,
        "domainSeparator": None,
        "scope": None,
        "layerId": None,
        "workspaceId": None,
        "repositoryId": None,
    }
    assert trust_attestation_replay_key(present) == trust_attestation_replay_key(explicit)


def test_the_fixture_keeps_the_offsets_the_interpreters_read_differently() -> None:
    """A UTC offset carrying a fraction is no instant, on every interpreter.

    The reader behind ``fromisoformat`` used to ask only whether an offset's
    whole seconds were zero and drop the fraction, so ``+00:00:00.999999`` was
    UTC itself; newer interpreters read it as a microsecond east. The shape
    refuses the spelling before ``fromisoformat`` sees it, so the answer no
    longer depends on which interpreter runs the check.
    """

    fractional = [
        case for case in _section("timestamps") if re.search(r"[+-]\d{2}:\d{2}:\d{2}\.\d+$", str(case["input"]))
    ]
    assert len(fractional) >= 15, len(fractional)
    for case in fractional:
        assert case["epochMicroseconds"] is None, case["input"]
    recorded = {str(case["input"]) for case in _section("timestamps")}
    assert "2026-10-23T12:00:00-00:00:00.000001" in recorded
    assert "2026-10-23T12:00:00+00:00:00.999999" in recorded
