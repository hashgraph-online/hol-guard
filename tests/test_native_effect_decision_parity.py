"""Read the native effect decision back the way the execution path does.

``rust/crates/guard-command/tests/effect_decision_parity.rs`` replays the same
corpus through the Rust evaluator and asserts the emitted ``decision_plane``
matches the recorded output byte for byte. That proves Rust still produces
those bytes; it says nothing about whether Guard can still read them.

Python reads them. ``native_execution._effect_decision`` turns a native
decision payload back into the dataclasses the contained execution paths carry,
and every vocabulary it meets on the way -- the action, the disposition, each
reason's source, each proof route -- goes through a Python enum. A value the
resident emits that Python does not name raises ``ValueError``, and the whole
native result fails to parse: safe, but the execution path is dead. Nothing
replayed the recorded output through that parse until this file did.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_execution
from codex_plugin_scanner.guard.runtime.effect_contract import ProofRoute
from codex_plugin_scanner.guard.runtime.effect_decision import (
    _REASON_CODE,
    _REFERENCE,
    EFFECT_DECISION_SCHEMA_VERSION,
    DecisionFactorSource,
    DecisionReason,
    FinalDisposition,
)

VECTORS = Path(__file__).resolve().parents[1] / "rust/crates/guard-command/tests/fixtures/effect_decision_vectors.json"

# Vocabulary the corpus has never recorded. `silent-contained` and the
# `containment` and `assurance` sources belong to the contained and assurance
# routes, which no recorded request drives. Python names them, so a payload
# carrying one parses today; nothing proves the resident still spells them the
# same way. Shrink this set when a case covering one is recorded -- a value
# that leaves the corpus without leaving this set fails below.
UNRECORDED_DISPOSITIONS = frozenset({"silent-contained"})
UNRECORDED_SOURCES = frozenset({"assurance", "containment"})


def _cases() -> list[dict[str, Any]]:
    cases = json.loads(VECTORS.read_text(encoding="utf-8"))
    assert isinstance(cases, list) and cases, "the recorded corpus is empty"
    return cases


def _assert_reason_is_the_recorded_one(reason: DecisionReason, recorded: dict[str, Any], key: str) -> None:
    """Every field the resident sends, read back and compared.

    `DecisionReason` carries five fields and the execution path reads all of
    them, so comparing a subset would let the parse return a different reason
    while this file stayed green. The references are `None` throughout the
    recorded corpus today; comparing them is what notices when they stop being.
    """

    assert reason.source.value == recorded["source"], (key, recorded)
    assert reason.reason_code == recorded["reason_code"], (key, recorded)
    assert reason.action_floor == recorded["action_floor"], (key, recorded)
    assert reason.segment_ref == recorded["segment_ref"], (key, recorded)
    assert reason.operation_ref == recorded["operation_ref"], (key, recorded)


@pytest.mark.parametrize("case", _cases(), ids=lambda case: f"case-{case['case']}")
def test_the_recorded_native_decision_parses_back(case: dict[str, Any]) -> None:
    """What Rust emits is what the execution path can read."""

    expected = case["expected"]
    decision = native_execution._effect_decision(expected)
    assert decision.action == expected["action"]
    assert decision.disposition.value == expected["disposition"]
    assert {route.value for route in decision.proof_routes} == set(expected["proof_routes"])
    # `_effect_decision` does not read the payload's version: the dataclass
    # default fills it, so the parsed decision always carries Python's own
    # constant. Pinning the recorded version against that constant is what
    # catches a resident that moves the contract out from under this parse.
    assert decision.schema_version == EFFECT_DECISION_SCHEMA_VERSION
    assert expected["schema_version"] == EFFECT_DECISION_SCHEMA_VERSION
    for key in ("reasons", "controlling_reasons"):
        parsed: tuple[DecisionReason, ...] = getattr(decision, key)
        assert len(parsed) == len(expected[key]), key
        for reason, recorded in zip(parsed, expected[key], strict=True):
            _assert_reason_is_the_recorded_one(reason, recorded, key)


def _recorded_reasons() -> list[dict[str, Any]]:
    return [
        reason for case in _cases() for key in ("reasons", "controlling_reasons") for reason in case["expected"][key]
    ]


def test_every_recorded_identifier_passes_pythons_own_grammar() -> None:
    """The reason-code and reference patterns live in both halves.

    ``DecisionReason`` carries no validation of its own -- only
    ``DecisionFactor`` runs these patterns -- so a reason the resident emits
    reaches Python unchecked. Rust applies the same three anchored patterns
    before it emits one. Replaying the recorded identifiers through Python's
    copy is what keeps the two spellings honest.
    """

    reasons = _recorded_reasons()
    assert reasons, "the corpus records no reasons"
    for reason in reasons:
        assert _REASON_CODE.fullmatch(reason["reason_code"]) is not None, reason
        for field in ("segment_ref", "operation_ref"):
            value = reason.get(field)
            if value is not None:
                assert _REFERENCE.fullmatch(value) is not None, reason


def test_the_corpus_records_no_reference_yet() -> None:
    """Both reference fields are null throughout the corpus, so say so.

    The replay compares them, which keeps the parse honest the moment a
    reference does arrive. Until then the comparison is `None` against `None`,
    and this is what makes that visible rather than quietly reassuring. Delete
    this test when a case records a reference -- it fails first.
    """

    reasons = _recorded_reasons()
    assert reasons, "the corpus records no reasons"
    assert all(reason["segment_ref"] is None for reason in reasons)
    assert all(reason["operation_ref"] is None for reason in reasons)


def test_the_corpus_covers_the_vocabulary_it_claims_to() -> None:
    """A value that stops being recorded has to be declared unrecorded."""

    cases = _cases()
    recorded_dispositions = {case["expected"]["disposition"] for case in cases}
    recorded_sources = {reason["source"] for reason in _recorded_reasons()}
    recorded_routes = {route for case in cases for route in case["expected"]["proof_routes"]}

    assert {member.value for member in FinalDisposition} - recorded_dispositions == (UNRECORDED_DISPOSITIONS)
    assert {member.value for member in DecisionFactorSource} - recorded_sources == (UNRECORDED_SOURCES)
    assert {member.value for member in ProofRoute} - recorded_routes == frozenset()
