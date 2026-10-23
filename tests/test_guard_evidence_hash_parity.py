"""Pin the evidence digest both runtimes have to agree on.

``runtime/evidence_hash.py`` and
``rust/crates/guard-command/src/evidence_hash.rs`` name the same local trust
claim on two different routes: a claim written on one route is looked up,
replayed and compared on the other, so a digest that drifted by a single byte
on either side would read as a claim nobody had ever made.

The fixture records a payload and the digest Python computes for it. Both
sides replay it, so a change to the canonical encoding or to the hash has to
move both copies or fail.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.evidence_hash import (
    canonical_guard_evidence_payload,
    guard_evidence_hash,
)

FIXTURE = Path(__file__).parent / "fixtures" / "guard-evidence-hash.v1.json"


def _cases() -> list[dict[str, object]]:
    document = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert document["schema"] == "guard-evidence-hash-parity.v1"
    return document["cases"]


@pytest.mark.parametrize("case", _cases(), ids=lambda case: case["name"])
def test_recorded_payloads_hash_to_their_recorded_digest(case: dict[str, object]) -> None:
    assert guard_evidence_hash(case["payload"]) == case["digest"]


def test_the_canonical_payload_sorts_keys_and_escapes_non_ascii() -> None:
    assert canonical_guard_evidence_payload({"b": 1, "a": "café"}) == '{"a":"caf\\u00e9","b":1}'


def test_insertion_order_does_not_change_the_digest() -> None:
    assert guard_evidence_hash({"a": 1, "b": 2}) == guard_evidence_hash({"b": 2, "a": 1})
