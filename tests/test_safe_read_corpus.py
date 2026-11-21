"""The safe-read corpus names routine actions that must run without a pause.

The benign false-positive gate replays every case through the native decision
path. This test keeps the corpus honest: each class lists routine allows and at
least one floor case, every id exists in the gate with the matching
expectation, and no routine case hides behind a ``pending_fix`` marker.
"""

from __future__ import annotations

import json
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"
CORPUS = json.loads((FIXTURES / "safe_read_corpus.json").read_text(encoding="utf-8"))
GATE = json.loads((FIXTURES / "benign_false_positive_gate.json").read_text(encoding="utf-8"))
CASES = {case["id"]: case for case in GATE["cases"]}
CLASSES = ("git_status", "safe_diff_query", "declared_script", "guard_status")


def test_the_corpus_covers_each_routine_class_with_a_floor():
    assert tuple(CORPUS["classes"]) == CLASSES
    for name, members in CORPUS["classes"].items():
        assert members["routine"], name
        assert members["floor"], f"{name} has no floor case, so its allows prove nothing about the floor"


def test_every_corpus_id_is_a_gate_case_with_the_matching_expectation():
    for name, members in CORPUS["classes"].items():
        for case_id in members["routine"]:
            assert CASES[case_id]["expect"] == "allow", (name, case_id)
        for case_id in members["floor"]:
            assert CASES[case_id]["expect"] == "not_allow", (name, case_id)


def test_no_routine_case_is_parked_as_a_known_failure():
    parked = {expanded.split("@", 1)[0] for expanded in GATE["pending_fix"]}
    routine = {case_id for members in CORPUS["classes"].values() for case_id in members["routine"]}

    assert sorted(routine & parked) == []


def test_each_id_appears_once():
    ids = [case_id for members in CORPUS["classes"].values() for kind in members.values() for case_id in kind]

    assert len(ids) == len(set(ids))
