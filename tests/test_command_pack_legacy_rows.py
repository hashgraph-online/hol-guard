"""The legacy authority envelopes the pack lifecycle migration reads from the native store."""

from __future__ import annotations

import json
import sqlite3
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.catalog_delivery import legacy_rows, lifecycle_store
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError

EVIDENCE = "command_pack_legacy_evidence_rows"
HISTORY = "command_pack_legacy_history_page"


def env(record):
    return {"record": record, "digest": "d" * 64, "mac": "m" * 64}


def answered(*answers):
    calls = []
    queue = list(answers)

    def call(method, args):
        calls.append((method, dict(args)))
        return queue.pop(0)

    return SimpleNamespace(_native_store_call=call), calls


def present(snapshot=None, pending=None, transition=None):
    return {"state": "present", "snapshot": snapshot, "pending": pending, "transition": transition}


def test_evidence_rows_hand_on_every_envelope():
    store, calls = answered(
        present(
            snapshot={**env("snap"), "revision": 4},
            pending={"activation": env("act"), "link": env("lnk")},
            transition={"transition": env("tr"), "snapshot": env("next")},
        )
    )
    rows = legacy_rows.evidence_rows(store, 5)
    assert calls == [(EVIDENCE, {"observed_revision": 5})]
    assert rows.snapshot_revision == 4
    assert rows.snapshot == env("snap")
    assert rows.pending == {"activation": env("act"), "link": env("lnk")}
    assert rows.transition == env("tr")
    assert rows.next_snapshot == env("next")


def test_an_empty_store_has_no_evidence():
    store, _ = answered(present())
    rows = legacy_rows.evidence_rows(store, None)
    assert rows == legacy_rows.EvidenceRows(None, None, None, None, None)


def test_a_missing_schema_fails_as_the_sql_read_did():
    store, _ = answered({"state": "schema_missing"})
    with pytest.raises(sqlite3.OperationalError):
        legacy_rows.evidence_rows(store, None)


@pytest.mark.parametrize(
    "answer",
    [
        None,
        {"state": "present"},
        {**present(), "extra": 1},
        present(snapshot={**env("snap"), "revision": True}),
        present(snapshot={**env("snap"), "revision": -1}),
        present(snapshot={**env("snap")}),
        present(snapshot={**env(None), "revision": 1}),
        present(snapshot={**env("snap"), "revision": 1, "extra": "x"}),
        present(pending={"activation": env("act")}),
        present(pending={"activation": env("act"), "link": env(1)}),
        present(transition={"transition": env("tr")}),
        present(transition={"transition": env("tr"), "snapshot": "next"}),
        {"state": "refused", "snapshot": None, "pending": None, "transition": None},
    ],
)
def test_a_malformed_evidence_answer_is_refused(answer):
    store, _ = answered(answer)
    with pytest.raises(NativePolicySnapshotError, match=EVIDENCE):
        legacy_rows.evidence_rows(store, 3)


def test_history_follows_the_cursor_to_the_end():
    store, calls = answered(
        {"state": "present", "items": [env("s9"), env("s8")], "next": 8},
        {"state": "present", "items": [env("s7")], "next": None},
    )
    assert legacy_rows.history(store, 10) == [env("s9"), env("s8"), env("s7")]
    assert calls == [
        (HISTORY, {"below_revision": 10, "before": None}),
        (HISTORY, {"below_revision": 10, "before": 8}),
    ]


@pytest.mark.parametrize(
    "answer",
    [
        {"state": "present", "items": [], "next": 3},
        {"state": "present", "items": [env("s")], "next": 10},
        {"state": "present", "items": [env("s")], "next": True},
        {"state": "present", "items": [env(None)], "next": None},
        {"state": "present", "items": None, "next": None},
        {"state": "present", "items": []},
    ],
)
def test_a_history_page_that_cannot_end_or_is_malformed_is_refused(answer):
    store, _ = answered(answer)
    with pytest.raises(NativePolicySnapshotError, match=HISTORY):
        legacy_rows.history(store, 10)


def test_legacy_evidence_composes_the_native_reads(monkeypatch):
    from codex_plugin_scanner.guard.catalog_delivery import activation_store

    anchor = json.dumps({"record": json.dumps({"revision": 6})})
    calls = []
    answers = {
        EVIDENCE: present(snapshot={**env("snap"), "revision": 5}),
        HISTORY: {"state": "present", "items": [env("s4")], "next": None},
    }

    def call(method, args):
        calls.append((method, dict(args)))
        return answers[method]

    store = SimpleNamespace(
        _native_store_call=call,
        _authority_key=lambda required: b"\x01",
        _secret_store=lambda: SimpleNamespace(get_secret=lambda ref: anchor),
        _anchor_ref=lambda: "anchor",
    )
    slot = {"record_json": "{}", "record_digest": "rd", "record_mac": "rm"}
    monkeypatch.setattr(activation_store, "read_slot", lambda _store: slot)
    evidence = lifecycle_store.legacy_evidence(store)
    assert calls == [
        (EVIDENCE, {"observed_revision": 6}),
        (HISTORY, {"below_revision": 5, "before": None}),
    ]
    assert evidence == {
        "legacy_key": "01",
        "legacy_anchor": json.loads(anchor),
        "legacy_snapshot": env("snap"),
        "legacy_activation": {"record": "{}", "digest": "rd", "mac": "rm"},
        "legacy_history": [env("s4")],
        "legacy_transition": None,
        "legacy_next_snapshot": None,
        "legacy_pending": None,
    }


def test_no_snapshot_reads_no_history(monkeypatch):
    from codex_plugin_scanner.guard.catalog_delivery import activation_store

    store, calls = answered(present())
    store._authority_key = lambda required: None
    store._secret_store = lambda: SimpleNamespace(get_secret=lambda ref: None)
    store._anchor_ref = lambda: "anchor"
    monkeypatch.setattr(activation_store, "read_slot", lambda _store: None)
    evidence = lifecycle_store.legacy_evidence(store)
    assert calls == [(EVIDENCE, {"observed_revision": None})]
    assert evidence["legacy_history"] == [] and evidence["legacy_activation"] is None
