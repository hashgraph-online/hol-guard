"""Finite lossless-retention controls; no native runtime or service qualification."""

from __future__ import annotations

import copy
import hashlib
import json

import pytest

from codex_plugin_scanner.guard.native_decision_receipt import canonical_receipt_bytes
from scripts.native_slo_session import _build_stop_diagnostic
from scripts.native_slo_workspace_poststart_evidence import RetainedLedger, encode_retained
from tests.native_workspace_request_fixtures import receipt, snapshot


def test_complete_receipts_and_large_nested_packet_survive_private_ledger(tmp_path):
    native = receipt(snapshot())
    native["request_id"] = "controlled-" + "r" * 200
    native["decision_id"] = hashlib.sha256(canonical_receipt_bytes(native)).hexdigest()
    nested = {"native_receipt": native, "committed_receipt": copy.deepcopy(native)}
    for _ in range(8):
        nested = {"child": nested}
    value = {
        "kind": "poststart_phase_terminal",
        "nested": nested,
        "identifiers": ["fixture-" + "a" * 200 for _ in range(64)],
        "samples": list(range(300)),
    }
    expected = copy.deepcopy(value)
    encoded = encode_retained(value)
    assert len(encoded) > 8192
    assert json.loads(encoded) == expected
    path = tmp_path / "retained.jsonl"
    ledger = RetainedLedger(path)
    assert ledger.write(value) is True
    report = ledger.finish()
    assert report["complete"] is True and report["packets"] == 1
    records = [json.loads(line) for line in path.read_bytes().splitlines()]
    parts = [row["payload"] for row in records if row["kind"] == "packet_part"]
    reconstructed = "".join(parts).encode("ascii")
    assert reconstructed == encoded
    assert json.loads(reconstructed) == expected
    assert report["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert value == expected


@pytest.mark.parametrize(
    "case",
    [
        "raw_field",
        "free_text",
        "sensitive_identifier",
        "nonfinite_nan",
        "nonfinite_infinity",
        "oversized_sequence",
        "oversized_integer",
        "opaque_object",
    ],
)
def test_unsupported_evidence_is_rejected_without_redaction(case):
    values = {
        "raw_field": {"payload": "controlled"},
        "free_text": {"message": "an arbitrary free form value"},
        "sensitive_identifier": {"message": "private_key"},
        "nonfinite_nan": {"value": float("nan")},
        "nonfinite_infinity": {"value": float("inf")},
        "oversized_sequence": {"value": list(range(513))},
        "oversized_integer": {"value": 1 << 257},
        "opaque_object": {"value": object()},
    }
    with pytest.raises(ValueError):
        encode_retained(values[case])


def test_receipt_identity_corruption_is_rejected_without_dropping_the_receipt():
    native = receipt(snapshot())
    native["command_extensions"]["program_digest"] = "9" * 64
    expected = copy.deepcopy(native)
    with pytest.raises(ValueError, match="complete receipt identity"):
        encode_retained({"native_receipt": native})
    assert native == expected


def test_deep_structure_is_explicitly_incomplete_instead_of_truncated():
    value = {"native_receipt": receipt(snapshot())}
    for _ in range(30):
        value = {"child": value}
    with pytest.raises(ValueError, match="structure outside bound"):
        encode_retained(value)


@pytest.mark.parametrize(
    "status,error",
    [
        ("failed", "native_resident_stop_unavailable"),
        ("contained", None),
        ("already-stopped", None),
    ],
)
def test_every_typed_native_stop_field_is_retained(status, error):
    value = _build_stop_diagnostic(status, error=error, fields={"endpoint": "verified", "owner_lock": "free"})
    expected = copy.deepcopy(value)
    assert json.loads(encode_retained({"diagnostic": value})) == {"diagnostic": expected}
    assert value == expected


def test_unknown_stop_status_is_rejected_without_rewriting_original():
    value = _build_stop_diagnostic("unknown_fixture_status")
    expected = copy.deepcopy(value)
    with pytest.raises(ValueError, match="diagnostic status"):
        encode_retained(value)
    assert value == expected


def test_partial_packet_failure_survives_finish_and_refuses_later_offers(tmp_path, monkeypatch):
    path = tmp_path / "partial.jsonl"
    ledger = RetainedLedger(path)
    write = ledger.original.write
    calls = []

    def fail_after_begin(row):
        calls.append(row["kind"])
        if len(calls) == 2:
            raise OSError("controlled private packet write failure")
        return write(row)

    monkeypatch.setattr(ledger.original, "write", fail_after_begin)
    with pytest.raises(OSError, match="controlled private packet write failure"):
        ledger.write({"kind": "poststart_phase_terminal", "value": "original"})
    first_failure = copy.deepcopy(ledger.errors[0])
    assert ledger.write({"kind": "poststart_phase_offer"}) is False
    report = ledger.finish()
    assert report["complete"] is False and report["packets"] == 1
    assert report["errors"][0] == first_failure
    assert (
        first_failure["failure"]["diagnostic_digest"]
        == hashlib.sha256(b"controlled private packet write failure").hexdigest()
    )
    assert calls == ["packet_begin", "packet_part"]
    assert [json.loads(row)["kind"] for row in path.read_bytes().splitlines()] == ["packet_begin"]


@pytest.mark.parametrize("mutation", ["same_size_payload", "extra_bytes"])
def test_independent_readback_rejects_same_inode_tampering(tmp_path, mutation):
    path = tmp_path / "tamper.jsonl"
    ledger = RetainedLedger(path)
    ledger.write({"kind": "poststart_phase_terminal", "value": "original"})
    original_inode = path.stat().st_ino
    raw = path.read_bytes()
    if mutation == "same_size_payload":
        offset = raw.index(b"original")
        with path.open("r+b") as changed:
            changed.seek(offset)
            changed.write(b"modified")
    else:
        with path.open("ab") as changed:
            changed.write(b"\n")
    assert path.stat().st_ino == original_inode
    retained = path.read_bytes()
    report = ledger.finish()
    assert report["complete"] is False
    assert report["errors"][-1]["stage"] == "finish_or_readback"
    assert path.read_bytes() == retained
