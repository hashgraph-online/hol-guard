"""Capture fingerprints and optional receipt projections."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.codex_binding_capture import (
    join_binding_records,
    record_bridge_ingress,
    record_native_worker,
)
from codex_plugin_scanner.guard.codex_binding_capture_crypto import open_receipt
from codex_plugin_scanner.guard.codex_binding_capture_join import valid_existing_records
from codex_plugin_scanner.guard.native_decision_receipt import canonical_receipt_bytes
from tests.codex_binding_capture_support import _enable_capture, _output_path, _rows, _session, _valid_native_receipt


@pytest.mark.parametrize(
    "transport_fields",
    [
        {},
        {"guard_remaining_seconds": 0.25},
        {"guard_remaining_ms": 250},
        {"hook_env": {"SYNTHETIC_CAPTURE_HINT": "private"}},
        {"guard_remaining_seconds": 0.25, "guard_remaining_ms": 250, "hook_env": {}},
    ],
)
def test_capture_keeps_raw_and_forwarded_fingerprints_separate_without_raw_content(
    tmp_path: Path, transport_fields: dict[str, object]
) -> None:
    from codex_plugin_scanner.guard.daemon.server import _runtime_hook_remaining_hint

    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)
    raw = {
        "hook_event_name": "PreToolUse",
        "tool_use_id": "call-1",
        "tool_input": {"command": "echo SECRET_COMMAND"},
        **transport_fields,
    }
    forwarded = {**raw, "guard_browser_wait_pid": 17}
    native_payload = dict(forwarded)
    _runtime_hook_remaining_hint(native_payload)
    native_payload.pop("hook_env", None)
    receipt = _valid_native_receipt()

    assert record_bridge_ingress(
        guard_home=guard_home,
        raw_payload=json.dumps(raw),
        forwarded_payload=json.dumps(forwarded),
        event_name="PreToolUse",
    )
    assert record_native_worker(
        guard_home=guard_home,
        payload=native_payload,
        harness="codex",
        event_name="PreToolUse",
        receipt=receipt,
    )

    output = _output_path(directory).read_text(encoding="utf-8")
    assert "SECRET_COMMAND" not in output
    rows = _rows(directory)
    assert rows[0]["raw_payload_hmac_sha256"] != rows[0]["forwarded_payload_hmac_sha256"]
    assert rows[0]["forwarded_payload_hmac_sha256"] == rows[1]["forwarded_payload_hmac_sha256"]
    assert rows[1]["decision_scope"] == "native_edge"
    sealed = cast(dict[str, object], rows[1]["sealed_receipt"])
    decrypted = open_receipt(_session(guard_home), rows[1], sealed)
    assert decrypted is not None
    assert decrypted["request_digest"] == "a" * 64
    assert "request_digest" not in rows[1]
    assert join_binding_records(rows, capture_session=_session(guard_home))["status"] == "bound"


def test_prompt_risk_receipt_round_trip_preserves_later_capture(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)
    receipt = _valid_native_receipt()
    receipt["event_name"] = "UserPromptSubmit"
    receipt["prompt_risk_classes"] = ["sensitive_material", "exfil_intent"]
    receipt["decision_id"] = hashlib.sha256(canonical_receipt_bytes(receipt)).hexdigest()
    assert record_native_worker(
        guard_home=guard_home,
        payload={"hook_event_name": "UserPromptSubmit", "prompt": "synthetic prompt"},
        harness="codex",
        event_name="UserPromptSubmit",
        receipt=receipt,
    )
    first_row = _rows(directory)[0]
    reopened = open_receipt(_session(guard_home), first_row, cast(dict[str, object], first_row["sealed_receipt"]))
    assert reopened == receipt
    assert record_bridge_ingress(
        guard_home=guard_home,
        raw_payload='{"hook_event_name":"PreToolUse","tool_use_id":"later-call"}',
        event_name="PreToolUse",
    )
    rows = _rows(directory)
    assert len(rows) == 2
    assert (
        valid_existing_records(
            _output_path(directory).read_bytes(), run_id="run-1", capture_session=_session(guard_home)
        )
        == 2
    )
    assert join_binding_records(rows, capture_session=_session(guard_home))["status"] != "invalid"
