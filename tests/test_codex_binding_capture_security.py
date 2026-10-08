"""Bounded, opt-in Codex ingress to native-edge receipt diagnostics."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from types import MethodType, SimpleNamespace
from typing import cast

import pytest

from codex_plugin_scanner.guard.codex_binding_capture import (
    CAPTURE_SCHEMA,
    join_binding_records,
    record_bridge_ingress,
    record_native_worker,
)
from codex_plugin_scanner.guard.codex_binding_capture_crypto import (
    new_capture_session,
    open_receipt,
    row_aad,
    row_hmac,
)
from tests.codex_binding_capture_support import (
    _capture_pair,
    _enable_capture,
    _output_path,
    _rows,
    _session,
    _valid_native_receipt,
)


def test_keyed_rows_hide_secret_material_and_unkeyed_dictionary_digests(tmp_path: Path) -> None:
    guard_home, rows = _capture_pair(tmp_path)
    session = _session(guard_home)
    serialized = json.dumps(rows, sort_keys=True)
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_use_id": "call-security",
        "tool_input": {"command": "echo synthetic-secret"},
    }
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    unkeyed_digest = hashlib.sha256(canonical).hexdigest()
    marker_key = base64.urlsafe_b64encode(session.key).decode("ascii")
    assert "synthetic-secret" not in serialized
    assert unkeyed_digest not in serialized
    assert marker_key not in serialized
    assert all(
        field not in serialized
        for field in (
            "request_digest",
            "decision_id",
            "reviewed_output_sha256",
            "raw_payload_sha256",
            "forwarded_payload_sha256",
        )
    )
    assert rows[0]["raw_payload_hmac_sha256"] != rows[0]["forwarded_payload_hmac_sha256"]


def test_join_requires_same_run_key_and_rejects_missing_rotation_or_expiry(tmp_path: Path) -> None:
    guard_home, rows = _capture_pair(tmp_path)
    session = _session(guard_home)
    assert join_binding_records(rows)["status"] == "unbound"
    missing_issues = cast(list[dict[str, object]], join_binding_records(rows)["issues"])
    assert all(item["reason"] == "missing_capture_key" for item in missing_issues)

    wrong_key = replace(session, key=b"w" * 32)
    assert join_binding_records(rows, capture_session=wrong_key)["status"] == "unbound"
    rotated = new_capture_session("run-1", expires_at=int(time.time()) + 300)
    assert rotated is not None
    assert join_binding_records(rows, capture_session=rotated)["status"] == "unbound"
    cross_run = new_capture_session("different-run", expires_at=int(time.time()) + 300)
    assert cross_run is not None
    assert join_binding_records(rows, capture_session=cross_run)["status"] == "unbound"
    expired = replace(session, expires_at=int(time.time()) - 1)
    assert join_binding_records(rows, capture_session=expired)["status"] == "unbound"


def test_row_mac_and_aead_tampering_never_bind(tmp_path: Path) -> None:
    guard_home, rows = _capture_pair(tmp_path)
    session = _session(guard_home)
    row_tampered = [dict(row) for row in rows]
    row_tampered[0]["forwarded_payload_hmac_sha256"] = "f" * 64
    result = join_binding_records(row_tampered, capture_session=session)
    assert result["status"] == "unbound"
    assert result["issues"] == [{"status": "unbound", "reason": "row_mac_mismatch"}]

    aead_tampered = [dict(row) for row in rows]
    sealed = dict(cast(dict[str, object], aead_tampered[1]["sealed_receipt"]))
    ciphertext = str(sealed["ciphertext_b64"])
    sealed["ciphertext_b64"] = ("A" if ciphertext[0] != "A" else "B") + ciphertext[1:]
    aead_tampered[1]["sealed_receipt"] = sealed
    refreshed_mac = row_hmac(session, aead_tampered[1])
    assert refreshed_mac is not None
    aead_tampered[1]["row_mac"] = refreshed_mac
    assert join_binding_records(aead_tampered, capture_session=session)["status"] == "invalid"


@pytest.mark.parametrize(
    "plaintext",
    [
        pytest.param(b'{"nested":' + b"[" * 1100 + b"0" + b"]" * 1100 + b"}", id="parser-recursion"),
        pytest.param(b'{"nested":' + b"[" * 65 + b"0" + b"]" * 65 + b"}", id="structural-depth"),
        pytest.param(b'{"nodes":[' + b"0," * 4096 + b"0]}", id="structural-nodes"),
    ],
)
def test_authenticated_malformed_receipt_plaintext_fails_closed(tmp_path: Path, plaintext: bytes) -> None:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    guard_home, rows = _capture_pair(tmp_path)
    session = _session(guard_home)
    aad = row_aad(rows[1])
    assert aad is not None
    nonce = os.urandom(12)
    ciphertext = AESGCM(session.key).encrypt(nonce, plaintext, aad)
    sealed = {
        "nonce_b64": base64.urlsafe_b64encode(nonce).decode("ascii"),
        "ciphertext_b64": base64.urlsafe_b64encode(ciphertext).decode("ascii"),
    }
    rows[1]["sealed_receipt"] = sealed
    mac = row_hmac(session, rows[1])
    assert mac is not None
    rows[1]["row_mac"] = mac

    assert open_receipt(session, rows[1], sealed) is None
    assert join_binding_records(rows, capture_session=session)["status"] == "invalid"


def test_legacy_and_mixed_capture_rows_are_quarantined_without_migration(tmp_path: Path) -> None:
    guard_home, rows = _capture_pair(tmp_path)
    session = _session(guard_home)
    legacy = dict(rows[0])
    legacy["schema"] = "guard-codex-binding-capture.v1"
    legacy_result = join_binding_records([legacy], capture_session=session)
    assert legacy_result["status"] == "invalid"
    assert legacy_result["issues"] == [{"status": "invalid", "reason": "legacy_capture_schema"}]

    mixed = dict(rows[0])
    mixed["fingerprint_scheme"] = "sha256-unkeyed-v1"
    mixed_result = join_binding_records([mixed], capture_session=session)
    assert mixed_result["status"] == "invalid"
    assert mixed_result["issues"] == [{"status": "invalid", "reason": "record_shape"}]


def test_payload_fingerprint_mismatch_is_not_bound(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)
    raw = {"hook_event_name": "PreToolUse", "tool_use_id": "call-mismatch", "tool_input": {"command": "one"}}
    changed = {**raw, "tool_input": {"command": "two"}}
    assert record_bridge_ingress(
        guard_home=guard_home,
        raw_payload=json.dumps(raw),
        event_name="PreToolUse",
    )
    assert record_native_worker(
        guard_home=guard_home,
        payload=changed,
        harness="codex",
        event_name="PreToolUse",
        receipt=_valid_native_receipt(),
    )
    result = join_binding_records(_rows(directory), capture_session=_session(guard_home))
    assert result["status"] == "invalid"
    assert result["joins"] == [
        {
            "status": "invalid",
            "reason": "payload_fingerprint_mismatch",
            "identity": ("run-1", "codex", "PreToolUse", "call-mismatch"),
        }
    ]


def test_legacy_tool_call_id_is_unbound_without_alias_fallback(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)
    raw = json.dumps({"hook_event_name": "PreToolUse", "tool_call_id": "legacy-call"})
    assert record_bridge_ingress(guard_home=guard_home, raw_payload=raw, event_name="PreToolUse")
    row = _rows(directory)[0]
    assert row["tool_use_id_state"] == "missing"
    assert "tool_use_id" not in row
    assert join_binding_records([row], capture_session=_session(guard_home))["issues"] == [
        {"status": "unbound", "reason": "missing_tool_use_id"}
    ]


@pytest.mark.parametrize(
    "raw",
    [
        '{"hook_event_name":"UserPromptSubmit","prompt":"hello"}',
        '{"hook_event_name":"UserPromptSubmit","tool_use_id":"/private/secret"}',
    ],
)
def test_non_bindable_missing_or_unsupported_id_is_not_applicable(tmp_path: Path, raw: str) -> None:
    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)

    assert record_bridge_ingress(
        guard_home=guard_home,
        raw_payload=raw,
        event_name="UserPromptSubmit",
    )

    result = join_binding_records(_rows(directory), capture_session=_session(guard_home))
    assert result["status"] == "not_applicable"
    assert result["joins"] == []
    assert result["issues"] == [{"status": "not_applicable", "reason": "native_receipt_unsupported_event"}]


def test_missing_id_is_unbound_and_duplicate_rows_are_ambiguous(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)
    missing = '{"hook_event_name":"PreToolUse","tool_input":{"command":"echo hidden"}}'
    assert record_bridge_ingress(guard_home=guard_home, raw_payload=missing, event_name="PreToolUse")
    missing_result = join_binding_records(_rows(directory), capture_session=_session(guard_home))
    assert missing_result["status"] == "unbound"
    assert missing_result["issues"] == [{"status": "unbound", "reason": "missing_tool_use_id"}]

    guard_home = tmp_path / "duplicates"
    directory = _enable_capture(guard_home)
    raw = '{"hook_event_name":"PreToolUse","tool_use_id":"call-duplicate"}'
    assert record_bridge_ingress(guard_home=guard_home, raw_payload=raw, event_name="PreToolUse")
    assert record_bridge_ingress(guard_home=guard_home, raw_payload=raw, event_name="PreToolUse")
    assert join_binding_records(_rows(directory), capture_session=_session(guard_home))["status"] == "ambiguous"


def test_unsupported_id_is_explicitly_unbound_without_echoing_path_content(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)
    secret_path = "/private/secret/path?token=hidden"
    raw = json.dumps(
        {
            "hook_event_name": "PreToolUse",
            "tool_use_id": secret_path,
            "tool_input": {"command": "echo hidden"},
        }
    )

    assert record_bridge_ingress(guard_home=guard_home, raw_payload=raw, event_name="PreToolUse")
    output = _output_path(directory).read_text(encoding="utf-8")
    assert secret_path not in output
    rows = _rows(directory)
    assert rows[0]["tool_use_id_state"] == "unsupported"
    assert join_binding_records(rows, capture_session=_session(guard_home))["issues"] == [
        {"status": "unbound", "reason": "unsupported_tool_use_id"}
    ]


def test_unmanaged_event_label_is_never_persisted_or_joined(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)
    secret_label = "/private/secret/config"
    raw = '{"hook_event_name":"PreToolUse","tool_use_id":"call-event"}'

    assert not record_bridge_ingress(
        guard_home=guard_home,
        raw_payload=raw,
        event_name=secret_label,
    )
    assert not _output_path(directory).exists()

    externally_supplied = {
        "schema": CAPTURE_SCHEMA,
        "run_id": "run-1",
        "route": "bridge_ingress",
        "harness": "codex",
        "event_name": secret_label,
        "tool_use_id_state": "present",
        "tool_use_id": "call-event",
        "raw_payload_sha256": "a" * 64,
    }
    result = join_binding_records([externally_supplied])
    assert result["status"] == "invalid"
    assert result["issues"] == [{"status": "invalid", "reason": "record_shape"}]
    assert secret_label not in json.dumps(result, sort_keys=True)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("route", []),
        ("route", {}),
        ("tool_use_id_state", []),
        ("tool_use_id_state", {}),
        ("harness", "claude-code"),
    ],
)
def test_malformed_external_rows_are_invalid_without_normalizer_or_output_parser_errors(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    row: dict[str, object] = {
        "schema": CAPTURE_SCHEMA,
        "run_id": "run-1",
        "route": "bridge_ingress",
        "harness": "codex",
        "event_name": "PreToolUse",
        "tool_use_id_state": "present",
        "tool_use_id": "call-malformed",
        "raw_payload_sha256": "a" * 64,
    }
    row[field] = value

    result = join_binding_records([row])
    assert result["status"] == "invalid"
    assert result["issues"] == [{"status": "invalid", "reason": "record_shape"}]

    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)
    output = _output_path(directory)
    output.write_text(json.dumps(row, separators=(",", ":")) + "\n", encoding="utf-8")
    output.chmod(0o600)
    assert not record_bridge_ingress(
        guard_home=guard_home,
        raw_payload='{"hook_event_name":"PreToolUse","tool_use_id":"call-next"}',
        event_name="PreToolUse",
    )


def test_malformed_missing_id_row_is_invalid_after_full_shape_validation() -> None:
    row = {
        "schema": CAPTURE_SCHEMA,
        "run_id": "run-1",
        "route": "bridge_ingress",
        "harness": "codex",
        "event_name": "PreToolUse",
        "tool_use_id_state": "missing",
        "raw_payload_sha256": "z" * 64,
        "forwarded_payload_sha256": "a" * 64,
    }

    result = join_binding_records([row])
    assert result["status"] == "invalid"
    assert result["issues"] == [{"status": "invalid", "reason": "record_shape"}]


def test_native_receipt_validation_rejects_forged_or_mismatched_receipt(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)
    payload = {"hook_event_name": "PreToolUse", "tool_use_id": "call-receipt"}
    forged = _valid_native_receipt()
    forged["decision_id"] = "f" * 64
    assert not record_native_worker(
        guard_home=guard_home,
        payload=payload,
        harness="codex",
        event_name="PreToolUse",
        receipt=forged,
    )
    mismatch = _valid_native_receipt()
    mismatch["event_name"] = "PostToolUse"
    assert not record_native_worker(
        guard_home=guard_home,
        payload=payload,
        harness="codex",
        event_name="PreToolUse",
        receipt=mismatch,
    )
    assert not _output_path(directory).exists()


def test_shared_native_worker_defers_capture_after_receipt_acceptance(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.daemon.hook_worker_native import HookWorkerNativeMixin

    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)
    receipt = _valid_native_receipt()
    capture_receipts = []
    edge = {
        "event_name": "PreToolUse",
        "harness": "codex",
        "result": {
            "decision": "allow",
            "minimum_action": "allow",
            "policy_action": "allow",
            "reason_code": "native_allow",
        },
        "receipt": receipt,
    }
    host = SimpleNamespace(
        store=SimpleNamespace(),
        activity_writer=None,
        _last_native_decision_receipt=None,
        _review_raw_hook_native=lambda **_kwargs: edge,
    )
    record_receipt = cast(
        Callable[..., object],
        HookWorkerNativeMixin._record_native_decision_receipt,  # pyright: ignore[reportAttributeAccessIssue]
    )
    host._record_native_decision_receipt = MethodType(record_receipt, host)

    review_native_edge = cast(
        Callable[..., tuple[dict[str, object], bool]],
        HookWorkerNativeMixin._review_native_edge_with_snapshot,  # pyright: ignore[reportAttributeAccessIssue]
    )
    response, native_used = review_native_edge(
        host,
        payload={"hook_event_name": "PreToolUse", "tool_use_id": "call-worker"},
        harness="codex",
        event_name="PreToolUse",
        default_harness="codex",
        home_dir=tmp_path / "home",
        guard_home=guard_home,
        workspace=None,
        deadline=None,
        policy_snapshot=None,
        recording_only=False,
        capture_receipts=capture_receipts,
    )

    assert native_used is True
    assert response["policy_action"] == "allow"
    assert _rows(directory) == []
    assert len(capture_receipts) == 1
    assert capture_receipts[0]["decision_id"] == receipt["decision_id"]
