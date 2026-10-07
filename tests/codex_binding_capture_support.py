"""Bounded, opt-in Codex ingress to native-edge receipt diagnostics."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from codex_plugin_scanner.guard.codex_binding_capture import (
    CAPTURE_MARKER_NAME,
    CAPTURE_OUTPUT_PREFIX,
    CAPTURE_OUTPUT_SUFFIX,
    initialize_capture_marker,
    read_capture_session,
    record_bridge_ingress,
    record_native_worker,
)
from codex_plugin_scanner.guard.native_decision_receipt import canonical_receipt_bytes


def _enable_capture(
    guard_home: Path,
    *,
    run_id: str = "run-1",
    expires_at: int | None = None,
    max_records: int = 16,
    max_bytes: int = 64 * 1024,
) -> Path:
    directory = guard_home / "diagnostics"
    guard_home.mkdir(mode=0o700, parents=True, exist_ok=True)
    guard_home.chmod(0o700)
    requested_expiry = int(time.time()) + 300 if expires_at is None else expires_at
    session_expiry = requested_expiry if requested_expiry > int(time.time()) else int(time.time()) + 300
    session = initialize_capture_marker(
        guard_home,
        run_id=run_id,
        expires_at=session_expiry,
        max_records=max_records,
        max_bytes=max_bytes,
    )
    assert session is not None
    if requested_expiry != session_expiry:
        marker = directory / CAPTURE_MARKER_NAME
        marker_payload = json.loads(marker.read_text(encoding="utf-8"))
        marker_payload["expires_at"] = requested_expiry
        marker.write_text(json.dumps(marker_payload, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        marker.chmod(0o600)
    return directory


def _valid_native_receipt() -> dict[str, object]:
    receipt: dict[str, object] = {
        "schema": "guard-native-hook-decision-receipt.v1",
        "version": 1,
        "authority": "rust",
        "decision_id": "0" * 64,
        "request_id": "sha256:request-1",
        "request_digest": "a" * 64,
        "harness": "codex",
        "event_name": "PreToolUse",
        "payload_kind": "inline",
        "policy_generation": 1,
        "policy_digest": None,
        "rule_digest": None,
        "runtime_identity": None,
        "decision": "allow",
        "model_output_action": "not_applicable",
        "policy_action": "allow",
        "observed_policy_action": None,
        "reason_code": "native_allow",
        "workspace_bound": False,
        "source_ref_external_allowed": False,
        "reviewed_output_sha256": None,
        "observe_mode": False,
        "deadline_budget_ms": 100,
    }
    receipt["decision_id"] = hashlib.sha256(canonical_receipt_bytes(receipt)).hexdigest()
    return receipt


def _session(guard_home: Path):
    session = read_capture_session(guard_home)
    assert session is not None
    return session


def _output_path(directory: Path, run_id: str = "run-1") -> Path:
    return directory / f"{CAPTURE_OUTPUT_PREFIX}{run_id}{CAPTURE_OUTPUT_SUFFIX}"


def _rows(directory: Path, run_id: str = "run-1") -> list[dict[str, object]]:
    path = _output_path(directory, run_id)
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _capture_pair(tmp_path: Path) -> tuple[Path, list[dict[str, object]]]:
    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_use_id": "call-security",
        "tool_input": {"command": "echo synthetic-secret"},
    }
    assert record_bridge_ingress(
        guard_home=guard_home,
        raw_payload=json.dumps(payload),
        event_name="PreToolUse",
    )
    assert record_native_worker(
        guard_home=guard_home,
        payload=payload,
        harness="codex",
        event_name="PreToolUse",
        receipt=_valid_native_receipt(),
    )
    return guard_home, _rows(directory)
