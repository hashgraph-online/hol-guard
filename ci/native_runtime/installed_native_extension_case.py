"""Run one installed-native extension case and verify its persisted receipt."""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

_RECEIPT_PERSISTENCE_TIMEOUT_SECONDS = 60.0
_ACTION_RANK = {
    "allow": 0,
    "warn": 1,
    "review": 2,
    "require-reapproval": 3,
    "sandbox-required": 4,
    "block": 5,
}


def run_case(
    *,
    label: str,
    command: str,
    revision: int,
    matched: str | None,
    daemon: Any,
    home: Path,
    root: Path,
    workspace: Path,
    store: Any,
    previous_publisher: object | None,
    request: Callable[..., Any],
    rows: list[dict[str, object]],
    all_receipts: list[str],
    ready: Callable[..., dict[str, object]],
    review_raw_hook_native: Callable[..., Any],
    native_resident_client_failure_code: Callable[[], Any],
    persisted_native_receipt_ids: Callable[..., Any],
    receipt_processed_count: Callable[..., Any],
    await_persisted_native_receipt: Callable[..., Any],
    receipt_binding_diagnostic: Callable[..., dict[str, object]],
    policy_request_phase_diagnostic: Callable[..., dict[str, object]],
    require_native_http_admission: Callable[..., None],
    require: Callable[[bool, str], None],
    permission_for_rule_id: Callable[[str], Any],
    minimum: str | None = None,
    minimum_at_least: str | None = None,
    tool_payload: dict[str, object] | None = None,
    permission_id: str | None = None,
    matched_permission_id: str | None = None,
    reason_code: str | None = None,
) -> dict[str, object]:
    binding = ready(daemon, workspace, revision, previous_publisher=previous_publisher, case_label=label)
    publisher = daemon._server.hook_worker.policy_snapshot_publisher

    def emit_phase(phase: str) -> None:
        diagnostic = {"case": label, **policy_request_phase_diagnostic(publisher, phase)}
        print(json.dumps(diagnostic, sort_keys=True), flush=True)

    emit_phase("before_raw")
    payload = tool_payload or {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    }
    payload = {"hook_event_name": "PreToolUse", **payload}
    raw = review_raw_hook_native(
        payload=payload,
        harness="claude-code",
        event="PreToolUse",
        guard_home=home,
        home_dir=root,
        cwd=workspace,
        source_ref_external_allowed=False,
        observe_mode=False,
        deadline=time.monotonic() + 5,
        policy_snapshot=binding,
    )
    if raw is None:
        print(
            json.dumps(
                {
                    "schema": "guard.installed-native-extension-failure.v1",
                    "case": label,
                    "completed_cases": len(rows),
                    "control_revision": revision,
                    "policy_generation": binding["generation"],
                    "native_failure_code": native_resident_client_failure_code(),
                },
                sort_keys=True,
            ),
            flush=True,
        )
    require(raw is not None, f"{label}:native_missing")
    result = raw["result"]
    extensions = result.get("command_extensions")
    require(isinstance(extensions, dict), f"{label}:extension_binding_missing")
    observations = extensions["observations"]
    ids = [row["rule_id"] for row in observations]
    if matched is not None:
        require(matched in ids, f"{label}:owned_rule_missing")
    else:
        require(
            not any(row["extension_id"] == "command.ollama" for row in observations),
            f"{label}:external_not_inert",
        )
    if permission_id is not None:
        require(
            any(row["permission_id"] == permission_id for row in extensions["permission_observations"]),
            f"{label}:owned_permission_missing",
        )
    if matched_permission_id is not None:
        require(matched is not None, f"{label}:matched_permission_rule_missing")
        # Matched-rule permissions are bound through the installed catalog;
        # native permission_observations only reports standalone rows.
        matched_permission = permission_for_rule_id(matched)
        require(matched_permission is not None, f"{label}:matched_permission_mapping_missing")
        require(
            matched_permission.permission_id == matched_permission_id,
            f"{label}:wrong_matched_permission:{matched_permission.permission_id}",
        )
    if minimum is not None:
        require(result["minimum_action"] == minimum, f"{label}:wrong_floor:{result['minimum_action']}")
    if minimum_at_least is not None:
        actual = result["minimum_action"]
        require(
            isinstance(actual, str)
            and actual in _ACTION_RANK
            and minimum_at_least in _ACTION_RANK
            and _ACTION_RANK[actual] >= _ACTION_RANK[minimum_at_least],
            f"{label}:floor_below_{minimum_at_least}:{actual}",
        )
    if reason_code is not None:
        require(result.get("reason_code") == reason_code, f"{label}:wrong_reason:{result.get('reason_code')}")
    require(result["decision"] == "deny", f"{label}:unsafe_allow")
    known_receipt_ids = persisted_native_receipt_ids(store)
    receipt_writer = daemon._server.runtime_hook_evidence_writer
    receipt_processed_value = receipt_processed_count(receipt_writer)
    require(receipt_processed_value is not None, f"{label}:receipt_writer_stats")
    receipt_processed_before = receipt_processed_value
    emit_phase("before_http")
    response = request(daemon, home, workspace, "claude-code", "PreToolUse", payload)
    require(isinstance(response, dict), f"{label}:http_missing")
    emit_phase("after_http")
    require_native_http_admission(response)
    # Compatibility hooks execute in the isolated hook process. Its receipt
    # reaches the parent through the evidence writer, so the parent
    # worker's mutable last-receipt field cannot identify this request.
    # Wait for that asynchronous writer to report successful persistence
    # before querying SQLite, avoiding reader/writer lock churn on Windows.
    receipt = await_persisted_native_receipt(
        store,
        known_receipt_ids,
        writer=receipt_writer,
        receipt_processed_before=receipt_processed_before,
        diagnostic_context={
            "case": label,
            "http_reason_code": response.get("reason_code"),
            "http_decision": response.get("decision"),
        },
        timeout_seconds=_RECEIPT_PERSISTENCE_TIMEOUT_SECONDS,
    )
    require(receipt.get("authority") == "rust", f"{label}:receipt_missing")
    if receipt.get("command_extensions") != extensions["binding"]:
        diagnostic = receipt_binding_diagnostic(response, receipt, extensions["binding"], all_receipts)
        print(json.dumps({"case": label, "completed_cases": len(rows), **diagnostic}, sort_keys=True), flush=True)
    require(receipt.get("command_extensions") == extensions["binding"], f"{label}:receipt_generation_mismatch")
    require(receipt["decision"] == result["decision"], f"{label}:http_decision_mismatch")
    if reason_code is not None:
        require(receipt.get("reason_code") == reason_code, f"{label}:receipt_wrong_reason")
    all_receipts.append(receipt["decision_id"])
    rows.append(
        {
            "case": label,
            "control_revision": revision,
            "decision": receipt["decision"],
            "minimum_action": result["minimum_action"],
            "rule_ids": ids,
            "permission_ids": [row["permission_id"] for row in extensions["permission_observations"]],
            "matched_permission_id": matched_permission_id,
            "observations": extensions["binding"]["observation_count"],
        }
    )
    return extensions
