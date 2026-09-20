"""Check actual Rust non-command receipts through the Python approval consumer.

Input is three exact JSONL records emitted by the authenticated Rust store test.
The caller must bind their bytes to the fresh test executable, Cargo build,
original unit log and current source before invoking this separate control.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

from codex_plugin_scanner.guard.daemon.hook_native_review_approval import pause_native_pre_tool_for_approval
from codex_plugin_scanner.guard.daemon.hook_native_review_binding import native_review_policy_binding
from codex_plugin_scanner.guard.native_decision_receipt import receipt_matches_edge, validate_native_decision_receipt
from codex_plugin_scanner.guard.native_hook_edge import _decode_edge
from codex_plugin_scanner.guard.store import GuardStore

SCHEMA = "pr2974.native-non-command-review-evidence.v1"
LABELS = ("WebFetch", "Read", "MCP")
EXPECTED = {
    "WebFetch": ("WebFetch", "network", "native_network_review", {"url": "https://example.com/docs"}),
    "Read": ("Read", "file_read", "native_file_read_review", {"file_path": ".env"}),
    "MCP": ("mcp__filesystem__read", "mcp_tool", "native_mcp_tool_review", {"path": "README.md"}),
}
OMITTED_KEYS = {
    "event",
    "eventName",
    "hook_event_name",
    "hookEventName",
    "hook_name",
    "hookName",
    "timestamp",
    "timestamp_ms",
    "timestampMs",
    "created_at",
    "createdAt",
    "received_at",
    "receivedAt",
}
MAX_RECORD_BYTES = 64 * 1024
MAX_REPORT_BYTES = 512 * 1024


def _object(value: object) -> dict[str, Any]:
    assert type(value) is dict and all(type(key) is str for key in value)
    return cast(dict[str, Any], value)


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise ValueError(f"nonfinite JSON constant: {value}")


def _parse(value: str) -> dict[str, Any]:
    return _object(json.loads(value, object_pairs_hook=_pairs, parse_constant=_constant))


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _save(path: Path, state: dict[str, Any]) -> None:
    encoded = json.dumps(state, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"
    if len(encoded) > MAX_REPORT_BYTES:
        raise ValueError("native consumer report bound exceeded")
    path.write_bytes(encoded)


def _failure(error: BaseException) -> dict[str, Any]:
    original = traceback.format_exc()
    raw = original.encode("utf-8")
    tail = original[-8192:]
    sys.stderr.write(original)
    sys.stderr.flush()
    return {
        "error": {"type": type(error).__name__, "message": str(error)},
        "traceback": tail,
        "traceback_integrity": {
            "original_bytes": len(raw),
            "original_sha256": hashlib.sha256(raw).hexdigest(),
            "retained_tail_bytes": len(tail.encode("utf-8")),
            "tail_truncated": tail != original,
            "complete_original_written_to_command_stderr": True,
        },
    }


def _records(path: Path, expected_sha256: str) -> tuple[bytes, list[dict[str, Any]], list[str]]:
    assert re.fullmatch(r"[0-9a-f]{64}", expected_sha256)
    assert path.is_file() and not path.is_symlink()
    with path.open("rb") as handle:
        raw = handle.read(3 * (MAX_RECORD_BYTES + 1) + 1)
    assert len(raw) <= 3 * (MAX_RECORD_BYTES + 1)
    assert hashlib.sha256(raw).hexdigest() == expected_sha256
    assert raw.endswith(b"\n")
    lines = raw.split(b"\n")
    assert len(lines) == 4 and lines[-1] == b""
    records: list[dict[str, Any]] = []
    hashes: list[str] = []
    for label, line in zip(LABELS, lines[:-1], strict=True):
        assert 0 < len(line) <= MAX_RECORD_BYTES
        record = _parse(line.decode("utf-8", errors="strict"))
        assert set(record) == {"schema", "label", "envelope", "active_snapshot", "edge_json"}
        assert record["schema"] == SCHEMA and record["label"] == label
        records.append(record)
        hashes.append(hashlib.sha256(line).hexdigest())
    return raw, records, hashes


def _request_digest(envelope: dict[str, Any]) -> str:
    policy = _object(envelope["policy_snapshot"])
    scope = _object(policy.get("scope_contract", {}))
    payload = _object(envelope["raw_payload"])
    identity = {
        "event": envelope["event"],
        "harness": envelope["harness"],
        "payload": {key: value for key, value in payload.items() if key not in OMITTED_KEYS},
        "policy": {
            "generation": envelope["policy_generation"],
            "policy_digest": policy["policy_digest"],
            "rule_digest": policy.get("rule_digest"),
            "runtime_identity": policy["runtime_identity"],
            "scope_digest": scope.get("scope_digest"),
        },
        "schema": "guard-native-request-identity.v3",
        "source": envelope["source"],
        "version": 3,
    }
    return hashlib.sha256(_canonical(identity)).hexdigest()


def _native_case(record: dict[str, Any]) -> dict[str, Any]:
    label = record["label"]
    tool, action, reason, tool_input = EXPECTED[label]
    envelope = _object(record["envelope"])
    snapshot = _object(record["active_snapshot"])
    source = _object(envelope["source"])
    payload = _object(envelope["raw_payload"])
    assert envelope["schema"] == "guard-hook-envelope.v2"
    assert envelope["harness"] == "cursor" and envelope["event"] == "PreToolUse"
    assert envelope["request_id"] is None
    assert envelope["deadline_budget_ms"] == 750
    assert envelope["policy_snapshot"] == {
        field: snapshot[field] for field in ("generation", "policy_digest", "runtime_identity")
    }
    assert envelope["policy_generation"] == snapshot["generation"] == 1
    assert snapshot["mode"] == "enforce"
    assert set(source) == {"cwd", "home_dir", "guard_home", "source_ref_external_allowed"}
    assert source["source_ref_external_allowed"] is False
    assert all(
        type(source[key]) is str and Path(source[key]).is_absolute() for key in ("cwd", "home_dir", "guard_home")
    )
    assert source["home_dir"] == source["guard_home"]
    assert Path(source["cwd"]) == Path(source["guard_home"]) / "workspace"
    assert payload == {"tool_name": tool, "tool_input": tool_input}
    edge_json = record["edge_json"]
    assert type(edge_json) is str and len(edge_json.encode("utf-8")) <= MAX_RECORD_BYTES
    edge = _parse(edge_json)
    assert edge["schema"] == "guard-hook-edge-result.v2" and edge["authority"] == "rust"
    assert edge["harness"] == "cursor" and edge["event_name"] == "PreToolUse" and edge["payload_kind"] == "inline"
    assert _decode_edge(edge) == edge
    result = _object(edge["result"])
    assert result["authority"] == "rust" and result["schema"] == "guard-pre-tool-result.v1"
    assert result["decision"] == "deny" and result["minimum_action"] == result["policy_action"] == "review"
    assert result["reason_code"] == reason and _object(result["action"])["action_type"] == action
    controls = _object(snapshot["command_extensions"])
    assert controls["health"] == "protected" and controls["revision"] == controls["managed_revision"] == 1
    assert "command_extensions" not in result
    receipt = validate_native_decision_receipt(edge["receipt"])
    assert receipt is not None and receipt == edge["receipt"] and receipt_matches_edge(edge, receipt)
    assert receipt["review_scope"] == "noncommand" and "command_extensions" not in receipt
    assert receipt["policy_generation"] == snapshot["generation"]
    for field in ("policy_digest", "rule_digest", "runtime_identity"):
        assert receipt[field] == snapshot[field]
    assert receipt["workspace_bound"] is True and receipt["source_ref_external_allowed"] is False
    assert receipt["deadline_budget_ms"] == envelope["deadline_budget_ms"]
    digest = _request_digest(envelope)
    assert receipt["request_digest"] == digest and receipt["request_id"] == f"sha256:{digest}"
    assert edge["request_id"] == receipt["request_id"]
    expected_binding = {
        "schema": "guard.native-review-policy-binding.v2",
        "review_scope": "noncommand",
        **{
            field: receipt[field]
            for field in (
                "policy_generation",
                "policy_digest",
                "rule_digest",
                "runtime_identity",
                "request_digest",
                "harness",
                "event_name",
                "payload_kind",
                "workspace_bound",
                "source_ref_external_allowed",
            )
        },
        "action_type": action,
        "operation": _object(result["action"])["operation"],
    }
    binding = native_review_policy_binding(
        harness="cursor",
        native_result=result,
        verified_receipt=receipt,
        policy_snapshot=snapshot,
        workspace_bound=True,
    )
    assert binding == expected_binding
    return {
        "edge": edge,
        "result": result,
        "receipt": receipt,
        "source": source,
        "snapshot": snapshot,
        "payload": payload,
        "binding": binding,
        "request_digest": digest,
        "expected_artifact_hash": f"native-review-v4:{digest}:deny:review:review:{reason}",
        "edge_bytes": len(edge_json.encode("utf-8")),
        "edge_sha256": hashlib.sha256(edge_json.encode("utf-8")).hexdigest(),
    }


def _consume(record: dict[str, Any], store_root: Path) -> dict[str, Any]:
    original = _canonical(record)
    native = _native_case(record)
    source, receipt, result = native["source"], native["receipt"], native["result"]
    store = GuardStore(store_root / record["label"])
    arguments: dict[str, Any] = {
        "harness": "cursor",
        "payload": native["payload"],
        "native_result": result,
        "workspace": Path(source["cwd"]),
        "guard_home": Path(source["guard_home"]),
        "home_dir": Path(source["home_dir"]),
        "policy_snapshot": native["snapshot"],
    }
    # The exact original request/source remain unchanged; only the test store
    # lives under the caller's fresh owned root, separate from the Rust store.
    missing = pause_native_pre_tool_for_approval(store, **arguments, native_receipt=None)
    assert missing["policy_action"] == "block" and missing["reason_code"] == "native_review_policy_binding_invalid"
    assert store.list_approval_requests(status="pending") == []
    refused_snapshots = []
    for snapshot in (None, {**native["snapshot"], "generation": native["snapshot"]["generation"] + 1}):
        changed = arguments.copy()
        changed["policy_snapshot"] = snapshot
        refused = pause_native_pre_tool_for_approval(store, **changed, native_receipt=receipt, verified_receipt=receipt)
        assert refused["policy_action"] == "block" and refused["reason_code"] == "native_review_policy_binding_invalid"
        assert store.list_approval_requests(status="pending") == []
        refused_snapshots.append(refused)
    with store._connect() as connection:
        assert connection.execute("select version from schema_migrations where version = 29").fetchone()[0] == 29
        assert connection.execute("select count(*) from native_hook_review_scopes").fetchone()[0] == 0
    assert store.record_native_decision_receipt(receipt) is True
    persisted = store.get_native_decision_receipt(receipt["decision_id"])
    assert persisted == receipt and store.native_decision_receipt_count() == 1
    with store._connect() as connection:
        assert (
            connection.execute(
                "select review_scope from native_hook_review_scopes where decision_id = ?", (receipt["decision_id"],)
            ).fetchone()[0]
            == "noncommand"
        )
        connection.execute("delete from native_hook_review_scopes where decision_id = ?", (receipt["decision_id"],))
    assert store.get_native_decision_receipt(receipt["decision_id"]) is None
    assert store.record_native_decision_receipt(receipt) is True
    assert store.get_native_decision_receipt(receipt["decision_id"]) == persisted
    assert store.native_decision_receipt_count() == 1
    response = pause_native_pre_tool_for_approval(
        store, **arguments, native_receipt=persisted, verified_receipt=receipt
    )
    assert response["policy_action"] == "review" and response["prompted"] is True
    assert _object(response["hookSpecificOutput"])["permissionDecision"] == "ask"
    assert response["reason_code"] == result["reason_code"]
    request_id = response["approval_request_id"]
    assert type(request_id) is str
    pending = store.list_approval_requests(status="pending")
    assert len(pending) == 1 and pending[0]["request_id"] == request_id
    row = store.get_approval_request(request_id)
    assert row is not None and row["artifact_hash"] == native["expected_artifact_hash"]
    assert row["workspace"] == source["cwd"]
    action_envelope = _object(row["action_envelope_json"])
    assert action_envelope["native_review_policy_binding"] == native["binding"]
    assert action_envelope["tool_name"] == native["payload"]["tool_name"]
    now = datetime.now(timezone.utc).isoformat()
    assert store.resolve_harness_native_approval_request(
        request_id, reason="bounded actual native receipt consumer", resolved_at=now, expected_harness="cursor"
    )
    reused = pause_native_pre_tool_for_approval(store, **arguments, native_receipt=persisted, verified_receipt=receipt)
    assert reused["policy_action"] == "allow" and reused["approval_reuse_status"] == "accepted"
    replay = pause_native_pre_tool_for_approval(store, **arguments, native_receipt=persisted, verified_receipt=receipt)
    assert replay["policy_action"] == "review" and replay["prompted"] is True
    assert replay.get("approval_reuse_status") != "accepted"
    assert len(store.list_approval_requests(status="pending")) == 1
    assert _canonical(record) == original
    return {
        "edge_bytes": native["edge_bytes"],
        "edge_sha256": native["edge_sha256"],
        "request_digest": native["request_digest"],
        "receipt": persisted,
        "policy_binding": native["binding"],
        "approval_row": row,
        "missing_binding_response": missing,
        "missing_or_changed_snapshot_responses": refused_snapshots,
        "review_response": response,
        "one_use_allow_response": reused,
        "replay_review_response": replay,
        "original_record_unchanged": True,
        "checks": {
            "actual_native_edge_receipt_and_v3_request": True,
            "current_snapshot_explicit_noncommand_v2_domain": True,
            "missing_or_changed_selected_ack_refused_before_queue": True,
            "real_migration29_scope_sidecar_and_missing_marker_refusal": True,
            "missing_verified_receipt_refused_before_queue": True,
            "real_receipt_sqlite_roundtrip": True,
            "real_pending_approval_binding": True,
            "one_use_native_request_retry": True,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--records", required=True, type=Path)
    parser.add_argument("--records-sha256", required=True)
    parser.add_argument("--store-root", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    state: dict[str, Any] = {
        "schema": "pr2974.native-non-command-python-consumer.v2",
        "status": "started",
        "passed": False,
        "declared_cases": list(LABELS),
        "cases": [],
        "records_sha256": args.records_sha256,
        "scope": "actual native unit output through typed receipt, SQLite and pause/queue/retry",
        "full_http_worker_exercised": False,
        "installed_qualification": False,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    _save(args.report, state)
    try:
        raw, records, hashes = _records(args.records, args.records_sha256)
        state["records_bytes"] = len(raw)
        root = args.store_root
        assert root.is_absolute() and root.parent.resolve(strict=True) == root.parent
        assert not root.exists() and not root.is_symlink()
        root.mkdir(mode=0o700)
        for index, record in enumerate(records):
            case: dict[str, Any] = {
                "index": index,
                "label": record["label"],
                "record_sha256": hashes[index],
                "passed": False,
            }
            state["cases"].append(case)
            _save(args.report, state)
            try:
                case["result"] = _consume(record, root)
                case["passed"] = True
            except BaseException as error:
                case.update(_failure(error))
            _save(args.report, state)
        assert _records(args.records, args.records_sha256)[0] == raw
        state["records_unchanged"] = True
        state["completed_cases"] = len(state["cases"])
        state["passed_cases"] = sum(case["passed"] is True for case in state["cases"])
        state["passed"] = state["completed_cases"] == state["passed_cases"] == 3
        state["status"] = "completed"
    except BaseException as error:
        state["status"] = "error"
        state["passed"] = False
        state.update(_failure(error))
    _save(args.report, state)
    return 0 if state["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
