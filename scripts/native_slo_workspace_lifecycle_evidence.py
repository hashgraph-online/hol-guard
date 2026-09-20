"""Retain exact bounded lifecycle proofs beside a small aggregate summary.

The generic SLO sanitizer intentionally removes receipt schema fields. Only
the summary passes through it; independently validated receipts, authority
projections and publication spans are stored as exact JSON in the private
ledger. A rejected proof produces no partial ledger records.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any, cast

from scripts.native_slo_contract import SAFE_ROUTE_NAMES, assert_privacy_safe
from scripts.native_slo_workspace_decision import MAX_REQUESTS, authority_projection, finite_time, join_decisions
from scripts.native_slo_workspace_lifecycle_clocks import valid_lifecycle_clocks
from scripts.native_slo_workspace_lifecycle_evidence_schema import (
    _ACK_FLAGS,
    _ATTEMPT,
    _CONTROLS,
    _DIGEST,
    _EXPIRY_FLAGS,
    _FACT_FIELDS,
    _FAILURE_FIELDS,
    _HINT_FLAGS,
    _KEY_FLAGS,
    _LIFECYCLE_COUNTS,
    _OBSERVATION_COUNTS,
    _PROOF_FIELDS,
    _PUBLICATION_FIELDS,
    _REQUEST_EXTRA,
    _ROW_COUNTS,
    _ROW_FLAGS,
    _ROW_OTHER,
    _ROW_TIMES,
    _SCOPE_CHECKS,
    _SERVICE_FLAGS,
    _SPAN_COMMON,
    _SPAN_FIELDS,
    _WITNESS_COUNTS,
    EVIDENCE_SCHEMA,
    MAX_CELL_BYTES,
    PART_CHARS,
)
from scripts.native_slo_workspace_observer import MAX_EVENTS, public_binding
from scripts.native_slo_workspace_trace import phase_chain, validate_trace


def _require(condition: bool) -> None:
    if not condition:
        raise ValueError("workspace lifecycle evidence schema or bound invalid")


def _count(value: object) -> bool:
    return type(value) is int and 0 <= value < 2**63


def _flags(value: dict[str, Any], fields: set[str]) -> None:
    _require(all(type(value.get(key)) is bool for key in fields))


def _bounded_copy(value: object) -> Any:
    remaining = 65_536

    def visit(item: object, depth: int = 0) -> None:
        nonlocal remaining
        remaining -= 1
        _require(remaining >= 0 and depth <= 12)
        if item is None or type(item) is bool:
            return
        if type(item) in (int, float):
            _require(finite_time(item) and -(2**64) < item < 2**64)
        elif type(item) is str:
            _require(len(item) <= 256 and "\x00" not in item)
        elif type(item) is dict:
            _require(len(item) <= 256 and all(type(key) is str and len(key) <= 64 for key in item))
            for child in item.values():
                visit(child, depth + 1)
        elif type(item) is list:
            _require(len(item) <= 256)
            for child in item:
                visit(child, depth + 1)
        else:
            _require(False)

    visit(value)
    return json.loads(json.dumps(value, allow_nan=False))


def _authority(value: object) -> None:
    _require(type(value) is dict)
    value = cast(dict[str, Any], value)
    controls = value.get("command_controls")
    _require(type(controls) is dict and set(controls) == set(_CONTROLS))
    controls = cast(dict[str, Any], controls)
    reconstructed = authority_projection(
        {**value, "command_extensions": {source: controls[target] for target, source in _CONTROLS.items()}}
    )
    _require(reconstructed == value)


def _request_row(row: object, count: int) -> None:
    from codex_plugin_scanner.guard.native_decision_receipt import validate_native_decision_receipt

    _require(type(row) is dict and set(row) <= _ROW_FLAGS | _ROW_COUNTS | _ROW_TIMES | _ROW_OTHER)
    row = cast(dict[str, Any], row)
    _require(type(row.get("attempt")) is str and _ATTEMPT.fullmatch(row["attempt"]) is not None)
    _require(type(row.get("workspace_index")) is int and 0 <= row["workspace_index"] < count)
    for key, value in row.items():
        if key in _ROW_FLAGS:
            _require(value is None or type(value) is bool)
        elif key in _ROW_COUNTS:
            _require(value is None or _count(value))
        elif key in _ROW_TIMES:
            _require(value is None or (finite_time(value) and -(2**63) < value < 2**63))
        elif key in {"authority_before", "authority_after"} and value is not None:
            _authority(value)
        elif key == "request_binding" and value is not None:
            _require(public_binding(value) == value)
        elif key in {"native_receipt", "committed_receipt"} and value is not None:
            _require(validate_native_decision_receipt(value) == value)
        elif key == "request_mode":
            _require(value in (None, "enforce", "observe"))
        elif key == "delivered_decision":
            _require(value in (None, "allow", "deny"))
        elif key == "witness_decision_id":
            _require(value is None or (type(value) is str and _DIGEST.fullmatch(value) is not None))


def _requests(value: object, count: int) -> dict[str, Any]:
    requests = _bounded_copy(value)
    _require(type(requests) is dict and set(requests) >= _REQUEST_EXTRA)
    requests = cast(dict[str, Any], requests)
    rows = requests["actual_request_rows"]
    _require(type(rows) is list and len(rows) <= MAX_REQUESTS)
    rows = cast(list[dict[str, Any]], rows)
    for row in rows:
        _request_row(row, count)
    _authority(requests.get("authority"))
    _require(type(requests.get("observation_complete")) is bool)
    expected = join_decisions(
        rows,
        authority=requests["authority"],
        action="allow",  # Every recovered lifecycle probe has the unchanged allow policy.
        accepted_ms=requests["accepted_ms"],
        declared_attempts=requests["declared_attempts"],
        observation_complete=requests["observation_complete"],
    )
    _require(set(requests) == set(expected) | _REQUEST_EXTRA)
    _require(all(requests[key] == expected[key] for key in expected))
    offered = [row["attempt"] for row in rows]
    _require(requests["owned_offered_attempts"] == offered)
    _require(
        requests["undeclared_owned_attempts"] == [item for item in offered if item not in requests["declared_attempts"]]
    )
    witness = requests["receipt_witness"]
    _require(type(witness) is dict and set(witness) == _WITNESS_COUNTS | {"observations"})
    witness = cast(dict[str, Any], witness)
    _require(all(_count(witness[key]) for key in _WITNESS_COUNTS))
    observations = witness["observations"]
    _require(type(observations) is dict and set(observations) <= _OBSERVATION_COUNTS)
    observations = cast(dict[str, Any], observations)
    _require(all(_count(item) for item in observations.values()))
    lifecycle = requests["observation_lifecycle"]
    _require(type(lifecycle) is dict and set(lifecycle) == _LIFECYCLE_COUNTS | {"owned_wrapper_restored"})
    lifecycle = cast(dict[str, Any], lifecycle)
    _require(all(item is None or _count(item) for key, item in lifecycle.items() if key in _LIFECYCLE_COUNTS))
    _require(type(lifecycle["owned_wrapper_restored"]) is bool)
    _require(_count(requests["unowned_native_calls_excluded"]))
    clocks = requests["clock_sources"]
    _require(type(clocks) is dict and set(clocks) == {"monotonic", "wall"})
    clocks = cast(dict[str, Any], clocks)
    _require(clocks["monotonic"] in {"time.monotonic", "injected_control_clock"})
    _require(clocks["wall"] in {"time.time", "injected_control_clock"})
    bound = requests["receipt_bound"]
    _require(type(bound) is dict and set(bound) == {"requests", "bytes_per_validated_receipt"})
    bound = cast(dict[str, Any], bound)
    _require(type(bound["requests"]) is int and max(1, len(rows)) <= bound["requests"] <= MAX_REQUESTS)
    _require(bound["bytes_per_validated_receipt"] == 16 * 1024)
    _require(
        requests["readback_scope"] == "caller-side sequential SQL counts and validated getter, not atomic commit time"
    )
    return requests


def _publication(result: Mapping[str, Any], count: int) -> dict[str, Any]:
    proof = _bounded_copy({key: result[key] for key in _PUBLICATION_FIELDS if key in result})
    rows = proof.get("publication_rows", [])
    _require(type(rows) is list and len(rows) <= MAX_EVENTS)
    rows = cast(list[dict[str, Any]], rows)
    for row in rows:
        _require(type(row) is dict and row.get("kind") in _SPAN_FIELDS)
        _require(set(row) == _SPAN_COMMON | _SPAN_FIELDS[row["kind"]])
        for key, value in row.items():
            if key == "kind":
                continue
            if key == "binding":
                _require(value is None or public_binding(value) == value)
            elif key == "scope_loads":
                _require(type(value) is list and len(value) == count + 1 and all(_count(item) for item in value))
            elif key in {"succeeded", "scope_counts_overflow", "returned", "validated", "ready"}:
                _require(type(value) is bool)
            elif key.endswith("_ms"):
                _require(finite_time(value) and 0 <= value < 2**63)
            else:
                _require(value is None or _count(value))
    if "publication_observer" in proof:
        report = proof["publication_observer"]
        _require(
            type(report) is dict
            and set(report)
            == {
                "events",
                "event_bound",
                "counts",
                "event_digest",
                "complete",
                "calls_in_flight_at_freeze",
                "timing_scope",
                "thread_cpu_scope",
                "headline_timing_eligible",
            }
        )
        report = cast(dict[str, Any], report)
        _require(
            type(report["counts"]) is dict
            and set(report["counts"]) <= set(_SPAN_FIELDS) | {"overflow", "scope_overflow"}
        )
        _require(all(_count(item) for item in report["counts"].values()))
        _require(type(report["complete"]) is bool and report["headline_timing_eligible"] is False)
        _require(report["calls_in_flight_at_freeze"] is None or _count(report["calls_in_flight_at_freeze"]))
        _require(report["timing_scope"] == "instrumented_publisher_thread_including_forwarding_observer")
        _require(report["thread_cpu_scope"] == "calling_thread_only_excludes_native_resident_cpu")
        validate_trace(rows, report)
    elif rows:
        _require(False)
    if "publication_chain" in proof:
        chain = proof["publication_chain"]
        _require(type(chain) is dict and finite_time(result.get("accepted_ms")))
        selected = [row for row in rows if row["publication"] == chain.get("publication")]
        _require(chain == phase_chain(selected, result.get("binding"), accepted_ms=result["accepted_ms"]))
    if "scope_checks" in proof:
        checks = proof["scope_checks"]
        _require(
            type(checks) is dict
            and set(checks) == _SCOPE_CHECKS
            and all(type(item) is bool for item in checks.values())
        )
    return proof


def _fault_request(value: object) -> None:
    required = {
        "passed",
        "scope",
        "offered_requests",
        "returned_requests",
        "native_receipts_expected",
        "availability_semantics",
        "elapsed_ms",
    }
    _require(type(value) is dict and required <= set(value) <= required | {"delivered_decision", "route", "reason"})
    value = cast(dict[str, Any], value)
    _require(type(value["passed"]) is bool)
    _require(value["scope"] == "fault_request_separate_from_recovered_receipt_cohort")
    _require(value["availability_semantics"] == "explicit_advisory_continuation_without_native_policy_decision")
    _require(all(type(value[key]) is int and value[key] in {0, 1} for key in ("offered_requests", "returned_requests")))
    _require(type(value["native_receipts_expected"]) is int and value["native_receipts_expected"] == 0)
    _require(finite_time(value["elapsed_ms"]) and 0 <= value["elapsed_ms"] < 2**63)
    if "delivered_decision" in value:
        _require(value["delivered_decision"] in (None, "allow", "deny"))
    if "route" in value:
        _require(type(value["route"]) is str and value["route"] in SAFE_ROUTE_NAMES | {"engine_bypassed"})
    if "reason" in value:
        _require(
            value["reason"]
            in (
                "native_policy_not_ready",
                "native_pre_tool_unavailable",
                "native_command_control_fence_unavailable",
            )
        )


def _facts(result: Mapping[str, Any]) -> dict[str, Any]:
    proof = _bounded_copy({key: result[key] for key in _FACT_FIELDS | _FAILURE_FIELDS if key in result})
    for kind, value in proof.items():
        if kind in _FAILURE_FIELDS:
            # Failure exporters already admit bounded labels and digests only.
            # Require an exact, stable export; never silently sanitize it twice.
            _require(type(value) is (list if kind == "cleanup_failures" else dict))
            _require(assert_privacy_safe({kind: value}) == {kind: value})
            continue
        _require(type(value) is dict)
        if kind == "lifecycle_clocks":
            _require(valid_lifecycle_clocks(value))
        elif kind == "service_replacement":
            _require(set(value) == _SERVICE_FLAGS | {"scope", "service_instances", "cold_observation_boundary"})
            _flags(value, _SERVICE_FLAGS)
            _require(value["scope"] == "two_python_service_instances_same_process_same_owned_home")
            _require(value["cold_observation_boundary"] == "before_real_constructor_start")
            _require(type(value["service_instances"]) is int and value["service_instances"] == 2)
        elif kind == "key_change":
            _require(
                set(value)
                == _KEY_FLAGS | {"key_domain", "old_authority_key_id", "old_authority_epoch", "fault_request"}
            )
            _flags(value, _KEY_FLAGS)
            _require(value["key_domain"] == "generated_command_control_authority")
            identity = value["old_authority_key_id"]
            _require(type(identity) is str and _DIGEST.fullmatch(identity) is not None)
            _require(_count(value["old_authority_epoch"]))
            _fault_request(value["fault_request"])
        elif kind == "expiry":
            _require(set(value) == _EXPIRY_FLAGS)
            _flags(value, _EXPIRY_FLAGS)
        elif kind == "fault_request":
            _fault_request(value)
        elif "metadata_observations" in value:
            _require(set(value) == _HINT_FLAGS | {"metadata_observations", "changed_metadata_hints_dropped"})
            _flags(value, _HINT_FLAGS)
            _require(_count(value["metadata_observations"]) and _count(value["changed_metadata_hints_dropped"]))
        else:
            _require(set(value) == _ACK_FLAGS | {"scope", "real_client_calls"})
            _flags(value, _ACK_FLAGS)
            _require(value["scope"] == "one_real_accepted_reply_discarded_before_first_python_admission")
            _require(_count(value["real_client_calls"]))
    return proof


def retain_cell(ledger: Any, result: dict[str, Any]) -> dict[str, object]:
    """Validate all proof before writing, and return a sanitizer-stable summary.

    Reassemble ``content`` from the indicated terminal parts in part order and
    verify ``result_sha256`` over the exact ASCII JSON before reading evidence.
    Validation preserves captured values; it cannot authenticate their origin
    or turn this instrumented experiment into installed qualification.
    """
    from scripts.native_slo_workspace_lifecycle import LIFECYCLE_SCENARIOS

    _require(type(result) is dict and result.get("scenario") in LIFECYCLE_SCENARIOS)
    count = result.get("registered_workspaces")
    _require(type(count) is int and count in {1, 10, 100} and type(result.get("passed")) is bool)
    count = cast(int, count)
    proof = {**_publication(result, count), **_facts(result)}
    if "requests" in result:
        proof["requests"] = _requests(result["requests"], count)
    if result["passed"]:
        _require(proof.get("requests", {}).get("passed") is True)
        _require(proof.get("publication_observer", {}).get("complete") is True)
        _require(proof.get("publication_chain", {}).get("matched") is True)
        _require(bool(proof.get("scope_checks")) and all(proof["scope_checks"].values()))
    summary = assert_privacy_safe({key: value for key, value in result.items() if key not in _PROOF_FIELDS})
    if "requests" in proof:
        request = proof["requests"]
        summary["request_checks"] = {
            key: request[key]
            for key in (
                "passed",
                "observation_complete",
                "declared_requests",
                "observed_requests",
                "exact_attempts",
                "unique_receipt_identities",
                "unique_native_request_ids",
            )
        }
    summary["publication_checks"] = proof.get("scope_checks", {})
    summary["publication_events"] = len(proof.get("publication_rows", []))
    envelope = {"schema": EVIDENCE_SCHEMA, "summary": summary, "proof": proof}
    encoded = json.dumps(envelope, sort_keys=True, separators=(",", ":"), allow_nan=False)
    _require(len(encoded) <= MAX_CELL_BYTES)
    digest = hashlib.sha256(encoded.encode("ascii")).hexdigest()
    parts = [encoded[offset : offset + PART_CHARS] for offset in range(0, len(encoded), PART_CHARS)]
    for index, content in enumerate(parts):
        ledger.write(
            {
                "kind": "lifecycle_cell_terminal_part",
                "part": index,
                "parts": len(parts),
                "result_sha256": digest,
                "content": content,
            }
        )
    summary["evidence"] = {
        "schema": EVIDENCE_SCHEMA,
        "sha256": digest,
        "bytes": len(encoded),
        "parts": len(parts),
        "record_kind": "lifecycle_cell_terminal_part",
    }
    return summary
