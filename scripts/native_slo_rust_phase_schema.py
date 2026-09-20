"""Strict aggregate schema for optional Linux native phase datagrams.

No request data, paths, tokens or free-form errors are admitted. Missing phase
statistics remain None; observations are inclusive and never headline timings.
"""

from __future__ import annotations

import json
from typing import Any, cast

MAX_DATAGRAM_BYTES = 8192
MAX_EXPORT_ATTEMPTS = 256
MAX_OBSERVATIONS = 100_000
MAX_DURATION_NS = 60_000_000_000
PHASES = (
    "client_connect_inclusive",
    "client_authenticate",
    "client_request_write_flush",
    "client_committed_response_read",
    "resident_evaluate_inclusive",
    "unix_socket_creation",
    "loopback_connect_handle",
)
ROLES = {
    "hook-client": "resident_client",
    "resident-client": "resident_client",
    "resident-client-stream": "persistent_client",
    "serve": "resident",
    "serve-managed": "managed_resident",
}
OUTCOMES = ("returned_ok", "returned_err", "unwound", "abandoned")
FRAME_FIELDS = frozenset(
    {
        "schema",
        "sender_pid",
        "sender_start_ticks",
        "role",
        "ordinal",
        "max_export_attempts",
        "export_interval_ms",
        "max_datagram_bytes",
        "diagnostic_socket_opens",
        "diagnostic_socket_in_request_counts",
        "prior_export_loss_observed",
        "last_allowed_attempt",
        "run_state_when_sampled",
        "complete_run",
        "headline_timing_eligible",
        "snapshot",
    }
)
REPORT_FIELDS = frozenset(
    {
        "schema",
        "scope",
        "span_semantics",
        "headline_timing_eligible",
        "complete_run",
        "snapshot_atomic",
        "collector_loss_observed",
        "active_observations_when_read",
        "max_observations_per_phase",
        "max_duration_ns",
        "unobserved_phase",
        "loopback_failed_internal_socket_creations",
        "all_platform_socket_opens",
        "phases",
    }
)
STAT_FIELDS = frozenset(
    {
        "retained_count",
        *OUTCOMES,
        "duration_ns_sum",
        "duration_ns_min",
        "duration_ns_max",
        "duration_clipped",
        "observations_discarded_at_cap",
    }
)


def _require(condition: bool) -> None:
    if not condition:
        raise ValueError("native_phase_schema_refused")


def _integer(value: object, low: int, high: int) -> None:
    _require(type(value) is int and low <= value <= high)


def _object(value: object, fields: frozenset[str]) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == fields)
    return cast(dict[str, Any], value)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        _require(key not in result)
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ValueError("native_phase_schema_refused")


def _statistics(value: object) -> None:
    if value is None:
        return
    stats = _object(value, STAT_FIELDS)
    _integer(stats["retained_count"], 1, MAX_OBSERVATIONS)
    count = stats["retained_count"]
    for name in OUTCOMES:
        _integer(stats[name], 0, count)
    _require(sum(stats[name] for name in OUTCOMES) == count)
    for name in ("duration_ns_min", "duration_ns_max"):
        _integer(stats[name], 0, MAX_DURATION_NS)
    _integer(stats["duration_ns_sum"], 0, MAX_DURATION_NS * count)
    _require(stats["duration_ns_min"] <= stats["duration_ns_max"])
    _require(count * stats["duration_ns_min"] <= stats["duration_ns_sum"] <= count * stats["duration_ns_max"])
    for name in ("duration_clipped", "observations_discarded_at_cap"):
        _require(type(stats[name]) is bool)
    _require(not stats["duration_clipped"] or stats["duration_ns_max"] == MAX_DURATION_NS)
    _require(not stats["observations_discarded_at_cap"] or count == MAX_OBSERVATIONS)


def _snapshot(value: object) -> None:
    if value is None:
        return
    report = _object(value, REPORT_FIELDS)
    fixed = {
        "schema": "hol-guard-native-phase-diagnostics.v1",
        "scope": "diagnostic_instrumented_process_snapshot",
        "span_semantics": "inclusive_do_not_sum",
        "headline_timing_eligible": False,
        "complete_run": False,
        "snapshot_atomic": False,
        "max_observations_per_phase": MAX_OBSERVATIONS,
        "max_duration_ns": MAX_DURATION_NS,
        "unobserved_phase": "null_missing_or_unretained_not_zero_cost",
        "loopback_failed_internal_socket_creations": None,
        "all_platform_socket_opens": None,
    }
    for key, expected in fixed.items():
        _require(type(report[key]) is type(expected) and report[key] == expected)
    _require(type(report["collector_loss_observed"]) is bool)
    _integer(report["active_observations_when_read"], 0, 2**64 - 1)
    _require(type(report["phases"]) is list and len(report["phases"]) == len(PHASES))
    for phase, expected in zip(report["phases"], PHASES, strict=True):
        row = _object(phase, frozenset({"phase", "statistics"}))
        _require(type(row["phase"]) is str and row["phase"] == expected)
        _statistics(row["statistics"])


def decode_frame(payload: bytes) -> dict[str, Any]:
    _require(type(payload) is bytes and 0 < len(payload) <= MAX_DATAGRAM_BYTES)
    frame = _object(
        json.loads(payload.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=_reject_constant),
        FRAME_FIELDS,
    )
    fixed = {
        "schema": "hol-guard-native-phase-frame.v1",
        "max_export_attempts": MAX_EXPORT_ATTEMPTS,
        "export_interval_ms": 50,
        "max_datagram_bytes": MAX_DATAGRAM_BYTES,
        "diagnostic_socket_opens": 1,
        "diagnostic_socket_in_request_counts": False,
        "complete_run": False,
        "headline_timing_eligible": False,
    }
    for key, expected in fixed.items():
        _require(type(frame[key]) is type(expected) and frame[key] == expected)
    _integer(frame["sender_pid"], 1, 2**31 - 1)
    _integer(frame["sender_start_ticks"], 1, 2**64 - 1)
    _integer(frame["ordinal"], 1, MAX_EXPORT_ATTEMPTS)
    _require(type(frame["role"]) is str and frame["role"] in ROLES.values())
    _require(
        type(frame["run_state_when_sampled"]) is str
        and frame["run_state_when_sampled"]
        in {
            "running",
            "returned_ok",
            "returned_err",
        }
    )
    _require(type(frame["prior_export_loss_observed"]) is bool)
    _require(type(frame["last_allowed_attempt"]) is bool)
    _require(frame["last_allowed_attempt"] is (frame["ordinal"] == MAX_EXPORT_ATTEMPTS))
    _snapshot(frame["snapshot"])
    return frame


def require_progress(previous: dict[str, Any], current: dict[str, Any]) -> None:
    """Refuse counter resets or conflicting process roles; never sum snapshots."""
    for key in ("sender_pid", "sender_start_ticks", "role"):
        _require(previous[key] == current[key])
    _require(previous["ordinal"] < current["ordinal"])
    _require(previous["run_state_when_sampled"] == "running")
    _require(not previous["prior_export_loss_observed"] or current["prior_export_loss_observed"])
    old, new = previous["snapshot"], current["snapshot"]
    if old is None or new is None:
        return
    _require(not old["collector_loss_observed"] or new["collector_loss_observed"])
    for left, right in zip(old["phases"], new["phases"], strict=True):
        before, after = left["statistics"], right["statistics"]
        if before is None:
            continue
        _require(after is not None)
        for key in ("retained_count", *OUTCOMES, "duration_ns_sum", "duration_ns_max"):
            _require(after[key] >= before[key])
        _require(after["duration_ns_min"] <= before["duration_ns_min"])
        for key in ("duration_clipped", "observations_discarded_at_cap"):
            _require(not before[key] or after[key])
