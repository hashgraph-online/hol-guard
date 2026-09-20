"""Validate bounded publisher spans without treating a transport reply as authority."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any

from scripts.native_slo_workspace_observer import MAX_EVENTS, public_binding


def event_digest(rows: Sequence[Mapping[str, object]]) -> str:
    return hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def phase_chain(
    rows: Sequence[Mapping[str, Any]],
    binding: object,
    *,
    accepted_ms: float,
    require_final_compile: bool = False,
) -> dict[str, object]:
    """Pair spans from one actual publish call; retain negative acceptance offsets.

    An asynchronous publisher may finish before a public mutation API returns.
    Its observed intervals must not be moved or clipped to look sequential.
    """
    expected = public_binding(binding)
    if expected is None:
        return {"matched": False}
    for barrier in reversed(rows):
        attempt = barrier.get("publication")
        if (
            barrier.get("kind") != "barrier"
            or barrier.get("ready") is not True
            or type(attempt) is not int
            or attempt <= 0
            or barrier.get("binding") != expected
        ):
            continue
        current = [row for row in rows if row.get("publication") == attempt]
        compiles = [row for row in current if row["kind"] == "compile" and row.get("succeeded") is True]
        pushes = [
            row
            for row in current
            if row["kind"] == "push" and row.get("returned") is True and row.get("binding") == expected
        ]
        acks = [
            row
            for row in current
            if row["kind"] == "transport_ack" and row.get("validated") is True and row.get("binding") == expected
        ]
        if not compiles or not pushes or not acks:
            continue
        compiled, pushed, ack = compiles[-1], pushes[-1], acks[-1]
        if not (
            compiled["started_ms"]
            <= compiled["finished_ms"]
            <= pushed["started_ms"]
            <= pushed["finished_ms"]
            <= ack["finished_ms"]
            <= barrier["finished_ms"]
        ) or (require_final_compile and compiled["started_ms"] < accepted_ms):
            continue
        return {
            "matched": True,
            "publication": attempt,
            "accepted_to_compile_started_ms": compiled["started_ms"] - accepted_ms,
            "compile_ms": compiled["finished_ms"] - compiled["started_ms"],
            "compile_thread_cpu_ms": compiled["thread_cpu_ms"],
            "accepted_to_push_started_ms": pushed["started_ms"] - accepted_ms,
            "push_ms": pushed["finished_ms"] - pushed["started_ms"],
            "accepted_to_validated_transport_ack_ms": ack["finished_ms"] - accepted_ms,
            "accepted_to_committed_barrier_ms": barrier["finished_ms"] - accepted_ms,
        }
    return {"matched": False}


def validate_trace(rows: Sequence[Mapping[str, object]], report: Mapping[str, Any]) -> None:
    if len(rows) > MAX_EVENTS or type(report.get("events")) is not int or report["events"] != len(rows):
        raise ValueError("workspace observer event count mismatch")
    if report.get("event_bound") != MAX_EVENTS or report.get("event_digest") != event_digest(rows):
        raise ValueError("workspace observer event digest mismatch")


def startup_rows(failure: Mapping[str, Any]) -> tuple[dict[str, Any], list[dict[str, object]]]:
    """Remove paged startup spans before persisting the small failure record."""
    detail = dict(failure)
    observation = detail.get("workspace_observation")
    if not isinstance(observation, Mapping):
        return detail, []
    retained = dict(observation)
    pages = retained.pop("retained_initial_pages", {})
    if not isinstance(pages, Mapping) or len(pages) > 16:
        raise ValueError("workspace startup pages outside bound")
    rows: list[dict[str, object]] = []
    for index in range(len(pages)):
        page = pages.get(f"page_{index}")
        if not isinstance(page, list) or not 1 <= len(page) <= 32 or not all(isinstance(row, dict) for row in page):
            raise ValueError("workspace startup event page invalid")
        rows.extend(page)
    report = retained.get("observer")
    if not isinstance(report, Mapping):
        raise ValueError("workspace startup observer report invalid")
    validate_trace(rows, report)
    detail["workspace_observation"] = retained
    return detail, rows
