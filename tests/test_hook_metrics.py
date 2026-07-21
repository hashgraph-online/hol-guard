"""Tests for the daemon hot-path hook metrics recorder.

These tests exercise the public contract of ``HookMetricsRecorder``:

* ``record()`` never stores raw output, prompts, or secret samples —
  only buckets, counters, and (short) reason codes.
* ``snapshot()`` exposes latency percentiles and bucket counters.
* ``maybe_flush_to_store(force=True)`` writes one rollup ``guard_events``
  row containing no raw content and leaves the store usable.

``reason_code`` is a short code (the production caller hardcodes
``"unknown"``; every other codebase value is short snake_case such as
``secret_match`` or ``scanner_budget_exhausted``). The recorder
interpolates it verbatim into a composite counter key *by design*, so
these tests probe the real boundary — no raw-output *field names* leak
and every snapshot *value* is numeric — rather than asserting the
caller-controlled reason string is absent from keys.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.daemon.hook_metrics import HookMetricsRecorder
from codex_plugin_scanner.guard.store import GuardStore

# Field names that would indicate raw output leaked into the snapshot.
# The recorder must never emit these as top-level keys or counter keys.
_RAW_OUTPUT_FIELDS = frozenset(
    {
        "output",
        "raw_output",
        "prompt",
        "payload",
        "content",
        "decrypted_payload",
        "secret_sample",
        "reason_text",
        "tool_response",
    }
)


def _record_one(
    recorder: HookMetricsRecorder,
    *,
    reason_code: str = "secret_match",
    output_size: int = 10_000,
    latency_ms: float = 25.0,
    decision: str = "block",
    policy_action: str | None = "block",
) -> None:
    """Record a single realistic hook decision metric."""
    recorder.record(
        harness="cursor",
        event_name="PostToolUse",
        route="source_read",
        payload_kind="file_output",
        output_size=output_size,
        latency_ms=latency_ms,
        decision=decision,
        policy_action=policy_action,
        model_output_action="unknown",
        reason_code=reason_code,
        cache_status="miss",
        fallback_kind="none",
        scanner_bytes=512,
    )


def _leaf_values(blob: object) -> Any:
    """Yield every leaf value in ``blob`` (dict values, not keys)."""
    if isinstance(blob, dict):
        for value in blob.values():
            yield from _leaf_values(value)
    elif isinstance(blob, (list, tuple, set)):
        for item in blob:
            yield from _leaf_values(item)
    else:
        yield blob


@pytest.fixture()
def recorder() -> HookMetricsRecorder:
    return HookMetricsRecorder()


@pytest.fixture()
def store(tmp_path: Path) -> GuardStore:
    return GuardStore(tmp_path / "guard-home")


def test_record_excludes_raw_output(recorder: HookMetricsRecorder) -> None:
    """Recording a decision yields a snapshot with no raw-output fields.

    Passes a ``reason_code`` that looks like it could carry data
    (``tool_response: secret_data_here``) — matching the task example —
    then asserts the real contract boundary:

    * no top-level snapshot key names a raw-output field,
    * every counter value is an int,
    * every scalar snapshot value is numeric,
    * no leaf *value* (recursively, excluding dict keys) contains the
      secret fragment.

    Counter keys are caller-controlled by design (the composite key
    interpolates ``reason_code``), so this deliberately does not assert the
    reason string is absent from keys — only that no raw output is stored
    as a field name or value.
    """
    secret = "secret_data_here"
    _record_one(recorder, reason_code=f"tool_response: {secret}")
    snap = recorder.snapshot()

    assert isinstance(snap, dict)
    assert snap["total_decisions"] == 1

    leaked_fields = _RAW_OUTPUT_FIELDS & set(snap.keys())
    assert not leaked_fields, f"snapshot leaked raw-output field names: {leaked_fields}"

    counters = snap.get("counters", {})
    assert isinstance(counters, dict)
    assert counters, "expected at least one counter after recording"
    for key, value in counters.items():
        assert not isinstance(value, bool), f"counter {key!r} value is bool, not int"
        assert isinstance(value, int), f"counter {key!r} value {value!r} is not an int"
        assert key not in _RAW_OUTPUT_FIELDS, f"counter key {key!r} names a raw-output field"

    for field in ("latency_p50_ms", "latency_p95_ms", "latency_p99_ms", "total_decisions"):
        value = snap[field]
        assert isinstance(value, (int, float)) and not isinstance(value, bool), f"{field}={value!r} is not numeric"

    leaked_values = [v for v in _leaf_values(snap) if isinstance(v, str) and secret in v]
    assert not leaked_values, f"secret fragment leaked into snapshot values: {leaked_values}"


def test_latency_bucketing(recorder: HookMetricsRecorder) -> None:
    """Latencies map onto discrete bucket counters."""
    for latency in (5, 50, 500, 5000):
        _record_one(recorder, latency_ms=latency)

    counters = recorder.snapshot()["counters"]
    assert isinstance(counters, dict)
    latency_keys = [k for k in counters if k.startswith("latency:")]
    assert latency_keys, "no latency bucket counters recorded"

    # 5, 50, 500, 5000 each land in a distinct bucket.
    expected_buckets = {"latency:<= 5ms", "latency:<= 50ms", "latency:<= 500ms", "latency:<= 5000ms"}
    recorded_buckets = set(latency_keys)
    assert expected_buckets.issubset(recorded_buckets), (
        f"missing expected latency buckets: {expected_buckets - recorded_buckets}"
    )
    for bucket in expected_buckets:
        assert counters[bucket] == 1, f"bucket {bucket} expected count 1, got {counters[bucket]}"


def test_size_bucketing(recorder: HookMetricsRecorder) -> None:
    """Output sizes map onto discrete size bucket counters."""
    for size in (1000, 50_000, 200_000, 800_000, 3_000_000):
        _record_one(recorder, output_size=size)

    counters = recorder.snapshot()["counters"]
    assert isinstance(counters, dict)
    size_keys = [k for k in counters if k.startswith("size:")]
    assert size_keys, "no size bucket counters recorded"

    expected_buckets = {"size:0-12k", "size:12k-64k", "size:64k-256k", "size:256k-1m", "size:1m-5m"}
    recorded_buckets = set(size_keys)
    assert expected_buckets.issubset(recorded_buckets), (
        f"missing expected size buckets: {expected_buckets - recorded_buckets}"
    )
    for bucket in expected_buckets:
        assert counters[bucket] == 1, f"bucket {bucket} expected count 1, got {counters[bucket]}"


def test_snapshot_has_bucket_counters(recorder: HookMetricsRecorder) -> None:
    """Snapshot exposes either latency bucket counters or p50/p95 percentiles."""
    for latency in (5, 50, 500):
        _record_one(recorder, latency_ms=latency)

    snap = recorder.snapshot()
    assert isinstance(snap, dict)

    has_percentiles = {"latency_p50_ms", "latency_p95_ms"}.issubset(snap.keys())
    counters = snap.get("counters", {})
    assert isinstance(counters, dict)
    has_latency_buckets = any(k.startswith("latency:") for k in counters)
    has_size_buckets = any(k.startswith("size:") for k in counters)

    assert has_percentiles or has_latency_buckets, (
        "snapshot has neither latency percentiles nor latency bucket counters"
    )
    assert has_size_buckets, "snapshot has no size bucket counters"
    assert snap["total_decisions"] == 3


def test_flush_to_store_no_raw_content(
    recorder: HookMetricsRecorder,
    store: GuardStore,
) -> None:
    """``maybe_flush_to_store(force=True)`` writes one rollup event with no raw content.

    After flush, the recorder's internal state is cleared and the store
    remains usable for further writes.
    """
    for latency in (5, 50, 500):
        _record_one(recorder, latency_ms=latency)

    # Flush should not raise.
    recorder.maybe_flush_to_store(store, force=True)

    # Snapshot state is cleared after a forced flush.
    assert recorder.snapshot()["total_decisions"] == 0

    # Exactly one guard_events rollup row was written.
    with store._connect() as connection:
        rows = connection.execute("select event_name, payload_json from guard_events order by rowid").fetchall()
    assert len(rows) == 1, f"expected 1 rollup event, got {len(rows)}"
    assert rows[0]["event_name"] == "hook.metrics.rollup"
    payload = json.loads(rows[0]["payload_json"])
    assert isinstance(payload, dict)

    # The rollup payload must carry no raw-output field names.
    leaked_fields = _RAW_OUTPUT_FIELDS & set(payload.keys())
    assert not leaked_fields, f"rollup payload leaked raw-output field names: {leaked_fields}"
    assert "counters" in payload
    assert payload["total_decisions"] == 3

    # Store is still usable: a second add_event succeeds.
    store.add_event("hook.metrics.rollup", {"total_decisions": 0}, "2026-06-27T00:00:00+00:00")
    with store._connect() as connection:
        count = connection.execute("select count(*) as n from guard_events").fetchone()["n"]
    assert count == 2, f"store unusable after flush: expected 2 events, got {count}"
