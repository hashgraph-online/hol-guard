"""Adversarial value and monotonicity controls for aggregate-only diagnostics."""

from __future__ import annotations

import copy
import json

import pytest

from scripts.native_slo_rust_phase_schema import decode_frame, require_progress
from tests.native_slo_rust_phase_test_support import sample_frame


def test_phase_schema_preserves_nulls_and_exact_bounded_aggregate_values() -> None:
    original = sample_frame()
    observed = decode_frame(json.dumps(original).encode())
    assert observed == original
    assert observed["snapshot"]["phases"][1]["statistics"] is None
    assert observed["snapshot"]["all_platform_socket_opens"] is None
    assert observed["headline_timing_eligible"] is False


@pytest.mark.parametrize(
    "field,value",
    [
        ("payload", "must never be admitted"),
        ("sender_pid", True),
        ("sender_start_ticks", 0),
        ("ordinal", 257),
        ("role", "unlisted role"),
        ("complete_run", True),
        ("diagnostic_socket_in_request_counts", True),
        ("max_datagram_bytes", 8193),
    ],
)
def test_phase_schema_refuses_extra_fields_and_false_authority(field: str, value: object) -> None:
    frame = sample_frame()
    frame[field] = value
    with pytest.raises(ValueError, match="native_phase_schema_refused"):
        decode_frame(json.dumps(frame).encode())


@pytest.mark.parametrize(
    "field,value",
    [
        ("retained_count", 0),
        ("returned_ok", 2),
        ("duration_ns_sum", 0),
        ("duration_ns_min", 2),
        ("duration_clipped", True),
        ("observations_discarded_at_cap", True),
    ],
)
def test_phase_schema_refuses_inconsistent_statistics(field: str, value: object) -> None:
    frame = sample_frame()
    frame["snapshot"]["phases"][0]["statistics"][field] = value
    with pytest.raises(ValueError, match="native_phase_schema_refused"):
        decode_frame(json.dumps(frame).encode())


def test_phase_schema_refuses_duplicate_json_names_and_oversize_frames() -> None:
    encoded = json.dumps(sample_frame()).encode()
    duplicate = encoded.replace(b'"ordinal": 1', b'"ordinal": 1, "ordinal": 2')
    with pytest.raises(ValueError, match="native_phase_schema_refused"):
        decode_frame(duplicate)
    with pytest.raises(ValueError, match="native_phase_schema_refused"):
        decode_frame(b" " * 8193)


def test_cumulative_progress_accepts_growth_and_refuses_replay_reset_or_role_change() -> None:
    first = decode_frame(json.dumps(sample_frame(1, 1)).encode())
    second = decode_frame(json.dumps(sample_frame(2, 2)).encode())
    require_progress(first, second)
    for changed in (first, sample_frame(2, 1), {**second, "role": "managed_resident"}):
        before = second if changed is first else first
        if changed is not first and changed["role"] == first["role"]:
            changed["snapshot"]["phases"][0]["statistics"]["duration_ns_sum"] = 0
        with pytest.raises(ValueError, match="native_phase_schema_refused"):
            require_progress(before, changed)
    absent = copy.deepcopy(second)
    absent["ordinal"] = 3
    absent["snapshot"]["phases"][0]["statistics"] = None
    with pytest.raises(ValueError, match="native_phase_schema_refused"):
        require_progress(second, absent)
