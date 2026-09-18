"""The benchmark must exercise forwarding, freshness and approvals, not skip them."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "guard_mcp_stdio_profile", Path(__file__).resolve().parents[1] / "scripts" / "profile_guard_mcp_session.py"
)
assert SPEC and SPEC.loader
profile = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(profile)


def test_real_stdio_catalog_modes_preserve_complete_trace_and_refresh() -> None:
    optimized = profile.run_case(catalog_size=10, payload_bytes=16384, samples=2, profile=True, refresh_every=1)
    uncached = profile.run_case(catalog_size=10, payload_bytes=16384, samples=2, uncached=True, refresh_every=1)
    expected = optimized["correctness"]
    assert expected["exact_response_trace_sha256"] == uncached["correctness"]["exact_response_trace_sha256"]
    assert expected["forwarded_ids_exact"] is True
    assert expected["accepted"] == 3
    assert expected["notifications"] == {"notifications/progress": 3, "notifications/tools/list_changed": 2}
    assert len(expected["catalog_generations"]) == 3
    assert expected["quiet_barrier_seconds"] == 0.005
    assert optimized["exclusive_phases"]["prewrite_quiet_barrier"]["calls"] == 2
    assert optimized["exclusive_phases"]["classification"]["calls"] == 4
    assert optimized["memory"]["max_processes"] >= 2
    encoded = json.dumps(optimized)
    assert "guard-mcp-profile-" not in encoded
    assert "xxxxxxxx" not in encoded


def test_compact_memory_probe_preserves_utf8_and_complete_arguments_digest() -> None:
    result = profile.run_case(
        catalog_size=10,
        payload_bytes=3072,
        samples=1,
        profile=True,
        compact_result=True,
        payload_kind="unicode",
    )
    assert result["correctness"]["accepted"] == 2
    assert result["correctness"]["forwarded_ids_exact"] is True
    assert 3072 < result["correctness"]["largest_client_frame_utf8_bytes"] < 4096
    assert result["exclusive_phases"]["classification"]["calls"] == 2
    assert result["exclusive_phases"].get("facts_snapshot", {}).get("calls", 0) == 0
    if profile.sys.platform in {"linux", "darwin"}:
        assert result["memory"]["worker_peak_rss_bytes"] > 0


@pytest.mark.parametrize("kind", ["dense-integers", "nested-records", "nested-text"])
def test_compact_container_probe_preserves_all_arguments_and_frame_limit(kind: str) -> None:
    result = profile.run_case(
        catalog_size=10, payload_bytes=3072, samples=1, profile=True, compact_result=True, payload_kind=kind
    )
    assert result["correctness"]["accepted"] == 2
    assert result["correctness"]["forwarded_ids_exact"] is True
    assert 2000 < result["correctness"]["largest_client_frame_utf8_bytes"] < 4096
    assert result["exclusive_phases"]["classification"]["calls"] == 2
    assert result["exclusive_phases"].get("facts_snapshot", {}).get("calls", 0) == 0


@pytest.mark.parametrize("approval", ["accept", "cancel", "invalidate"])
def test_real_stdio_approval_wait_preserves_outcome_and_no_replay(approval: str) -> None:
    result = profile.run_case(
        catalog_size=10, payload_bytes=256, samples=1, profile=True, approval=approval, approval_delay_ms=25
    )
    correctness = result["correctness"]
    assert correctness["errors"] == 0
    assert correctness["forwarded_ids_exact"] is True
    assert correctness[{"accept": "accepted", "cancel": "cancelled", "invalidate": "invalidated"}[approval]] == 2
    assert result["exclusive_phases"]["inline_approval_wait"]["calls"] == 1
    if approval != "accept":
        assert correctness["accepted"] == 0
    if approval == "invalidate":
        assert correctness["notifications"]["notifications/tools/list_changed"] == 2


def test_failed_matrix_cell_retains_attempted_and_completed_counts(tmp_path, monkeypatch) -> None:
    output = tmp_path / "matrix.json"

    def failed_case(**_options):
        raise profile.BenchmarkCaseError(
            {"stage": "tool_call", "attempted_tool_requests": 3, "observed_tool_responses": 2, "errors": 1}
        )

    monkeypatch.setattr(profile, "run_case", failed_case)
    with pytest.raises(profile.BenchmarkCaseError):
        profile.run_matrix(samples=3, output=output)
    saved = json.loads(output.read_text())
    assert saved["completed_cases"] == 0
    assert saved["failed_case"]["attempted_tool_requests"] == 3
    assert saved["failed_case"]["observed_tool_responses"] == 2
    # A failed attempt must be resolved explicitly, never counted as a resumed success.
    with pytest.raises(ValueError, match="failed_attempt_resolution"):
        profile.run_matrix(samples=3, output=output, resume=True)


def test_resume_rejects_fixture_drift_before_running_any_more_cases(tmp_path) -> None:
    output = tmp_path / "matrix.json"
    output.write_text(
        json.dumps(
            {
                "schema": "hol-guard-mcp-stdio-rebaseline.v1",
                "platform": profile.platform.system(),
                "architecture": profile.platform.machine(),
                "python": profile.platform.python_version(),
                "runtime_sources_sha256": profile.runtime_source_identity(),
                "cases": [{"fixture": {"samples": 999}, "block": 0, "correctness": {"errors": 0}}],
            }
        )
    )
    with pytest.raises(ValueError, match="resume_fixture_mismatch"):
        profile.run_matrix(samples=3, output=output, resume=True)
