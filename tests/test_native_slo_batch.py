from __future__ import annotations

import pytest

from scripts.native_slo_adapter import Observation
from scripts.native_slo_batch import apply_offered_route_evidence, validate_batch_routes
from scripts.native_slo_daemon_fixture import witnessed_route


def test_zero_invocations_are_engine_bypass_and_mixed_counts_fail() -> None:
    assert witnessed_route({}, {}) == "engine_bypassed"
    assert witnessed_route({}, {"native_resident": 1}) == "native_resident"
    with pytest.raises(RuntimeError, match="ambiguous"):
        witnessed_route({}, {"native_resident": 2})
    with pytest.raises(RuntimeError, match="ambiguous"):
        witnessed_route({}, {"native_resident": 1, "native_fail_safe": 1})


def test_batch_requires_exact_independent_counters_before_attribution() -> None:
    item = Observation("claude-code", "PostToolUse", "1k", 12.0, "pending_batch_validation", True)
    observations, routes = validate_batch_routes([item] * 16, {"native_resident": 20}, {"native_resident": 36})
    assert routes == {"native_resident": 16}
    assert all(item.route == "native_resident" for item in observations)
    with pytest.raises(RuntimeError, match="count does not match"):
        validate_batch_routes([item] * 16, {}, {"native_resident": 15})
    with pytest.raises(RuntimeError, match="left native"):
        validate_batch_routes([item] * 16, {}, {"python_semantic": 16})


def test_overload_batch_keeps_bypass_and_native_fail_safe_distinct() -> None:
    item = Observation("claude-code", "PostToolUse", "1k", 12.0, "pending_batch_validation", True)
    overload = Observation("claude-code", "PostToolUse", "1k", 12.0, "pending_batch_validation", False, True)
    items, routes = validate_batch_routes([item, overload, overload], {}, {"native_resident": 1, "native_fail_safe": 1})
    assert routes == {"native_resident": 1, "native_fail_safe": 1, "engine_bypassed": 1}
    assert [item.route for item in items] == ["native_resident", "overload_batch_validated", "overload_batch_validated"]
    report = {
        "accounted": True,
        "worker_shutdown_complete": True,
        "completed": 3,
        "attempted": 4,
        "concurrency": 64,
        "overloaded": 2,
    }
    apply_offered_route_evidence(report, [item, overload, overload], {}, {"native_resident": 1, "native_fail_safe": 1})
    assert report["evaluated_allowed"] == 1
    assert report["load_contract_passed"] is False
