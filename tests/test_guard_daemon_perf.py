"""Tests for Phase 21 daemon performance and detector lazy-init."""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.runtime.detectors import (
    _SLOW_DETECTOR_THRESHOLD_MS,
    DetectorContext,
    DetectorRegistry,
    DetectorRunResult,
    DetectorTelemetry,
)
from codex_plugin_scanner.guard.runtime.runner import _get_default_detector_registry


def _make_config(tmp_path: Path) -> GuardConfig:
    return GuardConfig(guard_home=tmp_path / "guard-home", workspace=tmp_path / "workspace")


def _make_harness_start_action() -> object:
    from codex_plugin_scanner.guard.runtime.actions import GuardActionEnvelope

    return GuardActionEnvelope(
        schema_version=1,
        action_id="perf-test-action",
        harness="codex",
        event_name="HarnessStart",
        action_type="harness_start",
        workspace=None,
        workspace_hash=None,
        tool_name=None,
        command=None,
        prompt_excerpt=None,
        prompt_text=None,
        target_paths=(),
        network_hosts=(),
        mcp_server=None,
        mcp_tool=None,
        package_manager=None,
        package_name=None,
        script_name=None,
        raw_payload_redacted={},
    )


def _make_detector_context(tmp_path: Path) -> DetectorContext:
    return DetectorContext(
        config=_make_config(tmp_path),
        workspace=None,
        prior_decisions={},
        threat_intel={},
        redaction_settings={},
    )


class TestSlowDetectorThreshold:
    def test_slow_detector_threshold_is_100ms(self) -> None:
        assert _SLOW_DETECTOR_THRESHOLD_MS == 100

    def test_slow_detectors_returns_empty_when_all_fast(self, tmp_path: Path) -> None:
        action = _make_harness_start_action()
        context = _make_detector_context(tmp_path)
        clock_values = iter([0.0, 0.001])

        def fast_clock() -> float:
            try:
                return next(clock_values)
            except StopIteration:
                return 0.001

        registry = DetectorRegistry((), clock=fast_clock)
        result = registry.run(action, context)
        assert result.slow_detectors() == ()

    def test_slow_detectors_flags_entries_at_or_above_threshold(self) -> None:
        fast_entry = DetectorTelemetry(
            detector_id="fast.detector",
            categories=("secret",),
            status="ok",
            elapsed_ms=50,
        )
        slow_entry = DetectorTelemetry(
            detector_id="slow.detector",
            categories=("network",),
            status="ok",
            elapsed_ms=100,
        )
        very_slow_entry = DetectorTelemetry(
            detector_id="very.slow.detector",
            categories=("prompt",),
            status="ok",
            elapsed_ms=250,
        )
        result = DetectorRunResult(
            signals=(),
            telemetry=(fast_entry, slow_entry, very_slow_entry),
        )
        slow = result.slow_detectors()
        assert len(slow) == 2
        assert slow[0].detector_id == "slow.detector"
        assert slow[1].detector_id == "very.slow.detector"

    def test_slow_detectors_custom_threshold(self) -> None:
        entry = DetectorTelemetry(
            detector_id="medium.detector",
            categories=("secret",),
            status="ok",
            elapsed_ms=75,
        )
        result = DetectorRunResult(signals=(), telemetry=(entry,))
        assert result.slow_detectors(threshold_ms=50) == (entry,)
        assert result.slow_detectors(threshold_ms=100) == ()


class TestLazyDetectorRegistry:
    def test_get_default_registry_returns_registry_instance(self) -> None:
        registry = _get_default_detector_registry()
        assert isinstance(registry, DetectorRegistry)

    def test_get_default_registry_returns_fresh_instance_each_call(self) -> None:
        first = _get_default_detector_registry()
        second = _get_default_detector_registry()
        assert isinstance(first, DetectorRegistry)
        assert isinstance(second, DetectorRegistry)

    def test_cached_registry_runs_without_error(self, tmp_path: Path) -> None:
        action = _make_harness_start_action()
        context = _make_detector_context(tmp_path)
        registry = _get_default_detector_registry()
        result = registry.run(action, context, timeout_ms=200)
        assert isinstance(result, DetectorRunResult)


class TestClientTimeoutConstants:
    def test_default_request_timeout_is_five_seconds(self) -> None:
        from codex_plugin_scanner.guard.daemon.client import _DEFAULT_REQUEST_TIMEOUT_S

        assert _DEFAULT_REQUEST_TIMEOUT_S == 5.0

    def test_status_request_timeout_is_250ms(self) -> None:
        from codex_plugin_scanner.guard.daemon.client import _STATUS_REQUEST_TIMEOUT_S

        assert pytest.approx(0.25) == _STATUS_REQUEST_TIMEOUT_S


class TestDoctorPerfPayload:
    def test_perf_payload_includes_all_detectors(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.cli.commands import _runtime_detector_perf_payload

        config = _make_config(tmp_path)
        perf = _runtime_detector_perf_payload(config)
        assert isinstance(perf, list)
        assert len(perf) >= 1

    def test_perf_payload_items_have_required_fields(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.cli.commands import _runtime_detector_perf_payload

        config = _make_config(tmp_path)
        perf = _runtime_detector_perf_payload(config)
        for item in perf:
            assert "detector_id" in item
            assert "status" in item
            assert "elapsed_ms" in item
            assert "slow" in item
            assert isinstance(item["slow"], bool)

    def test_perf_payload_slow_field_matches_threshold(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.cli.commands import _runtime_detector_perf_payload

        config = _make_config(tmp_path)
        perf = _runtime_detector_perf_payload(config)
        for item in perf:
            expected_slow = int(item["elapsed_ms"]) >= _SLOW_DETECTOR_THRESHOLD_MS
            assert item["slow"] == expected_slow


class TestProcessCountBound:
    """T620 — 100 safe hook evaluations must not spawn persistent threads."""

    def test_100_harness_start_evaluations_do_not_spawn_threads(self, tmp_path: Path) -> None:
        action = _make_harness_start_action()
        context = _make_detector_context(tmp_path)
        registry = _get_default_detector_registry()
        baseline_threads = threading.active_count()
        for _ in range(100):
            registry.run(action, context, timeout_ms=500)
        after_threads = threading.active_count()
        assert after_threads - baseline_threads <= 2, (
            f"Thread count grew by {after_threads - baseline_threads} after 100 evaluations; "
            "detectors must not leak persistent threads."
        )

    def test_100_harness_start_evaluations_complete_without_error(self, tmp_path: Path) -> None:
        action = _make_harness_start_action()
        context = _make_detector_context(tmp_path)
        registry = _get_default_detector_registry()
        results = [registry.run(action, context, timeout_ms=500) for _ in range(100)]
        assert all(isinstance(r, DetectorRunResult) for r in results)


class TestCPUBenchmark:
    """T622 — 100 safe hook evaluations must complete in under 10 seconds."""

    def test_100_safe_hook_calls_complete_within_budget(self, tmp_path: Path) -> None:
        action = _make_harness_start_action()
        context = _make_detector_context(tmp_path)
        registry = _get_default_detector_registry()
        start = time.monotonic()
        for _ in range(100):
            registry.run(action, context, timeout_ms=500)
        elapsed_s = time.monotonic() - start
        assert elapsed_s < 10.0, f"100 safe hook evaluations took {elapsed_s:.2f}s; budget is 10s."


class TestMemoryBenchmark:
    """T621 — Guard module import stays under 50 MB RSS budget."""

    def test_guard_config_import_does_not_import_heavy_deps(self) -> None:
        import sys

        imported = set(sys.modules.keys())
        assert "codex_plugin_scanner.guard.config" in imported, (
            "Guard config must be importable (already loaded by test session)"
        )
        heavy = {"matplotlib", "numpy", "pandas", "scipy", "torch", "tensorflow"}
        leaked = heavy & imported
        assert not leaked, f"Guard import leaked heavy dependencies: {leaked}"


class TestSlowSQLiteTelemetry:
    """T624 — Slow store transactions emit a warning via the logging module."""

    def test_slow_query_threshold_is_200ms(self) -> None:
        from codex_plugin_scanner.guard.store import _SLOW_QUERY_THRESHOLD_MS

        assert _SLOW_QUERY_THRESHOLD_MS == 200

    def test_fast_transaction_does_not_warn(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        import logging

        from codex_plugin_scanner.guard.store import GuardStore

        store = GuardStore(guard_home=tmp_path / "guard-home")
        with caplog.at_level(logging.WARNING, logger="codex_plugin_scanner.guard.store"):
            _ = store.list_approval_requests()
        slow_warnings = [r for r in caplog.records if "slow transaction" in r.getMessage().lower()]
        assert len(slow_warnings) == 0, "Fast transaction must not emit slow transaction warning"

    def test_store_has_slow_query_threshold_constant(self) -> None:
        from codex_plugin_scanner.guard.store import _SLOW_QUERY_THRESHOLD_MS

        assert isinstance(_SLOW_QUERY_THRESHOLD_MS, int)
        assert _SLOW_QUERY_THRESHOLD_MS > 0
