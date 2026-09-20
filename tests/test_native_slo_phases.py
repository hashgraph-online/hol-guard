from __future__ import annotations

import pytest

from scripts.native_slo_phases import PhaseProfiler


def test_phase_profiler_records_only_foreground_route_and_restores_on_exception() -> None:
    profiler = PhaseProfiler()

    def fail() -> object:
        raise ValueError("private synthetic argument must not be recorded")

    measured = profiler._wrap(fail, "config_lookup")
    with pytest.raises(ValueError):
        measured()
    assert profiler.report()["by_route"] == {}

    def hook(_self: object, payload: object, *, default_harness: str) -> object:
        del payload, default_harness
        return measured()

    wrapped = profiler._wrap(hook, "daemon_hook_inclusive", root=True)
    with pytest.raises(ValueError):
        wrapped(None, {"hook_event_name": "PostToolUse", "private": "not retained"}, default_harness="claude-code")
    report = profiler.report()
    spans = report["by_route"]["claude-code.PostToolUse"]
    assert spans["config_lookup"]["count"] == 1
    assert spans["daemon_hook_inclusive"]["count"] == 1
    assert "not retained" not in str(report)
    with pytest.raises(ValueError):
        measured()
    assert profiler.report()["by_route"]["claude-code.PostToolUse"]["config_lookup"]["count"] == 1


def test_phase_instrumentation_restores_production_functions_after_scope() -> None:
    from codex_plugin_scanner.guard import native_runtime

    original = native_runtime._validate_binary
    with PhaseProfiler():
        assert native_runtime._validate_binary is not original
    assert native_runtime._validate_binary is original
