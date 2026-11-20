"""Fixture lifecycle/timing checks; actual SDK qualification runs separately."""

from __future__ import annotations

import subprocess
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import cigar_benchmark_workload as workload_module
from scripts import cigar_slo_activity as activity_module
from scripts import native_slo_benchmark_stages as stages
from scripts import native_slo_session as session_module
from scripts.native_slo_adapter import Observation
from scripts.native_resident_stop_bound import RESIDENT_STOP_TIMEOUT_SECONDS


@pytest.mark.parametrize("stage", ["cold", "recovery"])
def test_activity_and_restart_checks_do_not_extend_the_existing_native_timed_budget(tmp_path, monkeypatch, stage):
    clock = [0.0]
    events = []

    class Activity:
        @contextmanager
        def background(self, label, *_):
            events.append(label)
            clock[0] += 50
            yield
            clock[0] += 10
            events.append("background-stopped")

        def after_restart(self, label, *_):
            events.append("checked-" + label)
            clock[0] += 100

    def stop(**kwargs):
        assert events[-1] == "background-stopped"
        assert kwargs == ({"preserve_clients": True} if stage == "recovery" else {})
        clock[0] += 0.5
        events.append("native-contained")
        return True

    def observe(*_):
        clock[0] += 0.02
        return Observation("claude-code", "PostToolUse", "1k", 20, "native_resident", True)

    def cold(command, **kwargs):
        assert kwargs["timeout"] == 5
        clock[0] += 0.02
        return subprocess.CompletedProcess(command, 0, b'{"decision":"allow"}', b"")

    monkeypatch.setattr(stages.time, "perf_counter", lambda: clock[0])
    monkeypatch.setattr(stages.subprocess, "run", cold)
    session = SimpleNamespace(guard_home=tmp_path, workspace=tmp_path, stop_resident=stop, observe=observe)
    if stage == "recovery":
        result = stages._run_recovery(session, 2, activity=Activity())
    else:
        result = stages._run_cold(tmp_path / "runtime", session, 2, activity=Activity())
    assert result == pytest.approx([20, 20])
    assert events.count("native-contained") == events.count("checked-" + stage) == 2


def test_scope_reuse_does_not_rewrite_the_current_source_or_grant_again(tmp_path, monkeypatch):
    source = tmp_path / "README.md"
    source.write_text("stable current source\n")
    before = source.stat().st_mtime_ns

    def unexpected(*_, **__):
        raise AssertionError("reusing a current scope cannot silently create another grant")

    monkeypatch.setattr(workload_module, "workspace", unexpected)
    workload = workload_module.ContextWorkload(tmp_path, tmp_path, reuse_scope="scope:existing")
    assert workload.scope == "scope:existing"
    assert source.stat().st_mtime_ns == before and source.read_text() == "stable current source\n"


class Sampler:
    errors = 0

    def sample(self):
        return {}

    def checkpoint(self):
        return 1

    def summary(self, start=0):
        return {"samples": 2, "maximum_counts": {"sdk_worker": 2, "python_bridge": 1}}


def test_actual_phase_progress_is_required_and_unknown_context_outcomes_do_not_reactivate(tmp_path, monkeypatch):
    state = {"requested_enabled": True, "effective_enabled": True, "runtime": {}, "execution_ready": True}
    monkeypatch.setattr(activity_module, "control", lambda *_, **__: state)
    created, closed = [], []

    class Workload:
        successes = 1

        def __init__(self, *_, **kwargs):
            self.scope = "scope:paired"
            created.append((self, kwargs))

        def start(self):
            pass

        def close(self):
            closed.append(self)
            return {"refusals": {}}

    monkeypatch.setattr(activity_module, "ContextWorkload", Workload)
    monkeypatch.setattr(activity_module, "activate", lambda *_: pytest.fail("a read must not reactivate itself"))
    activity = activity_module.CigarSloActivity(Path("/native"), enabled=True, sampler=Sampler(), settle_seconds=0)
    with activity.background("warm", tmp_path, tmp_path):
        created[-1][0].successes += 2
    assert activity.phases[0]["successful_overlapping_compiles"] == 2
    with (
        pytest.raises(RuntimeError, match="no actual compilation overlap"),
        activity.background("sizes", tmp_path, tmp_path),
    ):
        pass
    assert created[1][1]["reuse_scope"] == "scope:paired"
    assert len(closed) == 2
    Workload.close = lambda self: {"refusals": {"native_context_assistance_runtime_deadline_exceeded": 1}}
    with (
        pytest.raises(RuntimeError, match="workload returned refusals"),
        activity.background("capacity", tmp_path, tmp_path),
    ):
        created[-1][0].successes += 1
    assert not activity.phases[-1]["completed"]


def test_failed_hook_interval_still_joins_context_load_and_preserves_original_error(tmp_path, monkeypatch):
    state = {"requested_enabled": True, "effective_enabled": True, "runtime": {}, "execution_ready": True}
    monkeypatch.setattr(activity_module, "control", lambda *_, **__: state)
    joined = []
    monkeypatch.setattr(
        activity_module,
        "ContextWorkload",
        lambda *_, **__: SimpleNamespace(
            scope="scope:fixture",
            successes=1,
            start=lambda: None,
            close=lambda: joined.append(True) or {"refusals": {}},
        ),
    )
    activity = activity_module.CigarSloActivity(Path("/native"), enabled=True, sampler=Sampler(), settle_seconds=0)
    with pytest.raises(ValueError, match="original hook failure"), activity.background("warm", tmp_path, tmp_path):
        raise ValueError("original hook failure")
    assert joined == [True] and not activity.phases[0]["completed"]


@pytest.mark.parametrize("restore", ["runtime", "scope", "none"])
def test_restart_requires_absent_runtime_and_refuses_old_source_authority(tmp_path, monkeypatch, restore):
    state = {"requested_enabled": True, "effective_enabled": False, "runtime": None, "execution_ready": False}
    if restore == "runtime":
        state["runtime"] = {}
    monkeypatch.setattr(activity_module, "control", lambda *_, **__: state)

    def compile_context(*_, **__):
        if restore == "scope":
            return {"result": {"current": True}}
        raise workload_module.ContextAssistanceError("native_context_assistance_runtime_not_verified")

    monkeypatch.setattr(activity_module, "workspace", compile_context)
    activity = activity_module.CigarSloActivity(Path("/native"), enabled=True, sampler=Sampler())
    activity.scopes[tmp_path] = "scope:before-restart"
    if restore == "none":
        activity.after_restart("recovery", tmp_path, tmp_path)
        assert activity.restarts == [{"phase": "recovery", "runtime_absent": True, "old_scope_refused": True}]
    else:
        with pytest.raises(RuntimeError, match="restored"):
            activity.after_restart("recovery", tmp_path, tmp_path)


def test_off_variant_never_creates_context_load_and_observed_optional_children_fail_coverage(tmp_path, monkeypatch):
    state = {"requested_enabled": False, "effective_enabled": False, "runtime": None, "execution_ready": False}
    monkeypatch.setattr(activity_module, "control", lambda *_, **__: state)
    monkeypatch.setattr(activity_module, "ContextWorkload", lambda *_, **__: pytest.fail("off created context load"))
    activity = activity_module.CigarSloActivity(Path("/native"), enabled=False, sampler=Sampler(), settle_seconds=0)
    with activity.background("warm", tmp_path, tmp_path):
        pass
    assert activity.phases[0]["completed"] and activity.phases[0]["successful_overlapping_compiles"] == 0
    assert not activity.summary()["gates"]["optional_worker_coverage"]


def test_failed_explicit_setup_closes_private_session_before_native_readiness(tmp_path, monkeypatch):
    closed = []
    monkeypatch.setattr(
        activity_module,
        "_ObservedSession",
        lambda *_, **__: SimpleNamespace(
            guard_home=tmp_path,
            workspace=tmp_path,
            close=lambda: closed.append(True),
        ),
    )

    def fail(*_):
        raise RuntimeError("explicit setup failed")

    monkeypatch.setattr(activity_module, "configure", fail)
    activity = activity_module.CigarSloActivity(Path("/native"), enabled=True, sampler=Sampler())
    with pytest.raises(RuntimeError, match="explicit setup failed"):
        activity.session(Path("/native"))
    assert closed == [True]


@pytest.mark.parametrize("failure", ["timeout", "signal"])
def test_stop_process_failure_distinguishes_timeout_from_signal_without_echoing_stderr(tmp_path, monkeypatch, failure):
    monkeypatch.setattr(session_module, "_resident_state_may_exist", lambda *_: True)
    calls = []

    def run(command, **kwargs):
        assert kwargs["timeout"] == RESIDENT_STOP_TIMEOUT_SECONDS
        calls.append(command)
        if failure == "timeout":
            raise subprocess.TimeoutExpired(command, RESIDENT_STOP_TIMEOUT_SECONDS, stderr=b"private-output-must-not-render")
        return subprocess.CompletedProcess(command, -6, b"", b"private-output-must-not-render")

    monkeypatch.setattr(session_module.subprocess, "run", run)
    result = session_module.stop_native_resident(tmp_path / "runtime", tmp_path, write_diagnostic=False)
    assert not result and len(calls) == 1
    assert result.diagnostic["process_outcome"] == ("timed_out" if failure == "timeout" else "exited")
    if failure == "signal":
        assert result.diagnostic["process_returncode"] == -6
    assert "private-output" not in str(result.diagnostic)


def test_final_containment_is_recorded_without_erasing_an_earlier_cleanup_timeout(monkeypatch):
    def close(session):
        session.final_stop_diagnostic = {"status": "contained"}
        session.last_stop_diagnostic = {"status": "failed", "process_outcome": "timed_out"}

    monkeypatch.setattr(activity_module.AdapterSession, "close", close)
    activity = activity_module.CigarSloActivity(Path("/native"), enabled=True, sampler=Sampler())
    session = object.__new__(activity_module._ObservedSession)
    session.daemon_stop_contained = True
    session._on_cleanup = lambda final, prior, recovery, *, daemon_stop_contained: activity.contained(
        "session_1", final, prior, recovery, daemon_stop_contained=daemon_stop_contained
    )
    session.close()
    assert activity.cleanups == [
        {
            "fixture": "session_1",
            "final_contained": True,
            "daemon_stop_contained": True,
            "earlier_stop_failed": True,
            "earlier_process_outcome": "timed_out",
        }
    ]


def test_rss_diagnostics_are_bounded_and_recovery_cannot_qualify_a_failed_strict_stop():
    activity = activity_module.CigarSloActivity(Path("/native"), enabled=False, sampler=Sampler())
    sample = {"rss_bytes": 30, "root_rss_bytes": 10, "descendant_rss_bytes": 20, "processes": 2}
    for _ in range(512):
        activity.record_rss(sample)
    with pytest.raises(RuntimeError, match="RSS diagnostic budget"):
        activity.record_rss(sample)
    activity.contained(
        "session_1",
        {"status": "failed"},
        {"status": "failed", "process_outcome": "timed_out"},
        {"attempted": True, "contained": True},
    )
    assert activity.cleanups[0]["final_contained"] is False
    assert activity.cleanups[0]["recovery_cleanup"]["contained"] is True
    assert not activity.summary()["gates"]["all_five_private_fixtures_finally_contained"]
