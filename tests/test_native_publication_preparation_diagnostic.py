"""Finite preparation-phase observations preserve existing publisher calls."""

from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest

from scripts import native_publication_diagnostic as diagnostic


@pytest.mark.parametrize(
    "method,label",
    [
        ("_publication_context", "context"),
        ("_compiled_command_extensions", "command"),
        ("_compiled_effective_policy", "config"),
    ],
)
@pytest.mark.parametrize("raises", [False, True])
def test_preparation_phases_preserve_private_values_and_exception_identity(monkeypatch, method, label, raises):
    marker = object()
    private = {"private-key-canary": "private-value-canary"}
    failure = RuntimeError("private-exception-canary")
    calls = []
    ticks = iter([100.0, 100.125])
    monkeypatch.setattr(diagnostic, "_phase_clock", lambda: next(ticks))

    def original(*args, **kwargs):
        calls.append((args, kwargs))
        if raises:
            raise failure
        return private

    publisher = SimpleNamespace(_client_request=None, **{method: original})
    with diagnostic.observe_publication(publisher) as observation:
        if raises:
            with pytest.raises(RuntimeError) as caught:
                getattr(publisher, method)(marker, captured=private)
            assert caught.value is failure
        else:
            assert getattr(publisher, method)(marker, captured=private) is private
        assert calls == [((marker,), {"captured": private})]
        description = observation.readiness.describe()
        outcome = "raised" if raises else "returned"
        assert f"preparation_{label}={outcome}; preparation_{label}_calls=1/1" in description
        assert f"preparation_{label}_elapsed_ms=125; preparation_{label}_max_ms=125" in description
        assert f"preparation_{label}_invalid_clock=0" in description
        assert "private" not in description and "canary" not in description
        # The observer's retained state contains no argument or result material.
        assert "private" not in repr(vars(observation.readiness))
    assert getattr(publisher, method) is original


@pytest.mark.parametrize(
    "started,ended,elapsed,invalid",
    [
        (1.0, 1e300, 999_999, 0),
        (1.0, 0.0, 0, 1),
        (float("nan"), 1.0, 0, 1),
        (1.0, float("inf"), 0, 1),
        (object(), 1.0, 0, 1),
    ],
)
def test_preparation_elapsed_summaries_reject_invalid_clocks_and_cap_counters(
    monkeypatch, started, ended, elapsed, invalid
):
    ticks = iter([started, ended] * 1001)
    monkeypatch.setattr(diagnostic, "_phase_clock", lambda: next(ticks))
    publisher = SimpleNamespace(_client_request=None, _publication_context=lambda: None)
    with diagnostic.observe_publication(publisher) as observation:
        for _ in range(1001):
            assert publisher._publication_context() is None
        description = observation.readiness.describe()
        assert "preparation_context_calls=999/999" in description
        assert f"preparation_context_elapsed_ms={elapsed}; preparation_context_max_ms={elapsed}" in description
        assert f"preparation_context_invalid_clock={999 if invalid else 0}" in description


def test_failed_phase_clock_preserves_original_call(monkeypatch):
    def failed_clock():
        raise RuntimeError("private-clock-canary")

    monkeypatch.setattr(diagnostic, "_phase_clock", failed_clock)
    marker = object()
    publisher = SimpleNamespace(_client_request=None, _compiled_effective_policy=lambda: marker)
    with diagnostic.observe_publication(publisher) as observation:
        assert publisher._compiled_effective_policy() is marker
        description = observation.readiness.describe()
        assert "preparation_config_invalid_clock=1" in description
        assert "private" not in description


def test_running_retry_preserves_completed_publication_flags_and_nested_phase_state(monkeypatch):
    started, release = threading.Event(), threading.Event()
    publisher = SimpleNamespace(
        _client_request=None,
        _epoch=2,
        _acked=False,
        _snapshot=None,
        _closed=False,
        _initial_database_capture_retry_used=True,
        _failure_count=1,
    )
    calls = []
    monkeypatch.setattr(diagnostic, "_phase_clock", lambda: 100.0)

    def configuration():
        started.set()
        assert release.wait(2)
        return {"private": "config-canary"}

    def command():
        return {"private": "command-canary"}

    def context():
        publisher._compiled_command_extensions()
        return publisher._compiled_effective_policy()

    def publish():
        calls.append(1)
        if len(calls) == 2:
            return publisher._publication_context()
        return None

    publisher._compiled_effective_policy, publisher._compiled_command_extensions = configuration, command
    publisher._publication_context, publisher._publish_once = context, publish
    with diagnostic.observe_publication(publisher) as observation:
        publisher._publish_once()
        worker = threading.Thread(target=publisher._publish_once)
        worker.start()
        try:
            assert started.wait(2)
            description = observation.readiness.describe(publisher)
            assert "publication=running; publication_calls=2/1" in description
            assert "publication_acked=no; publication_snapshot=missing; publication_closed=no" in description
            assert "publication_entry_epoch_unchanged=yes" in description
            assert "publication_last_completed=returned" in description
            assert "preparation_context=running; preparation_context_calls=1/0" in description
            assert "preparation_command=returned; preparation_command_calls=1/1" in description
            assert "preparation_config=running; preparation_config_calls=1/0" in description
            assert "initial_capture_retry_used=yes; publication_failure_count=1" in description
            assert "private" not in description and "canary" not in description
        finally:
            release.set()
            worker.join(2)
        assert not worker.is_alive() and len(calls) == 2
    assert publisher._publish_once is publish and publisher._publication_context is context
    assert publisher._compiled_effective_policy is configuration and publisher._compiled_command_extensions is command


@pytest.mark.parametrize(
    "used,failures,expected",
    [
        (False, 1001, "no; publication_failure_count=999"),
        ("private", object(), "unknown; publication_failure_count=unknown"),
    ],
)
def test_retry_facts_are_bounded_without_coercing_private_values(used, failures, expected):
    publisher = SimpleNamespace(_initial_database_capture_retry_used=used, _failure_count=failures)
    assert diagnostic._retry_facts(publisher) == "; initial_capture_retry_used=" + expected
