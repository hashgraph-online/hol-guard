"""Finite startup observation controls; no installed macOS runtime claim."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from ci.native_runtime import default_auto_failure as failure
from ci.native_runtime import default_auto_startup_failure as startup
from ci.native_runtime.default_auto_startup_failure import MAX_EVENTS, SmokePublicationObservation
from codex_plugin_scanner.guard import native_policy_test_support as support
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.store import GuardStore


@pytest.fixture
def owned(tmp_path, monkeypatch):
    home = tmp_path / "guard-home"
    publisher = NativePolicySnapshotPublisher(store=GuardStore(home))
    calls = []

    def factory(*args, **kwargs):
        calls.append((args, kwargs))
        return publisher

    monkeypatch.setattr(support, "get_native_policy_snapshot_publisher", factory)
    yield SimpleNamespace(home=home, publisher=publisher, calls=calls, factory=factory)
    publisher.close()


def _report(tmp_path: Path):
    return json.loads((tmp_path / "probe-failure.json").read_text())


def test_first_actual_publisher_errors_survive_later_circuit_and_original_helper_cleanup(tmp_path, monkeypatch, owned):
    publisher = owned.publisher
    original_error, original_close = publisher._record_error, publisher.close
    deadlines, thread_failures = [], []
    codes = [
        "native_resident_start_timeout",
        "native_resident_live_request_failed",
        "native_resident_restart_circuit_open",
    ]

    def wait(deadline):
        deadlines.append(deadline)

        def worker():
            try:
                for code in codes:
                    publisher._record_error(code)
            except BaseException as error:
                thread_failures.append(error)

        thread = threading.Thread(target=worker)
        thread.start()
        thread.join(5)
        assert not thread.is_alive() and not thread_failures
        return False

    monkeypatch.setattr(publisher, "start", lambda: None)
    monkeypatch.setattr(publisher, "wait_until_ready", wait)
    monkeypatch.setattr(support, "time", SimpleNamespace(monotonic=lambda: 100.0))
    started = time.monotonic()
    with (
        pytest.raises(AssertionError, match="native_resident_restart_circuit_open"),
        failure.DefaultAutoFailureCapture(tmp_path / "probe.json"),
        SmokePublicationObservation(owned.home),
        support.native_policy_snapshot(owned.home),
    ):
        pytest.fail("original unready helper must not yield")
    report = _report(tmp_path)
    observed = report["smoke_publication"]
    rows = observed["events"]
    assert [row["code"] for row in rows if row["kind"] == "publisher_error_recorded"] == codes
    assert [row["publisher"]["last_error"] for row in rows[:3]] == codes
    assert rows[-2]["kind"] == "before_publisher_close" and rows[-2]["publisher"]["closed"] is False
    assert rows[-1]["kind"] == "publisher_closed" and rows[-1]["publisher"]["closed"] is True
    assert publisher._failure_count == 3 and publisher._retry_not_before_monotonic > started
    assert len(deadlines) == len(owned.calls) == 1
    assert deadlines == [125.0 if support.sys.platform == "win32" else 103.0]
    assert publisher._record_error == original_error and publisher.close == original_close
    assert support.get_native_policy_snapshot_publisher is owned.factory
    assert observed["callbacks_restored"] and not observed["detail_incomplete"]
    assert observed["latency_qualification"] is observed["deadlines_changed"] is observed["retries_added"] is False
    assert report["original_failure_category"] == "AssertionError"


def test_success_emits_no_failure_and_forwards_exact_factory_result(tmp_path, owned):
    supplied = object()
    with (
        failure.DefaultAutoFailureCapture(tmp_path / "probe.json") as capture,
        SmokePublicationObservation(owned.home),
    ):
        assert support.get_native_policy_snapshot_publisher(supplied, marker="unchanged") is owned.publisher
        owned.publisher.close()
    assert owned.calls == [((supplied,), {"marker": "unchanged"})]
    assert capture._smoke_publication["callbacks_restored"] is True
    assert not (tmp_path / "probe-failure.json").exists()


def test_event_bound_and_unknown_error_labels_do_not_change_original_backoff(tmp_path, owned):
    with (
        pytest.raises(RuntimeError),
        failure.DefaultAutoFailureCapture(tmp_path / "probe.json"),
        SmokePublicationObservation(owned.home),
    ):
        support.get_native_policy_snapshot_publisher(object())
        for _ in range(MAX_EVENTS + 7):
            owned.publisher._record_error("private_unknown_error")
        owned.publisher.close()
        raise RuntimeError("PRIVATE_EXCEPTION_PAYLOAD")
    report = _report(tmp_path)
    observed = report["smoke_publication"]
    assert len(observed["events"]) == MAX_EVENTS
    assert observed["dropped_events"] == 9 and observed["detail_incomplete"] is True
    assert all(row["code"] == row["publisher"]["last_error"] == "other" for row in observed["events"])
    assert owned.publisher._failure_count == MAX_EVENTS + 7
    assert "private_unknown_error" not in json.dumps(report) and "PRIVATE" not in json.dumps(report)
    assert (tmp_path / "probe-failure.json").stat().st_size < 32 * 1024


@pytest.mark.parametrize("foreign", ["home", "thread"])
def test_other_home_or_factory_thread_never_attaches_callbacks(tmp_path, owned, foreign):
    original_error = owned.publisher._record_error
    with failure.DefaultAutoFailureCapture(tmp_path / "probe.json") as capture:
        home = tmp_path / "other-home" if foreign == "home" else owned.home
        with SmokePublicationObservation(home):
            if foreign == "thread":
                thread = threading.Thread(target=lambda: support.get_native_policy_snapshot_publisher(object()))
                thread.start()
                thread.join(5)
                assert not thread.is_alive()
            else:
                support.get_native_policy_snapshot_publisher(object())
            assert owned.publisher._record_error == original_error
            owned.publisher.close()
    assert capture._smoke_publication["publisher_bound"] is False
    assert capture._smoke_publication["events"] == []


def test_optional_event_collection_failure_never_masks_original(tmp_path, owned, monkeypatch):
    original = RuntimeError("original probe failure")

    def broken(*args):
        raise OSError("PRIVATE_COLLECTOR_FAILURE")

    with (
        pytest.raises(RuntimeError) as raised,
        failure.DefaultAutoFailureCapture(tmp_path / "probe.json"),
        SmokePublicationObservation(owned.home) as observation,
    ):
        monkeypatch.setattr(observation, "_event", broken)
        support.get_native_policy_snapshot_publisher(object())
        owned.publisher._record_error("native_resident_start_timeout")
        owned.publisher.close()
        raise original
    assert raised.value is original
    assert owned.publisher._failure_count == 1
    assert _report(tmp_path)["smoke_publication"]["detail_incomplete"] is True


def test_original_factory_failure_is_preserved_and_factory_restored(tmp_path, monkeypatch):
    original = OSError("PRIVATE_FACTORY_FAILURE")

    def broken(*args):
        raise original

    monkeypatch.setattr(support, "get_native_policy_snapshot_publisher", broken)
    with (
        pytest.raises(OSError) as raised,
        failure.DefaultAutoFailureCapture(tmp_path / "probe.json"),
        SmokePublicationObservation(tmp_path),
    ):
        support.get_native_policy_snapshot_publisher(object())
    assert raised.value is original
    assert support.get_native_policy_snapshot_publisher is broken
    assert _report(tmp_path)["smoke_publication"]["callbacks_restored"] is True


def test_busy_publisher_capture_does_not_wait_for_state_lock(tmp_path, owned):
    entered, release = threading.Event(), threading.Event()

    def hold():
        with owned.publisher._condition:
            entered.set()
            assert release.wait(5)

    thread = threading.Thread(target=hold)
    thread.start()
    try:
        assert entered.wait(5)
        with (
            failure.DefaultAutoFailureCapture(tmp_path / "probe.json") as capture,
            SmokePublicationObservation(owned.home) as observation,
        ):
            support.get_native_policy_snapshot_publisher(object())
            observation._safe_event("before_publisher_close")
            assert not release.is_set()
        assert capture._smoke_publication["events"][0]["publisher"] == {"available": False, "busy": True}
    finally:
        release.set()
        thread.join(5)
        owned.publisher.close()
    assert not thread.is_alive()


def test_known_error_is_normalized_even_when_state_is_busy(tmp_path, owned, monkeypatch):
    monkeypatch.setattr(startup, "_publisher_state", lambda _: {"available": False, "busy": True})
    with (
        failure.DefaultAutoFailureCapture(tmp_path / "probe.json") as capture,
        SmokePublicationObservation(owned.home) as observation,
    ):
        support.get_native_policy_snapshot_publisher(object())
        owned.publisher._record_error(" OSError ")
        observation._incomplete = True
        support.get_native_policy_snapshot_publisher(object())
        assert observation._incomplete is True
        owned.publisher.close()
    row = capture._smoke_publication["events"][0]
    assert row["code"] == "oserror" and row["publisher"] == {"available": False, "busy": True}
    assert owned.publisher._last_error == "oserror"


def test_original_callback_exception_is_not_suppressed(tmp_path, owned, monkeypatch):
    original = ValueError("original callback failure")

    def broken(error):
        assert error == "unchanged_argument"
        raise original

    monkeypatch.setattr(owned.publisher, "_record_error", broken)
    with (
        pytest.raises(ValueError) as raised,
        failure.DefaultAutoFailureCapture(tmp_path / "probe.json"),
        SmokePublicationObservation(owned.home),
    ):
        support.get_native_policy_snapshot_publisher(object())
        owned.publisher._record_error("unchanged_argument")
    assert raised.value is original
    assert owned.publisher._record_error is broken
    assert _report(tmp_path)["smoke_publication"]["events"] == []
