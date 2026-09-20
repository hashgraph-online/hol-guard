from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.config_source_io import GuardConfigSourceError, capture_guard_config
from codex_plugin_scanner.guard.daemon import hook_worker_responses
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.store import GuardStore
from scripts import native_slo_config_observer
from scripts.native_slo_config_observer import PublisherConfigObserver
from scripts.native_slo_contract import assert_privacy_safe
from scripts.native_slo_publisher_diagnostic import policy_refusal_diagnostic


@pytest.fixture
def publisher(tmp_path: Path):
    instance = NativePolicySnapshotPublisher(store=GuardStore(tmp_path / "guard"))
    try:
        yield instance
    finally:
        instance.close()


def _failure() -> GuardConfigSourceError:
    cause = OSError(32, "private contents and path", "private-config.toml")
    cause.winerror = 32
    error = GuardConfigSourceError("guard_config_source_unavailable")
    error.__cause__ = cause
    return error


def _caught_record(publisher, error: Exception) -> None:
    try:
        raise error
    except Exception as caught:
        publisher._record_error(type(caught).__name__)


def _refusal(publisher) -> dict[str, object]:
    server = SimpleNamespace(hook_worker=SimpleNamespace(policy_snapshot_publisher=publisher))
    return policy_refusal_diagnostic(hook_worker_responses._native_policy_not_ready_reason(server))


def test_real_publisher_catch_retains_original_capture_cause_without_text(
    publisher, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard import config_source_io

    config = tmp_path / "config.toml"
    config.write_bytes(b'default_action = "block"\n')
    cause = OSError(32, "private marker and config contents", "private-config.toml")

    def fail_read(*_args):
        raise cause

    monkeypatch.setattr(config_source_io, "_read_descriptor", fail_read)

    def context():
        return capture_guard_config(config)

    monkeypatch.setattr(publisher, "_publication_context", context)
    original = publisher._record_error
    with PublisherConfigObserver(publisher) as observer:
        publisher._publish_once()
        assert publisher.last_error == "guardconfigsourceerror"
        assert publisher._failure_count == 1
        detail = observer.evidence(observer.stamp(), _refusal(publisher))
        assert detail is not None
        assert detail["category"] == "GuardConfigSourceError"
        assert detail["origin"] == "config_source_io.capture_guard_config"
        assert detail["config_cause_1_category"] == type(cause).__name__
        assert detail["config_cause_1_errno"] == 32
        assert detail["observer_generation"] == 2
        identity = detail["observer"]
        assert isinstance(identity, dict)
        assert identity["installed"] is True
        assert len(identity["observer_sha256"]) == 64
        assert len(identity["exporter_sha256"]) == 64
        serialized = json.dumps(assert_privacy_safe(detail))
        assert str(tmp_path) not in serialized and "private-config.toml" not in serialized
    assert publisher._record_error == original
    assert "_record_error" not in publisher.__dict__
    assert observer.evidence(2, _refusal(publisher)) is None


def test_owned_instance_and_record_generation_are_required(publisher, tmp_path: Path) -> None:
    other = NativePolicySnapshotPublisher(store=GuardStore(tmp_path / "other"))
    try:
        with PublisherConfigObserver(publisher) as observer:
            _caught_record(other, _failure())
            assert observer.stamp() is None
            _caught_record(publisher, _failure())
            stamp = observer.stamp()
            detail = observer.evidence(stamp, _refusal(publisher))
            assert detail is not None and detail["config_cause_1_winerror"] == 32
            _caught_record(publisher, _failure())
            assert observer.evidence(stamp, _refusal(publisher)) is None
            stamp = observer.stamp()
            publisher._record_error("native_policy_snapshot_expired")
            assert observer.evidence(stamp, _refusal(publisher)) is None
            assert observer.stamp() is None
    finally:
        other.close()


def test_uncaught_or_wrong_exception_does_not_reuse_prior_cause(publisher) -> None:
    with PublisherConfigObserver(publisher) as observer:
        _caught_record(publisher, _failure())
        publisher._record_error("guardconfigsourceerror")
        assert observer.stamp() is None
        try:
            raise OSError(32, "sensitive detail")
        except OSError:
            publisher._record_error("guardconfigsourceerror")
        assert observer.stamp() is None


def test_optional_exporter_failure_preserves_original_recorder(publisher, monkeypatch: pytest.MonkeyPatch) -> None:
    def unavailable(_error):
        raise RuntimeError("private serializer failure")

    monkeypatch.setattr(native_slo_config_observer, "_caught_config_failure", unavailable)
    with PublisherConfigObserver(publisher) as observer:
        _caught_record(publisher, _failure())
        assert publisher.last_error == "guardconfigsourceerror"
        assert publisher._failure_count == 1
        assert observer.stamp() is None


def test_original_return_exception_and_instance_override_are_preserved(
    publisher, monkeypatch: pytest.MonkeyPatch
) -> None:
    returned = object()
    failure = RuntimeError("original recorder failed")
    calls = []

    def recorder(*args, **kwargs):
        calls.append((args, kwargs))
        if kwargs.get("fail"):
            raise failure
        return returned

    monkeypatch.setattr(publisher, "_record_error", recorder)
    with pytest.raises(RuntimeError) as caught, PublisherConfigObserver(publisher) as observer:
        assert publisher._record_error("same", flag=returned) is returned
        publisher._record_error("guardconfigsourceerror", fail=True)
    assert caught.value is failure
    assert publisher._record_error is recorder
    assert calls == [(("same",), {"flag": returned}), (("guardconfigsourceerror",), {"fail": True})]
    assert observer.stamp() is None


def test_in_flight_or_overlapping_records_cannot_be_attributed(publisher, monkeypatch: pytest.MonkeyPatch) -> None:
    original = publisher._record_error
    entered = threading.Event()
    release = threading.Event()

    def blocked(error):
        if threading.current_thread().name.startswith("blocked-publisher"):
            entered.set()
            assert release.wait(2)
        original(error)

    monkeypatch.setattr(publisher, "_record_error", blocked)
    with PublisherConfigObserver(publisher) as observer, ThreadPoolExecutor(
        max_workers=1, thread_name_prefix="blocked-publisher"
    ) as pool:
        _caught_record(publisher, _failure())
        stamp = observer.stamp()
        pending = pool.submit(_caught_record, publisher, _failure())
        try:
            assert entered.wait(2)
            assert observer.stamp() is None
            assert observer.evidence(stamp, _refusal(publisher)) is None
            _caught_record(publisher, _failure())
        finally:
            release.set()
        pending.result(timeout=2)
        assert observer.stamp() is None


def test_unavailable_api_is_explicit_and_untouched() -> None:
    publisher = SimpleNamespace()
    with PublisherConfigObserver(publisher) as observer:
        assert observer.identity["installed"] is False
        assert observer.stamp() is None
    assert vars(publisher) == {}
