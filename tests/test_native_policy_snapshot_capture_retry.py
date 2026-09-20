"""Retry a coherent reservation after a real non-policy startup write."""

from __future__ import annotations

import time
from collections.abc import Callable
from contextlib import closing

import pytest

from codex_plugin_scanner.guard.native_policy_authority_read import read_native_policy_authority_inputs
from codex_plugin_scanner.guard.native_policy_snapshot_constants import (
    _PUBLISH_TIMEOUT_SECONDS,
    NativePolicySnapshotError,
)
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_policy_snapshot_publisher_context import (
    CapturedV3PublicationInputs,
    capture_for_reservation,
)
from codex_plugin_scanner.guard.native_policy_snapshot_storage import _read_v3_generation_state
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_native_policy_snapshot_reservation_capture import _make_publisher


def _write_startup_status(store: GuardStore, write_number: int, *, now: float) -> tuple[int, int]:
    # The daemon's no-credentials refresh writes this same non-policy state.
    stamp = f"2026-09-19T00:00:{write_number:02d}Z"
    payload = {"status": "not_configured", "refreshed_at": stamp}
    with store._connect() as observer:
        before = read_native_policy_authority_inputs(store, now=now)
        before_version = observer.execute("pragma data_version").fetchone()[0]
        store.set_sync_payload("supply_chain_bundle_daemon", payload, stamp)
        after_version = observer.execute("pragma data_version").fetchone()[0]
        after = read_native_policy_authority_inputs(store, now=now)
    assert before_version != after_version
    assert before.input_digest == after.input_digest
    assert store.get_sync_payload("supply_chain_bundle_daemon") == payload
    return before_version, after_version


def _interrupt_reservation(
    publisher: NativePolicySnapshotPublisher,
    monkeypatch: pytest.MonkeyPatch,
    *,
    repeated: bool = False,
    after_write: Callable[[], None] | None = None,
) -> tuple[list[CapturedV3PublicationInputs], list[tuple[int, int]]]:
    original = publisher._publication_context
    captures: list[CapturedV3PublicationInputs] = []
    writes: list[tuple[int, int]] = []

    def capture(*, publish_epoch: int | None = None, prepared_command_extensions=None):
        context = original(publish_epoch=publish_epoch, prepared_command_extensions=prepared_command_extensions)
        assert context is not None
        inputs = context[5]
        assert isinstance(inputs, CapturedV3PublicationInputs)
        captures.append(inputs)
        if len(captures) == 2 or (repeated and len(captures) > 2):
            writes.append(_write_startup_status(publisher.store, len(writes) + 1, now=publisher._wall_clock()))
            if after_write is not None:
                after_write()
        return context

    monkeypatch.setattr(publisher, "_publication_context", capture)
    return captures, writes


@pytest.mark.parametrize("repeated", [False, True], ids=["one-startup-write", "repeated-startup-writes"])
def test_startup_status_commit_requires_a_fresh_stable_capture(tmp_path, monkeypatch, repeated):
    store = GuardStore(tmp_path / "guard-home")
    calls = []
    with closing(_make_publisher(store, calls, scoped=False)) as publisher:
        initial_epoch = publisher._epoch
        captures, writes = _interrupt_reservation(publisher, monkeypatch, repeated=repeated)
        publisher._publish_once()
        assert writes and all(before != after for before, after in writes)
        assert publisher._epoch == initial_epoch
        assert all(capture.input_digest == captures[0].input_digest for capture in captures)
        if repeated:
            assert not publisher.is_ready()
            assert publisher.current_snapshot_binding() is None
            assert publisher._snapshot is None and calls == []
            assert publisher.last_error == "native_policy_authority_capture_changed"
            assert publisher._failure_count == 1
            assert publisher._retry_not_before_monotonic is not None
            assert _read_v3_generation_state(store.guard_home) is None
            assert 1 <= len(writes) <= 2
            assert len(captures) <= 3
        else:
            assert publisher.is_ready(), publisher.last_error
            assert len(writes) == 1 and len(captures) == 3
            assert len(calls) == 1 and publisher.current_snapshot() == calls[0]
            assert publisher._published_cloud_inputs == captures[-1]
            assert publisher.last_error is None
            assert publisher._failure_count == 0
            assert publisher._retry_not_before_monotonic is None


@pytest.mark.parametrize("mutation", ["request", "close"])
def test_startup_capture_retry_cannot_outlive_its_epoch(tmp_path, monkeypatch, mutation):
    store = GuardStore(tmp_path / "guard-home")
    calls = []
    with closing(_make_publisher(store, calls, scoped=False)) as publisher:
        initial_epoch = publisher._epoch
        captures, writes = _interrupt_reservation(
            publisher,
            monkeypatch,
            after_write=publisher.request_publish if mutation == "request" else publisher.close,
        )
        publisher._publish_once()
        assert len(writes) == 1 and len(captures) == 2
        assert publisher._epoch == initial_epoch + int(mutation == "request")
        assert publisher.closed is (mutation == "close")
        assert publisher._publish_event.is_set()
        assert not publisher.is_ready()
        assert publisher.current_snapshot_binding() is None
        assert publisher._snapshot is None and calls == []
        assert publisher.last_error is None
        assert publisher._failure_count == 0
        assert publisher._retry_not_before_monotonic is None
        assert _read_v3_generation_state(store.guard_home) is None


def test_capture_retry_never_replays_an_exception_after_yield(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "guard-home")
    calls = []
    with closing(_make_publisher(store, calls, scoped=False)) as publisher:
        expected = publisher._publication_context()
        assert expected is not None
        original = publisher._publication_context
        captures = []

        def capture(*, publish_epoch=None, prepared_command_extensions=None):
            context = original(publish_epoch=publish_epoch, prepared_command_extensions=prepared_command_extensions)
            captures.append(context is not None)
            return context

        monkeypatch.setattr(publisher, "_publication_context", capture)
        failure = NativePolicySnapshotError("native_policy_authority_capture_changed")
        yielded = []
        with (
            pytest.raises(NativePolicySnapshotError) as caught,
            capture_for_reservation(
                publisher,
                expected=expected,
                publish_epoch=publisher._epoch,
                deadline_monotonic=time.monotonic() + _PUBLISH_TIMEOUT_SECONDS,
            ) as context,
        ):
            yielded.append(context is not None)
            raise failure
        assert caught.value is failure
        assert captures == [True] and yielded == [True]
        assert not publisher.is_ready() and calls == []
        assert _read_v3_generation_state(store.guard_home) is None
