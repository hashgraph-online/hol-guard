"""Actual Store/capture/reservation controls; only resident replies are synthetic."""

import hashlib
import json
import threading
import time
from contextlib import closing
from datetime import datetime
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_policy_publication_lock import hold_policy_publication_mutation
from codex_plugin_scanner.guard.native_policy_snapshot_constants import POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION
from codex_plugin_scanner.guard.native_policy_snapshot_generation import _v3_generation_for_policy
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_policy_snapshot_publisher_scoped import SCOPED_PUBLISH_FEATURES
from codex_plugin_scanner.guard.native_policy_snapshot_storage import _read_v3_generation_state
from codex_plugin_scanner.guard.store import GuardStore
from tests.native_policy_snapshot_test_fixtures import _ack as v3_ack
from tests.native_policy_snapshot_test_fixtures import _status
from tests.test_canonical_policy_row_authority import _NOW, _activated_store
from tests.test_native_policy_snapshot_v4_barrier import _resident
from tests.test_native_policy_snapshot_v4_publication import _ack as v4_ack

_NOW_SECONDS = datetime.fromisoformat(_NOW.replace("Z", "+00:00")).timestamp()


def _reserve_retirement(home: Path) -> int:
    current = _read_v3_generation_state(home)
    return _v3_generation_for_policy(
        home,
        "f" * 64,
        deadline_monotonic=time.monotonic() + 5,
        force_increment=True,
        minimum_generation=(current[0] if current else 1) + 10,
    )


def _make_publisher(store, calls, during=None, scoped=True):
    status = _status()
    if scoped:
        status.capabilities.features += tuple(SCOPED_PUBLISH_FEATURES)

    def client(**kwargs):
        snapshot = json.loads(kwargs["payload"])["request"]["snapshot"]
        calls.append(snapshot)
        _resident(store.guard_home)
        reply_status = during(snapshot) if during is not None else "accepted"
        if "source_input_digest" in snapshot:
            return json.dumps(v4_ack(snapshot, status=reply_status)).encode()
        reply = json.loads(v3_ack(kwargs["payload"], resident_generation=3))
        reply["status"] = reply_status
        reply["idempotent"] = False
        return json.dumps(reply).encode()

    return NativePolicySnapshotPublisher(
        store=store,
        status_provider=lambda: status,
        client_request=client,
        wall_clock=(lambda: _NOW_SECONDS) if scoped else time.time,
    )


def test_unchanged_actual_signed_source_publishes(tmp_path):
    store = _activated_store(tmp_path)
    calls = []
    with closing(_make_publisher(store, calls)) as publisher:
        publisher._publish_once()
        assert publisher.is_ready(), publisher.last_error
        assert len(calls) == 1 and calls[0]["scoped_authority"]["rows"]


def test_rotated_source_is_not_reserved_after_capture(tmp_path, monkeypatch):
    store = _activated_store(tmp_path)
    calls = []
    retired = []
    with closing(_make_publisher(store, calls)) as publisher:
        original = publisher._publication_context

        def rotate_after_actual_capture(*, publish_epoch=None, prepared_command_extensions=None):
            context = original(publish_epoch=publish_epoch, prepared_command_extensions=prepared_command_extensions)
            assert context is not None
            previous = store.get_or_create_installation_id()
            assert store.rotate_installation_id(_NOW)["installation_id"] != previous
            retired.append(_reserve_retirement(store.guard_home))
            return context

        monkeypatch.setattr(publisher, "_publication_context", rotate_after_actual_capture)
        publisher._publish_once()
        assert not publisher.is_ready()
        # The old captured authority must not obtain a new reservation after retirement.
        assert calls == [], (len(calls), retired, [x["generation"] for x in calls])


def test_retry_recaptures_source_before_reserving_after_rotation(tmp_path):
    store = _activated_store(tmp_path)
    calls = []
    retired = []

    def rotate_during_first_push(snapshot):
        if len(calls) == 1:
            previous = store.get_or_create_installation_id()
            assert store.rotate_installation_id(_NOW)["installation_id"] != previous
            retired.append(_reserve_retirement(store.guard_home))
            return POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION
        return "accepted"

    with closing(_make_publisher(store, calls, during=rotate_during_first_push)) as publisher:
        publisher._publish_once()
        assert not publisher.is_ready()
        assert len(calls) == 1, (len(calls), retired, [x["generation"] for x in calls])


def test_source_free_v3_recovers_above_reserved_retirement(tmp_path):
    store = GuardStore(tmp_path / "empty")
    calls = []
    with closing(_make_publisher(store, calls, scoped=False)) as publisher:
        publisher._publish_once()
        assert publisher.is_ready(), publisher.last_error
        first = calls[0]["generation"]
        floor = _reserve_retirement(store.guard_home)
        assert floor > first
        publisher.request_publish()
        publisher._publish_once()
        assert publisher.is_ready(), publisher.last_error
        assert len(calls) == 2 and calls[1]["generation"] > floor


@pytest.mark.parametrize("scoped", [False, True])
def test_existing_retry_recaptures_actual_changed_configuration(tmp_path, scoped):
    store = _activated_store(tmp_path) if scoped else GuardStore(tmp_path / "empty")
    calls = []

    def change_during_first_push(snapshot):
        if len(calls) == 1:
            with hold_policy_publication_mutation(store.guard_home):
                (store.guard_home / "config.toml").write_text('mode = "observe"\n')
            return POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION
        return "accepted"

    publisher = _make_publisher(store, calls, during=change_during_first_push, scoped=scoped)
    with closing(publisher):
        publisher._publish_once()
        assert publisher.is_ready(), publisher.last_error
        assert len(calls) == 2
        assert calls[0]["mode"] == "enforce" and calls[1]["mode"] == "observe"
        assert calls[1]["generation"] > calls[0]["generation"]
        assert publisher._snapshot == calls[1]


@pytest.mark.parametrize("scoped", [False, True])
def test_complete_capture_is_serialized_and_transport_releases_mutation_lock(tmp_path, monkeypatch, scoped):
    store = _activated_store(tmp_path) if scoped else GuardStore(tmp_path / "empty")
    calls = []
    admitted = threading.Event()
    start = threading.Event()
    complete = threading.Event()
    errors = []

    def writer():
        assert start.wait(2)
        try:
            with hold_policy_publication_mutation(store.guard_home, timeout_seconds=1):
                admitted.set()
        except BaseException as error:
            errors.append(error)
        finally:
            complete.set()

    thread = threading.Thread(target=writer)
    thread.start()
    with closing(_make_publisher(store, calls, scoped=scoped)) as publisher:
        original = publisher._publication_context
        captures = []

        def capture(*, publish_epoch=None, prepared_command_extensions=None):
            value = original(publish_epoch=publish_epoch, prepared_command_extensions=prepared_command_extensions)
            captures.append(value)
            if len(captures) == 2:
                start.set()
                assert not admitted.wait(0.03)
            return value

        client = publisher._client_request
        assert client is not None

        def transport(**kwargs):
            assert complete.wait(1) and admitted.is_set() and not errors
            return client(**kwargs)

        monkeypatch.setattr(publisher, "_publication_context", capture)
        monkeypatch.setattr(publisher, "_client_request", transport)
        try:
            publisher._publish_once()
            assert publisher.is_ready(), publisher.last_error
            assert len(captures) == 2 and len(calls) == 1
        finally:
            start.set()
            thread.join(timeout=2)
    assert not thread.is_alive() and not errors


def test_v3_superseded_cache_recovery_keeps_default_strict_and_refuses_bad_state(tmp_path):
    from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
    from codex_plugin_scanner.guard.native_policy_snapshot_generation import native_policy_snapshot_v3
    from tests.native_policy_snapshot_test_fixtures import _config
    from tests.test_native_policy_snapshot_retirement import _MASTER, _RUNTIME, _snapshot

    home = tmp_path / "guard"
    home.mkdir(mode=0o700)
    first = _snapshot(home)
    floor = _reserve_retirement(home)
    with pytest.raises(NativePolicySnapshotError, match="generation_state_invalid"):
        _snapshot(home)
    recovered = native_policy_snapshot_v3(
        config=_config(),
        guard_home=home,
        runtime_identity=_RUNTIME,
        rule_digest="b" * 64,
        policy_integrity_key=_MASTER,
        allow_superseded_cache=True,
    )
    recovered_generation = recovered["generation"]
    first_generation = first["generation"]
    assert isinstance(recovered_generation, int) and isinstance(first_generation, int)
    assert recovered_generation > floor > first_generation


@pytest.mark.parametrize("changed_config", [False, True])
@pytest.mark.parametrize("corruption", ["cache", "missing", "behind", "conflict"])
def test_fresh_v3_capture_never_repairs_corrupt_missing_or_conflicting_state(tmp_path, changed_config, corruption):
    from codex_plugin_scanner.guard import native_policy_snapshot_storage as storage
    from codex_plugin_scanner.guard.native_policy_snapshot_constants import (
        _V3_GENERATION_STATE_NAME,
        NATIVE_POLICY_SNAPSHOT_CACHE_NAME,
        NativePolicySnapshotError,
    )
    from codex_plugin_scanner.guard.native_policy_snapshot_generation import native_policy_snapshot_v3
    from tests.native_policy_snapshot_test_fixtures import _config
    from tests.test_native_policy_snapshot_retirement import _MASTER, _RUNTIME, _snapshot

    home = tmp_path / "guard"
    home.mkdir(mode=0o700)
    first = _snapshot(home)
    counter = home / _V3_GENERATION_STATE_NAME
    cache = home / "native-runtime" / NATIVE_POLICY_SNAPSHOT_CACHE_NAME
    if corruption == "cache":
        cache.write_bytes(b"{}")
    elif corruption == "missing":
        counter.unlink()
    elif corruption == "behind":
        storage._write_v3_snapshot_cache(home, _snapshot(home, generation=2))
    else:
        first_generation = first["generation"]
        assert isinstance(first_generation, int)
        storage._write_v3_generation_state(home, generation=first_generation, policy_digest="e" * 64)
    before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (counter, cache) if p.exists()}
    config = _config()
    if changed_config:
        config["mode"] = "observe"
    with pytest.raises(NativePolicySnapshotError):
        native_policy_snapshot_v3(
            config=config,
            guard_home=home,
            runtime_identity=_RUNTIME,
            rule_digest="b" * 64,
            policy_integrity_key=_MASTER,
            allow_superseded_cache=True,
        )
    assert {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (counter, cache) if p.exists()} == before


@pytest.mark.parametrize("scoped", [False, True])
@pytest.mark.parametrize("withdrawal", ["identity", "capability", "disabled", "closed"])
def test_recovery_retry_refuses_changed_runtime_or_closed_publisher(tmp_path, scoped, withdrawal):
    from types import SimpleNamespace

    store = _activated_store(tmp_path) if scoped else GuardStore(tmp_path / "empty")
    calls = []
    publisher: NativePolicySnapshotPublisher

    def change_during_first_push(snapshot):
        assert publisher._status_provider is not None
        previous = publisher._status_provider()
        replacement = SimpleNamespace(**vars(previous))
        if withdrawal == "identity":
            replacement.identity = SimpleNamespace(**vars(previous.identity))
            replacement.identity.sha256 = "e" * 64
        elif withdrawal == "capability":
            replacement.capabilities = SimpleNamespace(**vars(previous.capabilities))
            replacement.capabilities.features = ()
        elif withdrawal == "disabled":
            replacement.mode = "off"
        else:
            publisher.close()
        publisher._status_provider = lambda: replacement
        return POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION

    publisher = _make_publisher(store, calls, during=change_during_first_push, scoped=scoped)
    with closing(publisher):
        publisher._publish_once()
        assert not publisher.is_ready()
        assert len(calls) == 1
        state = _read_v3_generation_state(store.guard_home)
        assert state is not None and state[0] == calls[0]["generation"]


@pytest.mark.parametrize("scoped", [False, True])
def test_fresh_capture_preserves_existing_publication_lock_wait_ceiling(tmp_path, monkeypatch, scoped):
    from contextlib import contextmanager

    from codex_plugin_scanner.guard import native_policy_snapshot_publisher_context as preparation

    store = _activated_store(tmp_path) if scoped else GuardStore(tmp_path / "empty")
    actual_lock = preparation.hold_policy_publication_mutation
    timeouts = []

    @contextmanager
    def observed_lock(guard_home, *, timeout_seconds):
        timeouts.append(timeout_seconds)
        with actual_lock(guard_home, timeout_seconds=timeout_seconds):
            yield

    with closing(_make_publisher(store, [], scoped=scoped)) as publisher:
        context = publisher._publication_context()
        assert context is not None
        monkeypatch.setattr(preparation, "hold_policy_publication_mutation", observed_lock)
        with preparation.capture_for_reservation(
            publisher,
            expected=context,
            publish_epoch=publisher._epoch,
            deadline_monotonic=time.monotonic() + 30,
        ) as captured:
            assert captured is not None
        assert timeouts == [5.0]
