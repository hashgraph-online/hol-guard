"""Controlled authenticated transport with actual Store/counter/serialization.

The native side is an explicit protocol fixture, not a resident/socket claim.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
from pathlib import Path
from typing import TypedDict

import pytest

from codex_plugin_scanner.guard import native_policy_snapshot_control as control
from codex_plugin_scanner.guard import native_policy_snapshot_rotation as rotation
from codex_plugin_scanner.guard.native_policy_snapshot_codec import (
    _canonical_json_bytes_v3 as canonical,
)
from codex_plugin_scanner.guard.native_policy_snapshot_codec import (
    derive_native_policy_verifier_key,
)
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from codex_plugin_scanner.guard.native_policy_snapshot_storage import _read_v3_generation_state, _v3_generation_lock
from codex_plugin_scanner.guard.native_runtime import NativeRuntimeIdentity, NativeRuntimeStatus
from codex_plugin_scanner.guard.native_runtime_capabilities import NativeRuntimeCapabilities
from codex_plugin_scanner.guard.sqlite_tuning import sqlite_connect_timeout_override
from codex_plugin_scanner.guard.store import GuardStore

MASTER = b"r" * 32
RUNTIME = "a" * 64


class _Observed(TypedDict):
    operations: list[str]
    withdrawn: threading.Event
    completed: threading.Event
    events: list[threading.Event]


def _native_fixture(tmp_path, monkeypatch, *, response_mode="valid", release=None, actual_key=False):
    store = GuardStore(tmp_path / "guard")
    state = store.guard_home / "native-runtime"
    state.mkdir(mode=0o700)
    if actual_key:
        master, _ = store._policy_integrity_secret_material(create=True)
        assert type(master) is bytes and len(master) == 32
    else:
        master = MASTER
        monkeypatch.setattr(
            store,
            "_policy_integrity_secret_material",
            lambda *, create: (master, "test-key") if not create else pytest.fail("new key"),
        )
    status = NativeRuntimeStatus(
        "auto",
        True,
        True,
        "ready",
        NativeRuntimeIdentity(tmp_path / "runtime", 1, 1, RUNTIME),
        NativeRuntimeCapabilities(1, "3.0.1", "test", "test", "test", ("policy-snapshot-control-v1",)),
    )
    monkeypatch.setattr(rotation, "_native_policy_control_runtime_status_owned", lambda **kwargs: status)
    key = derive_native_policy_verifier_key(master)
    observed: _Observed = {
        "operations": [],
        "withdrawn": threading.Event(),
        "completed": threading.Event(),
        "events": [],
    }

    def client(**kwargs):
        outer = json.loads(kwargs["payload"])
        request = outer["request"]
        intent = request["intent"]
        operation = outer["operation"]
        observe = operation == "policy_snapshot_observe"
        domain = control._OBSERVATION_DOMAIN if observe else control._WITHDRAWAL_DOMAIN
        assert request["mac"] == hmac.new(key, domain + canonical(intent), hashlib.sha256).hexdigest()
        # A second real file-lock acquisition proves generation ownership is
        # released before both calls into the transport fixture.
        with _v3_generation_lock(store.guard_home, deadline_monotonic=kwargs["deadline_monotonic"]):
            pass
        observed["operations"].append(operation)
        observed["events"].append(kwargs["cancelled"])
        base = {
            "runtime_identity": RUNTIME,
            "scope_digest": intent["scope_digest"],
            "resident_generation": 13,
            "request_sha256": hashlib.sha256(canonical(request)).hexdigest(),
        }
        if observe:
            response = {
                **base,
                "schema": "guard-policy-snapshot-observation-response.v1",
                "nonce": intent["nonce"],
                "authority": {
                    "fingerprint": "b" * 64,
                    "generation_floor": 7,
                    "policy_digest": "c" * 64,
                    "usable_snapshot": True,
                },
            }
            response_domain = control._OBSERVATION_RESPONSE_DOMAIN
        else:
            observed["withdrawn"].set()
            response = {
                **base,
                "schema": "guard-policy-snapshot-withdrawal-response.v1",
                "status": "withdrawn",
                "generation": intent["retirement_generation"],
                "policy_digest": intent["retirement_policy_digest"],
            }
            response_domain = control._WITHDRAWAL_RESPONSE_DOMAIN
            if release is not None:
                assert release.wait(2)
            observed["completed"].set()
            if response_mode == "lost":
                return None
        mac = hmac.new(key, response_domain + canonical(response), hashlib.sha256).hexdigest()
        if not observe and response_mode == "tampered":
            mac = "0" * 64
        return canonical({"response": response, "mac": mac})

    monkeypatch.setattr(rotation, "_native_policy_control_request_owned", client)
    return store, observed


def test_cold_installation_uses_no_runtime_or_key_and_returns_transaction_metadata(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "cold")
    old = store.get_device_metadata()
    monkeypatch.setattr(
        rotation, "_native_policy_control_runtime_status_owned", lambda **k: pytest.fail("runtime on cold path")
    )
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda **k: pytest.fail("key on cold path"))
    monkeypatch.setattr(store, "get_device_metadata", lambda: pytest.fail("metadata read after transaction"))
    result = store.rotate_installation_id("test")
    assert result["installation_id"] != old["installation_id"]
    assert result["device_label"] == old["device_label"]
    assert not (store.guard_home / "native-runtime").exists()
    assert not (store.guard_home / "native-policy-snapshot-generation-v3.json").exists()


@pytest.mark.parametrize(
    "name",
    [
        "native-runtime",
        "native-policy-generation.json",
        "native-policy-generation.lock",
        "native-policy-snapshot-generation-v3.json",
        "native-policy-snapshot-generation-v3.lock",
    ],
)
def test_any_native_history_requires_authenticated_control(tmp_path, monkeypatch, name):
    store = GuardStore(tmp_path / "guard")
    old = store.get_device_metadata()
    path = store.guard_home / name
    if name == "native-runtime":
        path.mkdir()
    else:
        path.write_text("malformed history")
    monkeypatch.setattr(
        rotation,
        "_native_policy_control_runtime_status_owned",
        lambda **k: NativeRuntimeStatus("off", False, False, "off"),
    )
    with pytest.raises(NativePolicySnapshotError, match="runtime_unavailable"):
        store.rotate_installation_id("test")
    assert store.get_device_metadata() == old


def test_unreadable_history_is_not_absence(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "guard")
    old = store.get_device_metadata()
    original = Path.lstat

    def lstat(path, *args, **kwargs):
        if path == store.guard_home / "native-runtime":
            raise PermissionError("synthetic")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", lstat)
    with pytest.raises(NativePolicySnapshotError, match="history_unavailable"):
        store.rotate_installation_id("test")
    assert store.get_device_metadata() == old


def test_authenticated_withdrawal_and_real_reservation_precede_sql(tmp_path, monkeypatch):
    store, observed = _native_fixture(tmp_path, monkeypatch)
    old = store.get_device_metadata()
    original = store._replace_remote_policy_rows_locked

    def replace(*args, **kwargs):
        assert observed["withdrawn"].is_set()
        return original(*args, **kwargs)

    monkeypatch.setattr(store, "_replace_remote_policy_rows_locked", replace)
    with sqlite_connect_timeout_override(1):
        result = store.rotate_installation_id("test")
    assert result["installation_id"] != old["installation_id"]
    state = _read_v3_generation_state(store.guard_home)
    assert state is not None and state[0] == 8
    assert observed["operations"] == ["policy_snapshot_observe", "policy_snapshot_withdraw"]
    assert observed["events"][0] is observed["events"][1]


@pytest.mark.parametrize("mode", ["lost", "tampered"])
def test_ambiguous_or_invalid_retirement_ack_never_runs_sql(tmp_path, monkeypatch, mode):
    store, observed = _native_fixture(tmp_path, monkeypatch, response_mode=mode)
    old = store.get_device_metadata()
    with pytest.raises(NativePolicySnapshotError):
        store.rotate_installation_id("test")
    assert observed["withdrawn"].is_set()
    assert store.get_device_metadata() == old
    state = _read_v3_generation_state(store.guard_home)
    assert state is not None and state[0] == 8


def test_late_valid_ack_never_authorizes_later_sql(tmp_path, monkeypatch):
    release = threading.Event()
    store, observed = _native_fixture(tmp_path, monkeypatch, release=release)
    old = store.get_device_metadata()
    try:
        with sqlite_connect_timeout_override(0.10), pytest.raises(NativePolicySnapshotError, match="deadline_exceeded"):
            store.rotate_installation_id("test")
        assert observed["withdrawn"].is_set()
        assert store.get_device_metadata() == old
    finally:
        release.set()
    assert observed["completed"].wait(1)
    # Reacquiring the real publication lock waits for all owner cleanup.
    from codex_plugin_scanner.guard.native_policy_publication_lock import hold_policy_publication_mutation

    with hold_policy_publication_mutation(store.guard_home, timeout_seconds=1):
        assert store.get_device_metadata() == old


def test_sql_failure_keeps_retirement_and_rolls_back_only_sql(tmp_path, monkeypatch):
    store, observed = _native_fixture(tmp_path, monkeypatch)
    old = store.get_device_metadata()

    def refuse(*args, **kwargs):
        raise RuntimeError("synthetic SQL failure")

    monkeypatch.setattr(store, "_replace_remote_policy_rows_locked", refuse)
    with pytest.raises(RuntimeError, match="synthetic SQL failure"):
        store.rotate_installation_id("test")
    assert observed["withdrawn"].is_set()
    assert store.get_device_metadata() == old
    state = _read_v3_generation_state(store.guard_home)
    assert state is not None and state[0] == 8
    assert observed["operations"] == ["policy_snapshot_observe", "policy_snapshot_withdraw"]


def test_late_runtime_setup_cannot_start_key_control_or_sql(tmp_path, monkeypatch):
    store, observed = _native_fixture(tmp_path, monkeypatch)
    old = store.get_device_metadata()
    release = threading.Event()
    complete = threading.Event()
    original = rotation._native_policy_control_runtime_status_owned

    def status(**kwargs):
        try:
            assert release.wait(2)
            return original(**kwargs)
        finally:
            complete.set()

    monkeypatch.setattr(rotation, "_native_policy_control_runtime_status_owned", status)
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda **k: pytest.fail("late key"))
    try:
        with sqlite_connect_timeout_override(0.03), pytest.raises(NativePolicySnapshotError, match="deadline_exceeded"):
            store.rotate_installation_id("test")
    finally:
        release.set()
    assert complete.wait(1)
    from codex_plugin_scanner.guard.native_policy_publication_lock import hold_policy_publication_mutation

    with hold_policy_publication_mutation(store.guard_home, timeout_seconds=1):
        assert store.get_device_metadata() == old
        assert observed["operations"] == []


def test_existing_real_store_key_is_read_without_reprovisioning(tmp_path, monkeypatch):
    store, observed = _native_fixture(tmp_path, monkeypatch, actual_key=True)
    before = store._policy_integrity_secret_material(create=False)
    calls = []
    original = store._policy_integrity_secret_material

    def material(*, create):
        calls.append(create)
        return original(create=create)

    monkeypatch.setattr(store, "_policy_integrity_secret_material", material)
    result = store.rotate_installation_id("test")
    assert result["installation_id"]
    assert observed["withdrawn"].is_set()
    assert calls == [False]
    assert original(create=False) == before


def test_late_implementation_import_cannot_begin_setup_or_sql(tmp_path, monkeypatch):
    import builtins

    store = GuardStore(tmp_path / "cold")
    before = store.get_device_metadata()
    release = threading.Event()
    finished = threading.Event()
    original = builtins.__import__

    def load(name, *args, **kwargs):
        if name == "native_policy_snapshot_rotation" and threading.current_thread().name == "hol-guard-native-control":
            try:
                assert release.wait(2)
                return original(name, *args, **kwargs)
            finally:
                finished.set()
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", load)
    try:
        with sqlite_connect_timeout_override(0.03), pytest.raises(NativePolicySnapshotError, match="deadline_exceeded"):
            store.rotate_installation_id("test")
    finally:
        release.set()
    assert finished.wait(1)
    assert store.get_device_metadata() == before
    assert not (store.guard_home / "native-policy-publication.lock").exists()


@pytest.mark.parametrize("stage", ["permission", "integrity-notification"])
def test_rotation_timeout_keeps_competing_writer_out_through_finalization(tmp_path, monkeypatch, stage):
    import multiprocessing

    from tests.test_native_policy_publication_maintenance import _lock_competitor

    store = GuardStore(tmp_path / "guard")
    old = store.get_device_metadata()
    context = multiprocessing.get_context("spawn")
    parent_channel, child_channel = context.Pipe()
    child = context.Process(target=_lock_competitor, args=(str(store.guard_home), child_channel))
    child.start()
    assert parent_channel.poll(5) and parent_channel.recv() == "ready"
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    original_repair = store._repair_store_permissions
    original_owner = rotation._rotate_owned

    def finalizer():
        entered.set()
        assert release.wait(2)
        original_repair()

    def owner(*args, **kwargs):
        try:
            return original_owner(*args, **kwargs)
        finally:
            finished.set()

    monkeypatch.setattr(rotation, "_rotate_owned", owner)
    if stage == "permission":
        monkeypatch.setattr(store, "_repair_store_permissions", finalizer)
    else:
        original_replace = store._replace_remote_policy_rows_locked

        def replace(connection, rows):
            original_replace(connection, rows)
            store._queue_policy_integrity_state_notification(connection, {"test": True})

        monkeypatch.setattr(store, "_replace_remote_policy_rows_locked", replace)
        store.set_policy_integrity_state_listener(lambda payload: finalizer())
    try:
        with sqlite_connect_timeout_override(0.1), pytest.raises(NativePolicySnapshotError, match="deadline_exceeded"):
            store.rotate_installation_id("test")
        assert entered.is_set()
        parent_channel.send("try")
        assert parent_channel.poll(1) and parent_channel.recv() is False
        release.set()
        assert finished.wait(1)
        parent_channel.send("try")
        assert parent_channel.poll(1) and parent_channel.recv() is True
        monkeypatch.setattr(store, "_repair_store_permissions", original_repair)
        assert store.get_device_metadata()["installation_id"] != old["installation_id"]
    finally:
        release.set()
        parent_channel.send("stop")
        child.join(2)
        if child.is_alive():
            child.terminate()
            child.join(2)
        parent_channel.close()
        child_channel.close()
