"""Mutation, crash, cross-process, and authenticated recovery publication tests."""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_command_control_authority import (
    AUTHORITY_FILE_NAME,
    AUTHORITY_MAX_BYTES,
    decode_authority,
    floor_link_digest,
)
from codex_plugin_scanner.guard.native_command_control_authority_io import read_private_state, write_private_state
from codex_plugin_scanner.guard.native_command_control_authority_store import (
    begin_native_command_control_mutation,
    commit_native_command_control_projection,
    read_native_control_floor,
)
from codex_plugin_scanner.guard.native_command_control_binding import (
    native_command_control_floor_mac,
    read_native_command_control_binding,
)
from codex_plugin_scanner.guard.native_policy_snapshot_codec import (
    _canonical_json_bytes_v3,
    derive_native_policy_verifier_key,
)
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth

from .test_guard_extension_control_authority import MemorySecretStore, _commit, _store
from .test_native_command_control_binding import _snapshot
from .test_native_command_control_binding_publisher import _publish_ready, _publisher

KEY = derive_native_policy_verifier_key(b"k" * 32)
CATALOG = BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest


def test_unbound_policy_snapshot_cannot_supply_command_control_floor(tmp_path: Path) -> None:
    store = _store(tmp_path, MemorySecretStore())
    unbound = _snapshot(tmp_path)
    write_private_state(tmp_path, "policy-snapshot-v3.json", _canonical_json_bytes_v3(unbound), 280 * 1024)
    with pytest.raises(NativePolicySnapshotError, match="recovery_floor_invalid"):
        read_native_control_floor(store, b"v" * 32)


@pytest.mark.parametrize("with_database_hint", [False, True])
def test_marker_hint_verifies_content_without_republishing_own_ack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, with_database_hint: bool
) -> None:
    store = _store(tmp_path, MemorySecretStore())
    publisher = _publisher(store, monkeypatch)
    try:
        _publish_ready(publisher)
        changed_paths = {str(tmp_path / "native-runtime" / AUTHORITY_FILE_NAME)}
        if with_database_hint:
            changed_paths.add(str(tmp_path / "guard.db-wal"))
        assert not publisher._policy_input_changed(changed_paths)
        assert publisher.is_ready()
        # A receipt write may accompany a marker fault. An unchanged SQL
        # domain hint must not skip verification of that marker's contents.
        write_private_state(tmp_path, AUTHORITY_FILE_NAME, b"{}", AUTHORITY_MAX_BYTES)
        assert publisher._policy_input_changed(changed_paths)
        assert not publisher.is_ready()
    finally:
        publisher.close()


@pytest.fixture(autouse=True)
def _allow_terminal_proof(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof._require_local_terminal_confirmation",
        lambda _enrollment: None,
    )


def _marker(home: Path) -> dict:
    encoded = read_private_state(home, AUTHORITY_FILE_NAME, AUTHORITY_MAX_BYTES)
    assert encoded is not None
    return decode_authority(encoded, KEY)


def _persist_native_floor(home: Path, snapshot: dict) -> dict:
    binding = snapshot["command_extensions"]
    floor = {
        "revision": binding["revision"],
        "managed_revision": binding["managed_revision"],
        "effective_digest": binding["effective_digest"],
        "authority": binding["authority"],
    }
    if binding["authority"]["recovery"] is not None:
        floor["previous_floor_digest"] = binding["authority"]["recovery"]["previous_floor_digest"]
    authority = {
        "schema": "guard-policy-snapshot-authority.v3",
        "generation_floor": snapshot["generation"],
        "policy_digest": snapshot["policy_digest"],
        # Recovery must work even when an expired/quarantined snapshot is absent.
        "snapshot": None,
        "command_control_floor": floor,
        "floor_mac": native_command_control_floor_mac(snapshot["generation"], snapshot["policy_digest"], floor, KEY),
    }
    write_private_state(home, "policy-snapshot-v3.json", _canonical_json_bytes_v3(authority), 280 * 1024)
    return floor


def test_marker_sync_failure_prevents_control_mutation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _store(tmp_path, MemorySecretStore())
    publisher = _publisher(store, monkeypatch)
    try:
        first = _publish_ready(publisher)
        before = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)

        def fail_write(*args, **kwargs):
            raise NativePolicySnapshotError("injected_fence_sync_failure")

        monkeypatch.setattr(
            "codex_plugin_scanner.guard.native_command_control_authority_store.write_private_state", fail_write
        )
        with pytest.raises(NativePolicySnapshotError, match="injected_fence_sync_failure"):
            _commit(store)
        after = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
        assert after == before
        assert not publisher.is_ready()
        assert _marker(tmp_path)["effective_digest"] == first["command_extensions"]["effective_digest"]
    finally:
        publisher.close()


def test_foreign_process_crash_retains_closed_marker_until_new_ack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path, MemorySecretStore())
    publisher = _publisher(store, monkeypatch)
    try:
        first = _publish_ready(publisher)
        first_authority = first["command_extensions"]["authority"]
        script = """
import os, pathlib, sys
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.native_command_control_authority_store import begin_native_command_control_mutation
store = GuardStore(pathlib.Path(sys.argv[1]))
store._policy_integrity_secret_material = lambda *, create: (b'k' * 32, 'test')
with store._extension_control_authority_lock():
    begin_native_command_control_mutation(store)
    with store._connect() as connection:
        connection.execute("update extension_control_authority_snapshot set layers_json = 'pending'")
        os._exit(17)
"""
        completed = subprocess.run([sys.executable, "-c", script, str(tmp_path)], capture_output=True, timeout=20)
        assert completed.returncode == 17, completed.stderr.decode()
        marker = _marker(tmp_path)
        assert marker["phase"] == "closed"
        assert marker["effective_digest"] is None
        assert marker["mutation_revision"] > first_authority["mutation_revision"]
        # Foreign processes do not share the in-memory publisher callback.
        # The resident lease/marker protocol must reject this still-old binding.
        assert publisher.current_snapshot_binding()["generation"] == first["generation"]
        assert store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY).revision == 0
        publisher.request_publish()
        second = _publish_ready(publisher)
        assert second["generation"] > first["generation"]
        assert second["command_extensions"]["effective_digest"] == first["command_extensions"]["effective_digest"]
        assert second["command_extensions"]["authority"]["mutation_revision"] == marker["mutation_revision"]
        assert _marker(tmp_path)["phase"] == "committed"
    finally:
        publisher.close()


def test_explicit_recovery_links_exact_retained_floor_and_preserves_link_on_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path, MemorySecretStore())
    _commit(store)
    publisher = _publisher(store, monkeypatch)
    try:
        first = _publish_ready(publisher)
        prior_floor = _persist_native_floor(tmp_path, first)
        with store._connect() as connection:
            connection.execute("update extension_control_authority_snapshot set snapshot_mac = ?", ("0" * 64,))
        publisher.request_publish()
        unhealthy = _publish_ready(publisher)
        assert unhealthy["command_extensions"]["health"] == "tampered"
        recovered = store.recover_extension_control_authority(catalog_digest=CATALOG)
        assert recovered.health is AuthorityHealth.PROTECTED and recovered.revision == 0
        closed = _marker(tmp_path)
        assert closed["phase"] == "closed"
        assert closed["epoch"] > first["command_extensions"]["authority"]["epoch"]
        recovery = closed["recovery"]
        assert recovery["previous_floor_digest"] == floor_link_digest(prior_floor)
        assert recovery["previous_epoch"] == prior_floor["authority"]["epoch"]
        assert recovery["previous_mutation_revision"] == prior_floor["authority"]["mutation_revision"]
        assert recovery["previous_authority_key_id"] == prior_floor["authority"]["authority_key_id"]
        published = _publish_ready(publisher)
        assert published["command_extensions"]["revision"] == 0
        assert published["command_extensions"]["authority"]["recovery"] == recovery
        new_floor = _persist_native_floor(tmp_path, published)
        assert new_floor["previous_floor_digest"] == floor_link_digest(prior_floor)
        _commit(store, key="after-recovery")
        mutated = _publish_ready(publisher)
        assert mutated["command_extensions"]["authority"]["recovery"] == recovery
        assert (
            mutated["command_extensions"]["authority"]["epoch"] == published["command_extensions"]["authority"]["epoch"]
        )
        assert mutated["command_extensions"]["revision"] == 1
    finally:
        publisher.close()


def test_forged_retained_floor_cannot_authorize_recovery(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _store(tmp_path, MemorySecretStore())
    _commit(store)
    publisher = _publisher(store, monkeypatch)
    try:
        first = _publish_ready(publisher)
        _persist_native_floor(tmp_path, first)
        path = tmp_path / "native-runtime" / "policy-snapshot-v3.json"
        raw = json.loads(path.read_bytes())
        raw["command_control_floor"]["revision"] += 1
        path.write_bytes(_canonical_json_bytes_v3(raw))
        with pytest.raises(NativePolicySnapshotError, match="recovery_floor_invalid"):
            store._reset_extension_control_authority(CATALOG, key=store._authority_key(required=True), reason="test")
        assert store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY).revision == 1
    finally:
        publisher.close()


def test_older_publisher_accepts_already_acknowledged_authenticated_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path, MemorySecretStore())
    _commit(store)
    publisher = _publisher(store, monkeypatch)
    try:
        first = _publish_ready(publisher)
        old_runtime = publisher._command_control_runtime
        _persist_native_floor(tmp_path, first)
        with store._connect() as connection:
            connection.execute("update extension_control_authority_snapshot set snapshot_mac = ?", ("0" * 64,))
        store.recover_extension_control_authority(catalog_digest=CATALOG)
        # A different publisher starts after recovery and installs epoch2.
        publisher._command_control_runtime = None
        recovered = _publish_ready(publisher)
        _persist_native_floor(tmp_path, recovered)
        observed, runtime = read_native_command_control_binding(store, old_runtime)
        assert observed == recovered["command_extensions"]
        assert runtime.current().revision == 0
    finally:
        publisher.close()


def test_historical_recovery_proof_cannot_change_authority_key_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    _commit(store)
    publisher = _publisher(store, monkeypatch)
    try:
        first = _publish_ready(publisher)
        _persist_native_floor(tmp_path, first)
        with store._connect() as connection:
            connection.execute("update extension_control_authority_snapshot set snapshot_mac = ?", ("0" * 64,))
        store.recover_extension_control_authority(catalog_digest=CATALOG)
        recovered = _publish_ready(publisher)
        assert recovered["command_extensions"]["authority"]["recovery"] is not None
        with store._extension_control_authority_lock():
            begin_native_command_control_mutation(store)
            monkeypatch.setattr(store, "_authority_key", lambda *, required: b"x" * 32)
            with pytest.raises(NativePolicySnapshotError, match="authority_key_changed"):
                commit_native_command_control_projection(store, recovered["command_extensions"])
        assert _marker(tmp_path)["phase"] == "closed"
    finally:
        publisher.close()


def test_missing_key_recovery_rebuilds_manifest_and_publishes_new_key_epoch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    _commit(store)
    publisher = _publisher(store, monkeypatch)
    try:
        first = _publish_ready(publisher)
        _persist_native_floor(tmp_path, first)
        old_key_id = first["command_extensions"]["authority"]["authority_key_id"]
        secrets.delete_secret(store._key_ref())
        store.recover_extension_control_authority(catalog_digest=CATALOG)
        assert (
            store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY).health
            is AuthorityHealth.PROTECTED
        )
        published = _publish_ready(publisher)
        assert published["command_extensions"]["health"] == "protected"
        assert published["command_extensions"]["authority"]["authority_key_id"] != old_key_id
        assert published["command_extensions"]["authority"]["recovery"]["previous_authority_key_id"] == old_key_id
    finally:
        publisher.close()


def test_unchanged_projection_shares_lease_with_native_readers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _store(tmp_path, MemorySecretStore())
    publisher = _publisher(store, monkeypatch)
    process = None
    try:
        first = _publish_ready(publisher)
        script = """
import pathlib, sys
from codex_plugin_scanner.guard.native_command_control_authority_io import hold_command_control_authority_lock
with hold_command_control_authority_lock(pathlib.Path(sys.argv[1]), shared=True):
    print('leased', flush=True)
    sys.stdin.readline()
"""
        process = subprocess.Popen(
            [sys.executable, "-c", script, str(tmp_path)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True
        )
        assert process.stdout is not None
        ready: list[str] = []
        reader = threading.Thread(target=lambda: ready.append(process.stdout.readline()), daemon=True)
        reader.start()
        reader.join(10.0)
        assert ready == ["leased\n"], "child never acquired the shared authority lease"

        def forbid_write(*args, **kwargs):
            pytest.fail("unchanged verified controls attempted an authority write")

        monkeypatch.setattr(
            "codex_plugin_scanner.guard.native_command_control_authority_store.write_private_state", forbid_write
        )
        assert publisher._compiled_command_extensions() == first["command_extensions"]
        process.communicate("release\n", timeout=5)
        assert process.returncode == 0
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        publisher.close()
