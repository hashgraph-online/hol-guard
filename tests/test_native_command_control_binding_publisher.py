"""Verified control projection and commit-before-readiness integration tests."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

import pytest

import codex_plugin_scanner.guard.native_command_control_binding as binding_module
from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    ControlLayerKind,
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)
from codex_plugin_scanner.guard.store import GuardStore

from .managed_controls_activation_support import activate_managed_bundle, managed_bundle
from .native_policy_snapshot_test_fixtures import _ack, _status
from .test_guard_extension_control_authority import MemorySecretStore, _commit, _proof, _store


@pytest.fixture(autouse=True)
def _allow_terminal_proof(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof._require_local_terminal_confirmation",
        lambda _enrollment: None,
    )


def _publisher(store: GuardStore, monkeypatch: pytest.MonkeyPatch, client=None) -> NativePolicySnapshotPublisher:
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda *, create: (b"k" * 32, "test"))
    return NativePolicySnapshotPublisher(
        store=store,
        status_provider=_status,
        client_request=client or (lambda **kwargs: _ack(kwargs["payload"])),
        poll_interval_seconds=0.05,
    )


def _publish_ready(publisher: NativePolicySnapshotPublisher) -> dict:
    publisher._publish_once()
    assert publisher.is_ready(), publisher.last_error
    snapshot = publisher.current_snapshot()
    assert snapshot is not None
    return snapshot


@pytest.mark.parametrize("feature", ["native-command-program-v1", "native-command-control-fence-v1"])
def test_new_capability_is_required_even_with_unrelated_features(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    feature: str,
) -> None:
    calls: list[object] = []
    publisher = _publisher(GuardStore(tmp_path), monkeypatch, lambda **kwargs: calls.append(kwargs))
    status = _status()
    status.capabilities.features = (
        *(item for item in status.capabilities.features if item != feature),
        "unrelated-new-feature",
    )
    publisher._status_provider = lambda: status
    publisher._snapshot = {"expires_at_ms": int((time.time() + 60) * 1000)}
    publisher._acked = True
    try:
        publisher._publish_once()
        assert not publisher.is_ready()
        assert publisher.last_error == "native_policy_snapshot_protocol_unsupported"
        assert calls == []
    finally:
        publisher.close()


def test_missing_program_closes_old_readiness_and_never_pushes_legacy_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[object] = []
    publisher = _publisher(GuardStore(tmp_path), monkeypatch, lambda **kwargs: calls.append(kwargs))
    publisher._snapshot = {"expires_at_ms": int((time.time() + 60) * 1000)}
    publisher._acked = True
    monkeypatch.setattr(binding_module, "_program_path", lambda: tmp_path / "missing-program.json")
    try:
        publisher._publish_once()
        assert not publisher.is_ready()
        assert publisher.last_error == "native_command_program_artifact_unavailable"
        assert calls == []
    finally:
        publisher.close()


def test_local_control_commit_invalidates_before_anchor_and_reopens_only_after_commit_ack(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path, MemorySecretStore())
    entered = threading.Event()
    release = threading.Event()
    errors: list[BaseException] = []
    pushed_revisions: list[int] = []

    def client(**kwargs):
        snapshot = json.loads(kwargs["payload"])["request"]["snapshot"]
        authority = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
        assert authority.health is AuthorityHealth.PROTECTED
        assert snapshot["command_extensions"]["revision"] == authority.revision
        pushed_revisions.append(authority.revision)
        return _ack(kwargs["payload"])

    publisher = _publisher(store, monkeypatch, client)
    first = _publish_ready(publisher)
    original_anchor = store._write_and_verify_anchor

    def stop_after_anchor(anchor, *, key):
        original_anchor(anchor, key=key)
        if anchor.phase.value == "anchored":
            entered.set()
            assert release.wait(5.0)

    monkeypatch.setattr(store, "_write_and_verify_anchor", stop_after_anchor)

    def commit():
        try:
            _commit(store)
        except BaseException as error:
            errors.append(error)

    mutation = threading.Thread(target=commit)
    publication = threading.Thread(target=publisher._publish_once)
    try:
        mutation.start()
        assert entered.wait(5.0)
        assert not publisher.is_ready()
        assert publisher.current_snapshot_binding() is None
        publication.start()
        # The publisher cannot read prepared/anchored state through the held
        # authority lock, and no new payload was sent while commit is paused.
        assert pushed_revisions == [0]
        release.set()
        mutation.join(5.0)
        publication.join(5.0)
        assert not mutation.is_alive() and not publication.is_alive()
        assert errors == []
        second = publisher.current_snapshot()
        assert second is not None
        assert second["command_extensions"]["revision"] == 1
        assert second["generation"] > first["generation"]
        assert pushed_revisions == [0, 1]
    finally:
        release.set()
        mutation.join(5.0)
        if publication.ident is not None:
            publication.join(5.0)
        publisher.close()


def test_verified_post_ack_read_rejects_cross_process_control_change_without_callback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    entered = threading.Event()
    release = threading.Event()
    calls = 0

    def client(**kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            entered.set()
            assert release.wait(5.0)
        return _ack(kwargs["payload"])

    publisher = _publisher(store, monkeypatch, client)
    first = _publish_ready(publisher)
    foreign = GuardStore(tmp_path, prime_policy_integrity=False)
    foreign._extension_control_authority_secret_store = secrets
    # A different process cannot invoke this process's in-memory callbacks.
    monkeypatch.setattr(foreign, "_invalidate_native_extension_control_policy", lambda: None)
    publisher.request_publish()
    worker = threading.Thread(target=publisher._publish_once)
    try:
        worker.start()
        assert entered.wait(5.0)
        _commit(foreign)
        release.set()
        worker.join(5.0)
        assert not worker.is_alive()
        assert not publisher.is_ready()
        assert publisher.last_error == "native_command_control_binding_changed"
        second = _publish_ready(publisher)
        assert second["command_extensions"]["revision"] == 1
        assert second["generation"] > first["generation"]
    finally:
        release.set()
        worker.join(5.0)
        publisher.close()


def test_managed_activation_and_clear_preserve_local_opt_in_and_independent_revisions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path, MemorySecretStore())
    layer = ExtensionControlLayer(
        schema_version="1.0.0",
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=False,
        controls=(
            ExtensionControl(ControlTarget(ControlTargetKind.EXTENSION, "command.ollama"), ControlState.ENABLED),
        ),
    )
    store.commit_extension_control_layers(
        (layer,),
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        actor_id="local-admin",
        expected_revision=0,
        idempotency_key="enable-ollama",
        nonce="enable-ollama",
        proof=_proof(store, (layer,), revision=0, key="enable-ollama", actor_id="local-admin", nonce="enable-ollama"),
    )
    publisher = _publisher(store, monkeypatch)
    first = _publish_ready(publisher)
    marker = publisher._compiled_command_extensions()
    try:
        with store._connect() as connection:
            connection.execute(
                "insert into sync_state (state_key, payload_json, updated_at) values ('heartbeat', '{}', 'now')"
            )
        assert publisher._compiled_command_extensions() == marker

        def publish_after_commit(authority, commit):
            assert not publisher.is_ready()
            commit()
            assert authority.managed_revision == 1

        assert activate_managed_bundle(store, managed_bundle(), managed_controls_publish=publish_after_commit)
        assert not publisher.is_ready()
        assert publisher._compiled_command_extensions() != marker
        second = _publish_ready(publisher)
        binding = second["command_extensions"]
        assert binding["revision"] == first["command_extensions"]["revision"] == 1
        assert binding["managed_revision"] == 1
        assert [item["kind"] for item in binding["layers"]] == ["local-admin", "signed-cloud"]
        assert binding["layers"][0]["controls"] == [
            {"target_kind": "extension", "target_id": "command.ollama", "state": "enabled"}
        ]
        assert any(control["state"] == "disabled" for control in binding["layers"][1]["controls"])
        store.clear_policy_bundle_authority("2026-08-24T12:00:00Z", policy_bundle_last_error={})
        assert not publisher.is_ready()
        third = _publish_ready(publisher)["command_extensions"]
        assert third["revision"] == 1
        assert third["managed_revision"] == 2
        assert third["layers"] == [binding["layers"][0]]
    finally:
        publisher.close()


def test_wal_control_tamper_is_marker_trigger_and_verified_health_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path, MemorySecretStore())
    publisher = _publisher(store, monkeypatch)
    _publish_ready(publisher)
    try:
        with store._connect() as connection:
            connection.execute("pragma journal_mode=WAL")
            connection.execute(
                "update extension_control_authority_snapshot set layers_json = '[] ' where singleton = 1"
            )
        assert publisher._policy_input_changed({str(tmp_path / "guard.db-wal")})
        assert not publisher.is_ready()
        binding = publisher._compiled_command_extensions()
        assert binding["health"] == "tampered"
        assert binding["layers"] == []
    finally:
        publisher.close()


def test_rolled_back_managed_activation_can_only_republish_the_previous_committed_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path, MemorySecretStore())
    assert activate_managed_bundle(store, managed_bundle())
    publisher = _publisher(store, monkeypatch)
    first = _publish_ready(publisher)
    second_bundle = managed_bundle()
    second_bundle["bundleVersion"] = 8
    second_bundle["bundleHash"] = "sha256:" + "e" * 64

    def fail_before_commit(_connection, _rows):
        assert not publisher.is_ready()
        raise sqlite3.OperationalError("injected activation rollback")

    monkeypatch.setattr(store, "_replace_remote_policy_rows_locked", fail_before_commit)
    try:
        with pytest.raises(sqlite3.OperationalError, match="injected activation rollback"):
            activate_managed_bundle(store, second_bundle)
        assert not publisher.is_ready()
        republished = _publish_ready(publisher)
        assert republished["generation"] > first["generation"]
        before, after = first["command_extensions"], republished["command_extensions"]
        assert {key: value for key, value in before.items() if key != "authority"} == {
            key: value for key, value in after.items() if key != "authority"
        }
        assert after["authority"]["mutation_revision"] > before["authority"]["mutation_revision"]
    finally:
        publisher.close()


def test_hook_binding_read_never_reads_program_or_control_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    publisher = _publisher(_store(tmp_path, MemorySecretStore()), monkeypatch)
    first = _publish_ready(publisher)

    def unexpected_read(*_args, **_kwargs):
        raise AssertionError("synchronous hook performed background authority work")

    monkeypatch.setattr(publisher, "_compiled_command_extensions", unexpected_read)
    monkeypatch.setattr(binding_module, "load_native_command_program_metadata", unexpected_read)
    try:
        assert publisher.current_snapshot_binding() == {
            **{key: first[key] for key in ("generation", "policy_digest", "runtime_identity", "mode")},
            "command_extensions_bound": True,
        }
    finally:
        publisher.close()


def test_marker_handles_blob_tamper_without_terminating_reconciliation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path, MemorySecretStore())
    _commit(store)
    publisher = _publisher(store, monkeypatch)
    _publish_ready(publisher)
    try:
        with store._connect() as connection:
            connection.execute(
                "update extension_control_authority_transition set snapshot_digest = ? where revision = 1",
                (b"opaque-invalid-digest",),
            )
        assert publisher._policy_input_changed({str(tmp_path / "guard.db")})
        assert not publisher.is_ready()
        assert publisher._compiled_command_extensions()["health"] == "tampered"
    finally:
        publisher.close()
