"""Precise database invalidation and bounded active workspace policy tracking."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from codex_plugin_scanner.guard.config import load_guard_config
from codex_plugin_scanner.guard.config_source_io import MAX_GUARD_CONFIG_BYTES, GuardConfigSourceError
from codex_plugin_scanner.guard.mdm import policy as managed_policy_module
from codex_plugin_scanner.guard.mdm.contracts import MachinePaths
from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_policy_snapshot_publisher_inputs import _captured_config_reader
from codex_plugin_scanner.guard.store import GuardStore

from .native_policy_snapshot_test_fixtures import _ack, _status
from .test_guard_mdm_policy import _policy
from .test_native_decision_receipt import _receipt


def test_receipt_wal_changes_do_not_recompile_workspace_policy(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    publisher = NativePolicySnapshotPublisher(store=store)
    # Keep WAL open across the receipt commit so this exercises WAL visibility,
    # rather than accidentally relying on the main database's mtime.
    connection = sqlite3.connect(store.path)
    try:
        connection.execute("pragma journal_mode=wal")
        connection.execute("pragma wal_autocheckpoint=0")
        publisher._policy_input_changed()
        with patch.object(
            publisher, "_compiled_effective_policy", side_effect=AssertionError("receipt triggered compile")
        ):
            store.record_native_decision_receipt(_receipt())
            assert not publisher._policy_input_changed({str(store.path) + "-wal"})
    finally:
        connection.close()
        publisher.close()


def test_policy_domain_mutation_revokes_ack_even_when_effective_config_is_equal(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    publisher = NativePolicySnapshotPublisher(store=store)
    try:
        publisher._policy_input_changed()
        policy = publisher._compiled_effective_policy()
        publisher._snapshot = {"generation": 1, "expires_at_ms": int(time.time() * 1000) + 60_000}
        publisher._acked = True
        with sqlite3.connect(store.path) as external:
            external.execute(
                "update sync_state set payload_json = ? where state_key = 'policy_integrity'",
                ('{"generation":27}',),
            )

        def compile_policy() -> dict[str, object]:
            assert not publisher.is_ready()
            return policy

        with patch.object(publisher, "_compiled_effective_policy", side_effect=compile_policy):
            assert publisher._policy_input_changed({str(store.path) + "-wal"})
    finally:
        publisher.close()


def test_periodic_reconciliation_detects_domain_change_without_watcher_hint(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    publisher = NativePolicySnapshotPublisher(store=store)
    try:
        publisher._policy_input_changed()
        with sqlite3.connect(store.path) as external:
            external.execute(
                "update sync_state set payload_json = ? where state_key = 'policy_integrity'",
                ('{"generation":28}',),
            )
        assert publisher._policy_input_changed()
        assert not publisher._policy_input_changed()
    finally:
        publisher.close()


def test_relative_guard_home_still_observes_integrity_domain_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    store = GuardStore(Path("relative-home"))
    publisher = NativePolicySnapshotPublisher(store=store)
    try:
        assert publisher._database_policy_marker() != "unavailable"
        publisher._policy_input_changed()
        with sqlite3.connect(store.path) as external:
            external.execute(
                "update sync_state set payload_json = ? where state_key = 'policy_integrity'",
                ('{"generation":29}',),
            )
        assert publisher._policy_input_changed({str(store.path)})
    finally:
        publisher.close()


def test_workspace_cache_reuses_unchanged_scopes_and_reloads_changed_overlay(tmp_path: Path) -> None:
    publisher = NativePolicySnapshotPublisher(store=GuardStore(tmp_path / "home"))
    workspaces = [tmp_path / "workspace-a", tmp_path / "workspace-b"]
    try:
        for workspace in workspaces:
            workspace.mkdir()
            publisher.register_workspace(workspace)
        with patch("codex_plugin_scanner.guard.config.load_guard_config", wraps=load_guard_config) as loader:
            first = publisher._compiled_effective_policy()
            assert loader.call_count == 3
            loader.reset_mock()
            assert publisher._compiled_effective_policy() == first
            assert loader.call_count == 0
            override = workspaces[0] / ".hol-guard.toml"
            override.write_text('sandbox_analysis = "strict"\n', encoding="utf-8")
            stricter = publisher._compiled_effective_policy()
            assert stricter["sandbox_analysis"] == "strict"
            assert loader.call_count == 1
            assert loader.call_args.kwargs["workspace"] == workspaces[0]
            override.unlink()
            assert publisher._compiled_effective_policy() == first
            assert loader.call_count == 2
    finally:
        publisher.close()


def test_workspace_limit_keeps_active_overlays_and_rejects_in_flight_ack(tmp_path: Path) -> None:
    entered, release = threading.Event(), threading.Event()

    def client(**kwargs: object) -> bytes:
        entered.set()
        assert release.wait(timeout=3)
        return _ack(kwargs["payload"])

    publisher = NativePolicySnapshotPublisher(
        store=GuardStore(tmp_path / "home"), status_provider=_status, client_request=client, max_workspaces=1
    )
    first_workspace, second_workspace = tmp_path / "first", tmp_path / "second"
    publisher.register_workspace(first_workspace)
    publisher._provision_verifier_key()
    pending = threading.Thread(target=publisher._publish_once)
    pending.start()
    try:
        assert entered.wait(timeout=3)
        assert not publisher.register_workspace(second_workspace)
        assert publisher._workspace_paths == {first_workspace}
        release.set()
        pending.join(timeout=3)
        assert not pending.is_alive()
        assert publisher.current_snapshot_binding() is None
        assert publisher.last_error == "native_policy_snapshot_workspace_capacity"
        publisher._publish_once()
        assert not publisher.is_ready()
    finally:
        release.set()
        pending.join(timeout=3)
        publisher.close()


def test_workspace_content_change_with_restored_timestamp_reloads_policy(tmp_path: Path) -> None:
    publisher = NativePolicySnapshotPublisher(store=GuardStore(tmp_path / "home"))
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    override = workspace / ".hol-guard.toml"
    override.write_text('sandbox_analysis = "off"   \n', encoding="utf-8")
    original = override.stat()
    publisher.register_workspace(workspace)
    try:
        assert publisher._compiled_effective_policy()["sandbox_analysis"] == "off"
        override.write_text('sandbox_analysis = "strict"\n', encoding="utf-8")
        assert override.stat().st_size == original.st_size
        os.utime(override, ns=(original.st_atime_ns, original.st_mtime_ns))
        assert publisher._compiled_effective_policy()["sandbox_analysis"] == "strict"
    finally:
        publisher.close()


def test_config_reader_parses_the_hashed_capture_after_path_replacement(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text('default_action = "block"\n', encoding="utf-8")
    captured = NativePolicySnapshotPublisher._capture_policy_input(path)
    path.write_text('default_action = "allow"\n', encoding="utf-8")
    assert _captured_config_reader(path, inputs={path: captured}) == {"default_action": "block"}
    replaced = NativePolicySnapshotPublisher._capture_policy_input(path)
    assert replaced.identity != captured.identity
    assert _captured_config_reader(path, inputs={path: replaced}) == {"default_action": "allow"}


@pytest.mark.parametrize("location", ["home", "workspace", "legacy-workspace"])
@pytest.mark.parametrize("damage", ["symlink", "oversized", "unreadable"])
def test_config_capture_rejection_immediately_revokes_an_ack_during_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, location: str, damage: str
) -> None:
    from codex_plugin_scanner.guard import config_source_io

    home, workspace = tmp_path / "home", tmp_path / "workspace"
    workspace.mkdir()
    home.mkdir()
    (home / "config.toml").write_text('default_action = "block"\n', encoding="utf-8")
    (workspace / ".hol-guard.toml").write_text('sandbox_analysis = "strict"\n', encoding="utf-8")
    pushes: list[object] = []

    def client(**kwargs: object) -> bytes:
        pushes.append(kwargs["payload"])
        return _ack(kwargs["payload"])

    publisher = NativePolicySnapshotPublisher(store=GuardStore(home), status_provider=_status, client_request=client)
    try:
        publisher.register_workspace(workspace)
        publisher._provision_verifier_key()
        publisher._publish_once()
        assert publisher.is_ready()
        assert publisher.current_snapshot_binding() is not None
        assert len(pushes) == 1
        if location == "home":
            path = home / "config.toml"
        else:
            name = ".hol-guard.toml" if location == "workspace" else ".ai-plugin-scanner-guard.toml"
            path = workspace / name
        if damage == "symlink":
            outside = tmp_path / "outside.toml"
            outside.write_text('default_action = "allow"\n', encoding="utf-8")
            path.unlink(missing_ok=True)
            try:
                path.symlink_to(outside)
            except OSError:
                pytest.skip("symlink creation requires runner support")
        elif damage == "oversized":
            path.write_bytes(b"#" + b"x" * MAX_GUARD_CONFIG_BYTES)
        else:
            path.touch(exist_ok=True)
            original_capture = config_source_io._capture_in_parent

            def unreadable(candidate: Path, directory: int | None):
                if candidate == path:
                    raise PermissionError("fixture config read denied")
                return original_capture(candidate, directory)

            monkeypatch.setattr(config_source_io, "_capture_in_parent", unreadable)
        # Do not run the observer first: rejection itself must withdraw the old
        # ACK, even while a previously valid snapshot is still unexpired.
        publisher._publish_once()
        assert publisher.last_error == "guardconfigsourceerror"
        assert not publisher._acked
        assert not publisher.is_ready()
        assert publisher.current_snapshot_binding() is None
        assert len(pushes) == 1
        with pytest.raises(GuardConfigSourceError):
            publisher._compiled_effective_policy()
    finally:
        publisher.close()


def test_config_capture_uses_the_same_size_limit_as_ordinary_loading(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    prefix = b'default_action = "block"\n#'
    path.write_bytes(prefix + b"x" * (MAX_GUARD_CONFIG_BYTES - len(prefix)))
    captured = NativePolicySnapshotPublisher._capture_policy_input(path)
    assert _captured_config_reader(path, inputs={path: captured}) == {"default_action": "block"}
    assert load_guard_config(tmp_path).default_action == "block"
    with path.open("ab") as handle:
        handle.write(b"x")
    with pytest.raises(GuardConfigSourceError, match="guard_config_too_large"):
        NativePolicySnapshotPublisher._capture_policy_input(path)


@pytest.mark.parametrize("damage", ["deleted", "tampered"])
def test_managed_cache_is_repaired_before_machine_source_disappears(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, damage: str
) -> None:
    store = GuardStore(tmp_path / "home")
    source = tmp_path / "managed-policy.json"
    paths = MachinePaths(tmp_path / "runtime", tmp_path / "state", source, tmp_path / "logs", tmp_path / "manifest")
    cache = paths.state_root / "managed-policy-cache.json"
    load_managed = managed_policy_module.load_managed_policy
    monkeypatch.setattr(managed_policy_module, "default_machine_paths", lambda **_kwargs: paths)
    monkeypatch.setattr(managed_policy_module, "_administrator_context", lambda _system: True)
    monkeypatch.setattr(managed_policy_module, "_cache_owner_is_trusted", lambda _path, _system: True)
    monkeypatch.setattr(managed_policy_module, "_machine_policy_source_is_trusted", lambda _path, _system: True)
    monkeypatch.setattr(
        managed_policy_module, "load_managed_policy", lambda **kwargs: load_managed(system_name="Linux", **kwargs)
    )
    source.write_text(
        json.dumps(_policy(settings={"default_action": "block"}, lockedSettings=["default_action"])),
        encoding="utf-8",
    )
    publisher = NativePolicySnapshotPublisher(store=store)
    try:
        with patch.object(
            managed_policy_module, "_write_policy_cache", wraps=managed_policy_module._write_policy_cache
        ) as writes:
            assert publisher._compiled_effective_policy()["default_action"] == "block"
            assert writes.call_count == 1
            assert publisher._compiled_effective_policy()["default_action"] == "block"
            assert writes.call_count == 1
            if damage == "deleted":
                cache.unlink()
            else:
                cache.write_text('{"tampered":true}', encoding="utf-8")
            assert publisher._compiled_effective_policy()["default_action"] == "block"
            assert writes.call_count == 2
        source.unlink()
        assert publisher._compiled_effective_policy()["default_action"] == "block"
    finally:
        publisher.close()


def test_background_config_change_publishes_updated_snapshot_without_db_write(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    pushes: list[float] = []

    def client(**kwargs: object) -> bytes:
        pushes.append(time.monotonic())
        return _ack(kwargs["payload"])

    publisher = NativePolicySnapshotPublisher(
        store=store, status_provider=_status, client_request=client, poll_interval_seconds=0.05
    )
    try:
        publisher.start()
        assert publisher.wait_until_ready(time.monotonic() + 3)
        old_generation = publisher.current_snapshot_binding()["generation"]
        changed_at = time.monotonic()
        (tmp_path / "config.toml").write_text('default_action = "block"\n', encoding="utf-8")
        deadline = changed_at + 3
        current = publisher.current_snapshot_binding()
        while (current is None or current["generation"] == old_generation) and time.monotonic() < deadline:
            time.sleep(0.01)
            current = publisher.current_snapshot_binding()
        assert current is not None and current["generation"] > old_generation
        assert any(pushed >= changed_at for pushed in pushes)
    finally:
        publisher.close()
