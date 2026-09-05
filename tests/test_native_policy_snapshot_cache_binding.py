"""CLI hook workers reuse a durable ACKed snapshot when publication times out."""

from __future__ import annotations

import time
from collections.abc import Mapping
from pathlib import Path

import pytest

import codex_plugin_scanner.guard.daemon.hook_worker as hook_worker_module
from codex_plugin_scanner.guard.native_policy_snapshot import native_policy_snapshot_v3
from codex_plugin_scanner.guard.native_policy_snapshot_codec import (
    _canonical_json_bytes_v3,
    _generation_floor_mac_v3,
    derive_native_policy_verifier_key,
)
from codex_plugin_scanner.guard.native_policy_snapshot_constants import (
    POLICY_SNAPSHOT_AUTHORITY_SCHEMA,
)
from codex_plugin_scanner.guard.store import GuardStore

from .native_policy_snapshot_test_fixtures import _config


class _TimeoutPublisher:
    def start(self) -> None:
        return

    def register_workspace(self, workspace: Path | None) -> bool:
        del workspace
        return True

    def wait_until_ready(self, deadline_monotonic: float) -> bool:
        del deadline_monotonic
        return False

    def current_snapshot_binding(self) -> dict[str, object] | None:
        return None

    def current_snapshot(self) -> dict[str, object] | None:
        return None

    def close(self) -> None:
        return


class _PoisonPublisher(_TimeoutPublisher):
    def start(self) -> None:
        raise AssertionError("CLI hook workers must not start a competing publisher")

    def register_workspace(self, workspace: Path | None) -> bool:
        del workspace
        raise AssertionError("CLI hook workers must not request a competing publish")


def _write_resident_authority(guard_home: Path, snapshot: Mapping[str, object], master: bytes) -> None:
    generation = snapshot["generation"]
    digest = snapshot["policy_digest"]
    assert isinstance(generation, int)
    assert isinstance(digest, str)
    verifier = derive_native_policy_verifier_key(master)
    record = {
        "floor_mac": _generation_floor_mac_v3(generation, digest, verifier),
        "generation_floor": generation,
        "policy_digest": digest,
        "schema": POLICY_SNAPSHOT_AUTHORITY_SCHEMA,
        "snapshot": snapshot,
    }
    path = guard_home / "native-runtime" / "policy-snapshot-v3.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_canonical_json_bytes_v3(record))
    path.chmod(0o600)


def _write_lifecycle_generation(guard_home: Path, generation: object) -> None:
    assert isinstance(generation, int)
    resident = guard_home / "native-runtime" / "resident-v3-test"
    resident.mkdir(parents=True, exist_ok=True)
    (resident / f"generation-{generation:020d}.json").write_text("{}", encoding="utf-8")


def _ready_worker(
    guard_home: Path,
    master: bytes,
    monkeypatch: pytest.MonkeyPatch,
    *,
    publisher: object | None = None,
    publish_native_policy: bool = True,
) -> hook_worker_module.HookWorker:
    store = GuardStore(guard_home)
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda *, create: (master, "master-id"))
    monkeypatch.setattr(hook_worker_module, "native_mode", lambda: "auto")
    monkeypatch.setattr(
        hook_worker_module,
        "get_native_policy_snapshot_publisher",
        lambda _store: publisher if publisher is not None else _TimeoutPublisher(),
    )
    return hook_worker_module.HookWorker(store=store, publish_native_policy=publish_native_policy)


def test_prepare_workspace_policy_reuses_resident_authority_when_wait_times_out(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    master = b"k" * 32
    future_ms = int(time.time() * 1_000) + 60_000
    snapshot = native_policy_snapshot_v3(
        config=_config(),
        guard_home=guard_home,
        runtime_identity="a" * 64,
        rule_digest="b" * 64,
        policy_integrity_key=master,
        issued_at_ms=future_ms,
        expires_at_ms=future_ms + 60_000,
    )
    _write_resident_authority(guard_home, snapshot, master)
    worker = _ready_worker(guard_home, master, monkeypatch)
    binding = worker.prepare_workspace_policy(tmp_path / "workspace")

    assert binding is not None
    assert binding["generation"] == snapshot["generation"]
    assert binding["policy_digest"] == snapshot["policy_digest"]
    assert binding["runtime_identity"] == snapshot["runtime_identity"]
    assert binding["mode"] == snapshot["mode"]


def test_prepare_workspace_policy_ignores_publisher_cache_and_lifecycle_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    master = b"u" * 32
    future_ms = int(time.time() * 1_000) + 60_000
    snapshot = native_policy_snapshot_v3(
        config=_config(),
        guard_home=guard_home,
        runtime_identity="a" * 64,
        rule_digest="b" * 64,
        policy_integrity_key=master,
        issued_at_ms=future_ms,
        expires_at_ms=future_ms + 60_000,
    )
    _write_lifecycle_generation(guard_home, snapshot["generation"])
    worker = _ready_worker(guard_home, master, monkeypatch)
    assert worker.prepare_workspace_policy(tmp_path / "workspace") is None


def test_prepare_workspace_policy_rejects_expired_resident_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    master = b"e" * 32
    future_ms = int(time.time() * 1_000) + 60_000
    snapshot = native_policy_snapshot_v3(
        config=_config(),
        guard_home=guard_home,
        runtime_identity="a" * 64,
        rule_digest="b" * 64,
        policy_integrity_key=master,
        issued_at_ms=future_ms,
        expires_at_ms=future_ms + 60_000,
    )
    _write_resident_authority(guard_home, snapshot, master)
    expires_at_ms = snapshot["expires_at_ms"]
    assert isinstance(expires_at_ms, int)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_policy_snapshot_acked.time.time",
        lambda: (expires_at_ms / 1_000) + 1,
    )
    worker = _ready_worker(guard_home, master, monkeypatch)
    assert worker.prepare_workspace_policy(tmp_path / "workspace") is None


def test_prepare_workspace_policy_rejects_forged_floor_mac(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    master = b"f" * 32
    future_ms = int(time.time() * 1_000) + 60_000
    snapshot = native_policy_snapshot_v3(
        config=_config(),
        guard_home=guard_home,
        runtime_identity="a" * 64,
        rule_digest="b" * 64,
        policy_integrity_key=master,
        issued_at_ms=future_ms,
        expires_at_ms=future_ms + 60_000,
    )
    _write_resident_authority(guard_home, snapshot, master)
    path = guard_home / "native-runtime" / "policy-snapshot-v3.json"
    record = {
        "floor_mac": "0" * 64,
        "generation_floor": snapshot["generation"],
        "policy_digest": snapshot["policy_digest"],
        "schema": POLICY_SNAPSHOT_AUTHORITY_SCHEMA,
        "snapshot": snapshot,
    }
    path.write_bytes(_canonical_json_bytes_v3(record))
    path.chmod(0o600)
    worker = _ready_worker(guard_home, master, monkeypatch)
    assert worker.prepare_workspace_policy(tmp_path / "workspace") is None


def test_prepare_workspace_policy_binds_resident_authority_without_publishing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    master = b"c" * 32
    future_ms = int(time.time() * 1_000) + 60_000
    snapshot = native_policy_snapshot_v3(
        config=_config(),
        guard_home=guard_home,
        runtime_identity="a" * 64,
        rule_digest="b" * 64,
        policy_integrity_key=master,
        issued_at_ms=future_ms,
        expires_at_ms=future_ms + 60_000,
    )
    _write_resident_authority(guard_home, snapshot, master)
    worker = _ready_worker(
        guard_home,
        master,
        monkeypatch,
        publisher=_PoisonPublisher(),
        publish_native_policy=False,
    )
    binding = worker.prepare_workspace_policy(tmp_path / "workspace")
    assert binding is not None
    assert binding["generation"] == snapshot["generation"]
