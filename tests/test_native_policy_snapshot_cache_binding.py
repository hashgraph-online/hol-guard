"""CLI hook workers reuse a durable ACKed snapshot when publication times out."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

import codex_plugin_scanner.guard.daemon.hook_worker as hook_worker_module
from codex_plugin_scanner.guard.native_policy_snapshot import native_policy_snapshot_v3
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


def _write_resident_generation(guard_home: Path, generation: object) -> None:
    assert isinstance(generation, int)
    resident = guard_home / "native-runtime" / "resident-v3-test"
    resident.mkdir(parents=True, exist_ok=True)
    (resident / f"generation-{generation:020d}.json").write_text("{}", encoding="utf-8")


def _ready_worker(guard_home: Path, master: bytes, monkeypatch: pytest.MonkeyPatch) -> hook_worker_module.HookWorker:
    store = GuardStore(guard_home)
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda *, create: (master, "master-id"))
    monkeypatch.setattr(hook_worker_module, "native_mode", lambda: "auto")
    monkeypatch.setattr(hook_worker_module, "get_native_policy_snapshot_publisher", lambda _store: _TimeoutPublisher())
    return hook_worker_module.HookWorker(store=store)


def test_prepare_workspace_policy_reuses_resident_backed_cache_when_wait_times_out(
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
    _write_resident_generation(guard_home, snapshot["generation"])
    worker = _ready_worker(guard_home, master, monkeypatch)
    binding = worker.prepare_workspace_policy(tmp_path / "workspace")

    assert binding is not None
    assert binding["generation"] == snapshot["generation"]
    assert binding["policy_digest"] == snapshot["policy_digest"]
    assert binding["runtime_identity"] == snapshot["runtime_identity"]
    assert binding["mode"] == snapshot["mode"]


def test_prepare_workspace_policy_rejects_cache_without_resident_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    master = b"u" * 32
    future_ms = int(time.time() * 1_000) + 60_000
    native_policy_snapshot_v3(
        config=_config(),
        guard_home=guard_home,
        runtime_identity="a" * 64,
        rule_digest="b" * 64,
        policy_integrity_key=master,
        issued_at_ms=future_ms,
        expires_at_ms=future_ms + 60_000,
    )
    worker = _ready_worker(guard_home, master, monkeypatch)
    assert worker.prepare_workspace_policy(tmp_path / "workspace") is None


def test_prepare_workspace_policy_rejects_expired_acked_cache(
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
    _write_resident_generation(guard_home, snapshot["generation"])
    expires_at_ms = snapshot["expires_at_ms"]
    assert isinstance(expires_at_ms, int)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_policy_snapshot_storage.time.time",
        lambda: (expires_at_ms / 1_000) + 1,
    )
    worker = _ready_worker(guard_home, master, monkeypatch)
    assert worker.prepare_workspace_policy(tmp_path / "workspace") is None
