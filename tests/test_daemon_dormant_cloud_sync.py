"""Disconnected background workers leave the real policy database untouched."""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
from codex_plugin_scanner.guard.daemon import server as daemon_module
from codex_plugin_scanner.guard.daemon.first_cloud_sync import background_cloud_sync_is_dormant
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_base import EncryptedFileSecretStore, FallbackSecretStore

_NOW = "2026-06-01T00:00:00+00:00"


class _StopAfterWait(threading.Event):
    def __init__(self, *, cycles: int = 2, after_first_wait: Callable[[], None] | None = None) -> None:
        super().__init__()
        self.cycles = cycles
        self.after_first_wait = after_first_wait
        self.waits: list[float | None] = []

    def wait(self, timeout: float | None = None) -> bool:
        self.waits.append(timeout)
        if len(self.waits) == 1 and self.after_first_wait is not None:
            self.after_first_wait()
        if len(self.waits) >= self.cycles:
            self.set()
        return self.is_set()


def _daemon(store: GuardStore, stop: _StopAfterWait) -> daemon_module.GuardDaemonServer:
    # Exercise the actual worker bodies without starting an unrelated HTTP server.
    daemon = object.__new__(daemon_module.GuardDaemonServer)
    vars(daemon).update(
        _server=SimpleNamespace(store=store),
        _shutdown_started=stop,
        _headless_cloud_sync_interval_seconds=17.0,
        _headless_cloud_sync_backoff_seconds=23.0,
        _bundle_refresh_interval_seconds=17.0,
        _bundle_refresh_backoff_seconds=23.0,
    )
    return daemon


def _run(daemon: daemon_module.GuardDaemonServer, kind: str) -> None:
    if kind == "headless":
        daemon._refresh_headless_cloud_sync_loop()
    else:
        daemon._refresh_supply_chain_bundle_loop()


@pytest.fixture(autouse=True)
def _clear_sync_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner, "_test_sync_auth_context_override", None)
    monkeypatch.delenv("HOL_GUARD_TEST_SYNC_AUTH_CONTEXT_JSON", raising=False)


@pytest.mark.parametrize("kind", ["headless", "supply"])
def test_fresh_background_sync_does_not_commit_bookkeeping(tmp_path: Path, kind: str) -> None:
    store = GuardStore(tmp_path / "guard", allow_system_keyring=False)
    stop = _StopAfterWait()
    with store._connect() as observer:
        before = observer.execute("pragma data_version").fetchone()[0]
        _run(_daemon(store, stop), kind)
        after = observer.execute("pragma data_version").fetchone()[0]
    assert after == before
    assert store.get_sync_payload("headless_app_sync_summary") is None
    assert store.get_sync_payload("supply_chain_bundle_daemon") is None
    assert stop.waits == [23.0, 23.0]


def _seed_credentials(store: GuardStore) -> None:
    key = generate_dpop_key_pair()
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="synthetic-refresh",
        dpop_private_key_pem=key.private_key_pem,
        dpop_public_jwk=key.public_jwk,
        dpop_public_jwk_thumbprint=key.public_jwk_thumbprint,
        grant_id="synthetic-grant",
        machine_id="synthetic-machine",
        workspace_id="synthetic-workspace",
        now=_NOW,
    )


def _record_sync_calls(monkeypatch: pytest.MonkeyPatch, kind: str) -> list[GuardStore]:
    calls: list[GuardStore] = []

    def sync(store: GuardStore) -> dict[str, object]:
        calls.append(store)
        return {"status": "synced"}

    target = "_run_headless_cloud_sync" if kind == "headless" else "sync_supply_chain_bundle"
    monkeypatch.setattr(daemon_module, target, sync)
    return calls


@pytest.mark.parametrize("kind", ["headless", "supply"])
@pytest.mark.parametrize("configuration", ["healthy", "degraded", "primary_recovery", "fallback_recovery"])
def test_existing_or_recoverable_credentials_keep_background_work_active(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str, configuration: str
) -> None:
    store = GuardStore(tmp_path / "guard", allow_system_keyring=False)
    if configuration == "primary_recovery":
        primary = EncryptedFileSecretStore(tmp_path / "primary")
        fallback = EncryptedFileSecretStore(tmp_path / "fallback")
        store._oauth_secret_store = FallbackSecretStore(primary, fallback)
    _seed_credentials(store)
    payload = store.get_sync_payload(store._oauth_local_credentials_state_key)
    assert isinstance(payload, dict)
    if configuration == "degraded":
        store.set_sync_payload(store._oauth_local_credentials_state_key, {"unrecognized": True}, _NOW)
        assert store.get_cloud_sync_profile() is None
        assert store.get_oauth_local_credential_health()["state"] == "degraded"
    elif configuration == "primary_recovery":
        secret_store = store._oauth_secret_store
        assert isinstance(secret_store, FallbackSecretStore)
        secret_ref = str(payload["credentials_ref"])
        secret_store.fallback.delete_secret(secret_ref)
        assert secret_store.primary.get_secret(secret_ref) is not None
        store.record_guard_connect_pairing_completed(
            sync_url="https://hol.org/api/guard/receipts/sync", allowed_origin="https://hol.org", now=_NOW
        )
        store.delete_sync_payload(store._oauth_local_credentials_state_key)
        store._clear_oauth_secret_payload_cache()
        assert store.get_sync_payload(store._oauth_local_credentials_state_key) is None
    elif configuration == "fallback_recovery":
        payload["credentials_sha256"] = "pbkdf2-sha256$" + "0" * 64
        store.set_sync_payload(store._oauth_local_credentials_state_key, payload, _NOW)
        store._clear_oauth_secret_payload_cache()
        assert store.get_oauth_local_credentials() is None
        assert store.get_recoverable_oauth_local_credentials() is not None
    calls = _record_sync_calls(monkeypatch, kind)
    stop = _StopAfterWait()
    _run(_daemon(store, stop), kind)
    assert calls == [store, store]
    assert stop.waits == [17.0, 17.0]
    if configuration == "primary_recovery":
        assert store.get_sync_payload(store._oauth_local_credentials_state_key) is not None
        assert store.get_oauth_local_credentials(allow_primary=True) is not None


@pytest.mark.parametrize("kind", ["headless", "supply"])
def test_disconnected_worker_observes_connection_on_next_existing_poll(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    store = GuardStore(tmp_path / "guard", allow_system_keyring=False)
    calls = _record_sync_calls(monkeypatch, kind)
    stop = _StopAfterWait(after_first_wait=lambda: _seed_credentials(store))
    _run(_daemon(store, stop), kind)
    assert calls == [store]
    assert stop.waits == [23.0, 17.0]


@pytest.mark.parametrize("kind", ["headless", "supply"])
@pytest.mark.parametrize("override", ["module", "environment"])
def test_existing_test_auth_overrides_still_drive_background_workers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str, override: str
) -> None:
    store = GuardStore(tmp_path / "guard", allow_system_keyring=False)
    context = {"sync_url": "https://hol.org/api/guard/receipts/sync", "access_token": "synthetic-access"}
    if override == "module":
        monkeypatch.setattr(runner, "_test_sync_auth_context_override", context)
    else:
        monkeypatch.setenv("HOL_GUARD_TEST_SYNC_AUTH_CONTEXT_JSON", json.dumps(context))
    calls = _record_sync_calls(monkeypatch, kind)
    _run(_daemon(store, _StopAfterWait()), kind)
    assert calls == [store, store]


def test_background_observation_error_does_not_suppress_existing_sync_error_handling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard", allow_system_keyring=False)

    def unavailable() -> dict[str, object]:
        raise RuntimeError("synthetic unavailable credential observation")

    monkeypatch.setattr(store, "get_oauth_local_credential_health", unavailable)
    assert not background_cloud_sync_is_dormant(store)
    _run(_daemon(store, _StopAfterWait()), "supply")
    summary = store.get_sync_payload("supply_chain_bundle_daemon")
    assert isinstance(summary, dict)
    assert summary["status"] == "error"


def test_active_headless_worker_preserves_managed_publication_callback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard", allow_system_keyring=False)
    _seed_credentials(store)
    received: list[object] = []

    def publish(*_args: object) -> None:
        return None

    def sync(*, store: GuardStore, managed_controls_publish: object = None) -> dict[str, object]:
        assert store.guard_home == tmp_path / "guard"
        received.append(managed_controls_publish)
        return {"status": "synced"}

    monkeypatch.setattr(daemon_module, "_run_headless_cloud_sync", sync)
    daemon = _daemon(store, _StopAfterWait())
    vars(daemon)["_server"] = SimpleNamespace(
        store=store, extension_control_runtime=SimpleNamespace(publish_after_commit=publish)
    )
    _run(daemon, "headless")
    assert received == [publish, publish]


@pytest.mark.parametrize("kind", ["headless", "supply"])
@pytest.mark.parametrize(
    ("error_type", "status"),
    [
        (runner.GuardSyncNotConfiguredError, "not_configured"),
        (runner.GuardSyncAuthorizationExpiredError, "auth_expired"),
        (RuntimeError, "error"),
    ],
)
def test_configured_sync_keeps_original_failure_reports_and_backoff(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    error_type: type[Exception],
    status: str,
) -> None:
    store = GuardStore(tmp_path / "guard", allow_system_keyring=False)
    _seed_credentials(store)

    def fail(_store: GuardStore) -> dict[str, object]:
        raise error_type("synthetic synchronization failure")

    target = "_resolve_guard_sync_auth_context" if kind == "headless" else "sync_supply_chain_bundle"
    monkeypatch.setattr(daemon_module, target, fail)
    stop = _StopAfterWait()
    _run(_daemon(store, stop), kind)
    key = "headless_app_sync_summary" if kind == "headless" else "supply_chain_bundle_daemon"
    summary = store.get_sync_payload(key)
    assert isinstance(summary, dict)
    expected = "pending" if kind == "headless" and status == "error" else status
    assert summary["status"] == expected
    assert stop.waits == [23.0, 23.0]
