from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

SRC_PATH = Path(__file__).resolve().parents[1] / "src"
SUPPORT_PATH = Path(__file__).resolve().parent / "support"

if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))
if str(SUPPORT_PATH) not in sys.path:
    sys.path.insert(0, str(SUPPORT_PATH))

existing_pythonpath = os.environ.get("PYTHONPATH", "")
pythonpath_entries = [entry for entry in existing_pythonpath.split(os.pathsep) if entry]
pythonpath_prefix = [str(path) for path in (SUPPORT_PATH, SRC_PATH) if str(path) not in pythonpath_entries]
if pythonpath_prefix:
    os.environ["PYTHONPATH"] = os.pathsep.join([*pythonpath_prefix, *pythonpath_entries])


@pytest.fixture(autouse=True)
def _reset_guard_sync_resolver_override(monkeypatch: pytest.MonkeyPatch) -> None:
    """Undo any _resolve_guard_sync_auth_context override leaked by _seed_guard_cloud."""
    from codex_plugin_scanner.guard.runtime import runner as guard_runner_module

    monkeypatch.setattr(
        guard_runner_module,
        "_resolve_guard_sync_auth_context",
        guard_runner_module._resolve_guard_sync_auth_context,
    )
    guard_runner_module._test_sync_auth_context_override = None


@pytest.fixture(autouse=True)
def _isolate_trust_attestation_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Clear trust attestation env vars so tests don't inherit the developer's shell config."""
    for key in (
        "GUARD_AIBOM_TRUST_ATTESTATION_V2",
        "GUARD_AIBOM_TRUST_ATTESTATION_PRIVATE_KEY",
        "GUARD_AIBOM_TRUST_ATTESTATION_KEY_ID",
        "GUARD_AIBOM_TRUST_ATTESTATION_HEADLESS_SHORT_LIVED",
    ):
        monkeypatch.delenv(key, raising=False)


@pytest.fixture(autouse=True)
def _isolate_daemon_background_refresh_workers(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Start daemon refresh workers only in tests that exercise them."""
    from codex_plugin_scanner.guard.daemon import server as daemon_server

    worker_markers = {
        "daemon_aibom_refresh": "_start_aibom_inventory_refresh",
        "daemon_bundle_refresh": "_start_supply_chain_bundle_refresh",
        "daemon_headless_refresh": "_start_headless_cloud_sync",
    }
    for marker, method_name in worker_markers.items():
        if request.node.get_closest_marker(marker) is None:
            monkeypatch.setattr(daemon_server.GuardDaemonServer, method_name, lambda _self: None)
    if request.node.get_closest_marker("daemon_headless_queue") is None:
        monkeypatch.setattr(
            daemon_server,
            "_queue_headless_cloud_sync",
            lambda *, store: {
                "status": "not_configured",
                "message": "Cloud sync is isolated for this test.",
            },
        )

class _FakeSystemKeyringModule:
    def __init__(self) -> None:
        self._secrets: dict[tuple[str, str], str] = {}

    @staticmethod
    def _store_path() -> Path | None:
        value = os.environ.get("HOL_GUARD_TEST_KEYRING_FILE", "").strip()
        return Path(value) if value else None

    def _load(self) -> dict[tuple[str, str], str]:
        store_path = self._store_path()
        if store_path is None or not store_path.is_file():
            return dict(self._secrets)
        payload = json.loads(store_path.read_text(encoding="utf-8"))
        return {
            (str(service_name), str(secret_id)): str(secret_value)
            for service_name, secrets in payload.items()
            if isinstance(service_name, str) and isinstance(secrets, dict)
            for secret_id, secret_value in secrets.items()
            if isinstance(secret_id, str) and isinstance(secret_value, str)
        }

    def _persist(self, secrets: dict[tuple[str, str], str]) -> None:
        self._secrets = dict(secrets)
        store_path = self._store_path()
        if store_path is None:
            return
        payload: dict[str, dict[str, str]] = {}
        for (service_name, secret_id), secret_value in secrets.items():
            payload.setdefault(service_name, {})[secret_id] = secret_value
        store_path.parent.mkdir(parents=True, exist_ok=True)
        store_path.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")), encoding="utf-8")

    @staticmethod
    def get_keyring():
        class _Backend:
            priority = 1

        return _Backend()

    def set_password(self, service_name: str, secret_id: str, value: str) -> None:
        secrets = self._load()
        secrets[(service_name, secret_id)] = value
        self._persist(secrets)

    def get_password(self, service_name: str, secret_id: str) -> str | None:
        return self._load().get((service_name, secret_id))

    def delete_password(self, service_name: str, secret_id: str) -> None:
        secrets = self._load()
        secrets.pop((service_name, secret_id), None)
        self._persist(secrets)


@pytest.fixture
def install_fake_system_keyring(monkeypatch: pytest.MonkeyPatch) -> Callable[[], _FakeSystemKeyringModule]:
    from codex_plugin_scanner.guard.store import SystemKeyringSecretStore

    def _install() -> _FakeSystemKeyringModule:
        module = _FakeSystemKeyringModule()
        monkeypatch.setattr(SystemKeyringSecretStore, "_load_keyring_module", staticmethod(lambda: module))
        monkeypatch.setattr(
            SystemKeyringSecretStore,
            "_macos_default_keychain_is_usable",
            classmethod(lambda cls: True),
        )
        return module

    return _install


@pytest.fixture
def allow_transient_shell_profile_writes(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import shims as guard_shims_module

    monkeypatch.setattr(guard_shims_module, "_is_transient_path", lambda _path: False)


_FAKE_SYSTEM_KEYRING_DISABLED_FILES = {
    "test_guard_store_migrations.py",
}

_FAKE_SYSTEM_KEYRING_DISABLED_NODEIDS = {
    "tests/test_guard_cli.py::TestGuardCli::test_guard_status_reports_oauth_key_storage_health",
}


@pytest.fixture(autouse=True)
def _policy_integrity_keyring_for_selected_tests(
    request: pytest.FixtureRequest,
    install_fake_system_keyring,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    if (
        request.node.path.name in _FAKE_SYSTEM_KEYRING_DISABLED_FILES
        or request.node.nodeid in _FAKE_SYSTEM_KEYRING_DISABLED_NODEIDS
    ):
        return
    monkeypatch.setenv("HOL_GUARD_TEST_KEYRING_FILE", str(tmp_path / "fake-system-keyring.json"))
    install_fake_system_keyring()


@pytest.fixture
def seed_connected_oauth_without_entitlement() -> Callable[[object], None]:
    from codex_plugin_scanner.guard.store import GuardStore

    def _seed(store: GuardStore) -> None:
        store.set_oauth_local_credentials(
            issuer="https://hol.org",
            client_id="guard-local-daemon",
            refresh_token="refresh-token-1",
            dpop_private_key_pem="private-key",
            dpop_public_jwk={"kty": "EC", "crv": "P-256", "x": "x-value", "y": "y-value"},
            dpop_public_jwk_thumbprint="thumbprint-1",
            grant_id="grant-1",
            machine_id="machine-1",
            workspace_id="workspace-1",
            now="2026-06-05T01:39:51+00:00",
        )
        store.record_guard_connect_pairing_completed(
            sync_url="https://hol.org/api/guard/receipts/sync",
            allowed_origin="https://hol.org",
            now="2026-06-05T01:39:51+00:00",
            request_id="connect-1",
        )

    return _seed
