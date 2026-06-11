from __future__ import annotations

import os
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

SRC_PATH = Path(__file__).resolve().parents[1] / "src"

if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

existing_pythonpath = os.environ.get("PYTHONPATH", "")
pythonpath_entries = [entry for entry in existing_pythonpath.split(os.pathsep) if entry]
if str(SRC_PATH) not in pythonpath_entries:
    os.environ["PYTHONPATH"] = os.pathsep.join([str(SRC_PATH), *pythonpath_entries])


@pytest.fixture(autouse=True)
def _disable_real_macos_keychain(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.store import KeychainSecretStore

    monkeypatch.setattr(KeychainSecretStore, "_is_available", staticmethod(lambda: False))


@pytest.fixture
def seed_connected_oauth_without_entitlement() -> Callable[["GuardStore"], None]:
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
