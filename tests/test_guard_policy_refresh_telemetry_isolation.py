"""HGP-187: policy refresh stays applied when telemetry fails."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
from codex_plugin_scanner.guard.runtime import runner as guard_runner_module
from codex_plugin_scanner.guard.store import GuardStore
from tests.support.network import stub_authenticated_urlopen


class _JsonResponse:
    def __init__(self, payload: dict[str, object]) -> None:
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self) -> bytes:
        return json.dumps(self._payload).encode("utf-8")


def _seed(store: GuardStore, monkeypatch: pytest.MonkeyPatch) -> None:
    dpop = generate_dpop_key_pair()
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="demo-token",
        dpop_private_key_pem=dpop.private_key_pem,
        dpop_public_jwk=dpop.public_jwk,
        dpop_public_jwk_thumbprint=dpop.public_jwk_thumbprint,
        grant_id="grant-1",
        machine_id="machine-1",
        workspace_id="workspace-1",
        now="2026-09-17T00:00:00Z",
    )
    monkeypatch.setattr(
        guard_runner_module,
        "_test_sync_auth_context_override",
        {
            "sync_url": "https://hol.org/api/guard/receipts/sync",
            "access_token": "demo-token",
            "dpop_key_material": None,
        },
    )


def test_pain_signal_runtime_error_does_not_unapply_policy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed(store, monkeypatch)

    def _fake_urlopen(request, timeout):
        return _JsonResponse({"syncedAt": "2026-09-17T00:00:10+00:00", "receiptsStored": 0})

    stub_authenticated_urlopen(monkeypatch, _fake_urlopen)

    def _boom(_store, auth_context=None):
        raise RuntimeError("pain-signal upstream 500")

    monkeypatch.setattr(guard_runner_module, "sync_pain_signals", _boom)
    summary = guard_runner_module.sync_receipts(store)
    assert summary["pain_signals_uploaded"] == 0
    assert summary["telemetry_status"] == "degraded"
    assert summary["pain_signals_upload_status"] == "degraded"
    assert summary["pain_signals_upload_reason"] == "telemetry_upload_failed"
    retry = guard_runner_module.sync_receipts(store)
    assert retry["telemetry_status"] == "degraded"
