"""Cloud credentials and the shared HTTP handler for CLI tests."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import ClassVar

import pytest

from codex_plugin_scanner.guard.policy_bundle_parser import computed_policy_bundle_hash, payload_hash_for_policy_bundle
from codex_plugin_scanner.guard.runtime import runner as guard_runner_module
from codex_plugin_scanner.guard.store import GuardStore
from tests.cloud_exception_bundle_fixtures import build_cloud_exception_policy_bundle
from tests.policy_bundle_signing_helpers import policy_bundle_test_keyring, sign_policy_bundle


def _seed_guard_cloud(
    store, *, workspace_id="workspace-1", sync_url=None, token="demo-token", now="2026-05-19T00:00:00Z"
):
    """Seed OAuth credentials (replaces legacy set_sync_credentials scaffolding)."""
    from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair

    dpop_key_material = generate_dpop_key_pair()
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token=token,
        dpop_private_key_pem=dpop_key_material.private_key_pem,
        dpop_public_jwk=dpop_key_material.public_jwk,
        dpop_public_jwk_thumbprint=dpop_key_material.public_jwk_thumbprint,
        grant_id="grant-1",
        machine_id="machine-1",
        workspace_id=workspace_id,
        now=now,
    )
    if workspace_id is not None:
        store.set_sync_payload(
            "policy_bundle_keyring",
            policy_bundle_test_keyring(workspace_id=workspace_id),
            now,
        )
    if sync_url is not None:
        captured_sync_url = sync_url
        captured_token = token

        def _fake_resolve(store, *, allow_primary_repair=True):
            return {"sync_url": captured_sync_url, "access_token": captured_token, "dpop_key_material": None}

        _mp = pytest.MonkeyPatch()
        _mp.setattr(guard_runner_module, "_resolve_guard_sync_auth_context", _fake_resolve)


def _signed_status_policy_bundle(*, workspace_id: str = "workspace-1") -> dict[str, object]:
    policy_bundle = build_cloud_exception_policy_bundle(workspace_id=workspace_id)
    policy_bundle["bundleVersion"] = "policy-2026-05-01.3"
    policy_bundle["rolloutState"] = "enforcing"
    return sign_policy_bundle(policy_bundle, workspace_id=workspace_id)


def _digest_only_status_policy_bundle(*, workspace_id: str = "workspace-1") -> dict[str, object]:
    policy_bundle = _signed_status_policy_bundle(workspace_id=workspace_id)
    policy_bundle["verifier"] = {
        "algorithm": "sha256",
        "keyId": "attacker-recomputed-digest",
        "signature": None,
    }
    policy_bundle["bundleHash"] = computed_policy_bundle_hash(policy_bundle)
    policy_bundle["payloadHash"] = payload_hash_for_policy_bundle(policy_bundle)
    return policy_bundle


def _disable_oauth_persistence_assert(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(GuardStore, "_assert_oauth_secret_persisted", lambda self, secret_id, value: None)


def _seed_sync_credentials(
    home_dir: Path,
    sync_url: str,
    token: str = "demo-token",
    workspace_id: str = "workspace-1",
) -> None:
    from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
    from codex_plugin_scanner.guard.runtime import runner as guard_runner_module

    dpop_key_material = generate_dpop_key_pair()
    store = GuardStore(home_dir)
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token=token,
        dpop_private_key_pem=dpop_key_material.private_key_pem,
        dpop_public_jwk=dpop_key_material.public_jwk,
        dpop_public_jwk_thumbprint=dpop_key_material.public_jwk_thumbprint,
        grant_id="grant-1",
        machine_id="machine-1",
        workspace_id=workspace_id,
        now="2026-04-09T00:00:00Z",
    )
    store.set_sync_payload(
        "policy_bundle_keyring",
        policy_bundle_test_keyring(workspace_id=workspace_id),
        "2026-04-09T00:00:00Z",
    )
    guard_runner_module._test_sync_auth_context_override = {
        "sync_url": sync_url,
        "access_token": token,
        "dpop_key_material": None,
    }


class _SyncRequestHandler(BaseHTTPRequestHandler):
    response_code = 200
    captured_headers: ClassVar[dict[str, str]] = {}
    captured_body: ClassVar[dict[str, object] | None] = None
    captured_bodies: ClassVar[list[dict[str, object]]] = []
    captured_paths: ClassVar[list[str]] = []
    raw_response_body: ClassVar[str | None] = None
    response_payload: ClassVar[dict[str, object]] = {
        "syncedAt": "2026-04-09T00:00:00Z",
        "receiptsStored": 1,
    }

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8") if length else "{}"
        _SyncRequestHandler.captured_headers = {key.lower(): value for key, value in self.headers.items()}
        _SyncRequestHandler.captured_body = json.loads(body)
        _SyncRequestHandler.captured_bodies.append(_SyncRequestHandler.captured_body)
        _SyncRequestHandler.captured_paths.append(self.path)
        self.send_response(self.response_code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        response_body = _SyncRequestHandler.raw_response_body
        if response_body is None:
            response_body = json.dumps(_SyncRequestHandler.response_payload)
        self.wfile.write(response_body.encode("utf-8"))

    def log_message(self, fmt: str, *args) -> None:
        return
