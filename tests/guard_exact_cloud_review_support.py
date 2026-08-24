from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_oauth_token_support import oauth_binding_access_token
from tests.guard_review_signing_helpers import review_trusted_keyring_payload


def connected_exact_review_store(
    tmp_path: Path,
    *,
    device_id: str | None = None,
    missing_device_id: bool = False,
) -> GuardStore:
    store = GuardStore(tmp_path / "guard-home")
    dpop = generate_dpop_key_pair()
    machine_id = str(store.get_device_metadata()["installation_id"])
    now = datetime.now(timezone.utc).isoformat()
    bound_device_id = device_id or "device-default"
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-token",
        dpop_private_key_pem=dpop.private_key_pem,
        dpop_public_jwk=dpop.public_jwk,
        dpop_public_jwk_thumbprint=bound_device_id,
        grant_id="grant-1",
        machine_id=machine_id,
        device_id=None if missing_device_id else bound_device_id,
        workspace_id="workspace-1",
        access_token=oauth_binding_access_token(
            device_id=bound_device_id,
            grant_id="grant-1",
            machine_id=machine_id,
            workspace_id="workspace-1",
        ),
        access_token_expires_at="2099-01-01T00:00:00+00:00",
        now=now,
    )
    store.set_sync_payload(
        "guard_review_verification_keyring",
        review_trusted_keyring_payload(workspace_id="workspace-1"),
        now,
    )
    return store


def post_json(port: int, path: str, token: str, payload: dict[str, object]) -> tuple[int, dict[str, object]]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Origin": "http://127.0.0.1:6174",
            "X-Guard-Token": token,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read().decode("utf-8"))


__all__ = ["connected_exact_review_store", "post_json"]
