# pyright: reportPrivateUsage=false

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.connect_flow import _parse_guard_token_exchange_payload
from codex_plugin_scanner.guard.runtime import runner as runner_module
from codex_plugin_scanner.guard.runtime.exact_cloud_review import (
    ExactCloudReviewError,
    enable_exact_cloud_review,
    exact_cloud_review_status,
)
from tests.guard_exact_cloud_review_support import connected_exact_review_store

_FIXTURE_PATH = Path(__file__).parent / "fixtures" / "guard-cloud-review-v2" / "oauth-device-fixtures.json"
_FIXTURE_SHA256 = "63adcc35f5ebd09c8b18407ccad4241bbf8f1eafb4c4524f4262972877bc9c77"


def _oauth_cases() -> dict[str, dict[str, object]]:
    fixture_bytes = _FIXTURE_PATH.read_bytes()
    assert hashlib.sha256(fixture_bytes).hexdigest() == _FIXTURE_SHA256
    fixture = json.loads(fixture_bytes)
    assert fixture["contractVersion"] == "guard-cloud-review-oauth-device-v1"
    return {case["name"]: case for case in fixture["cases"]}


def _access_token(case: dict[str, object]) -> str:
    def encoded(value: dict[str, object]) -> str:
        return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")

    claims = {
        "device": case["device"],
        "grant": {"grantId": case["grantId"]},
        "machine": case["machine"],
        "workspace": {"workspaceId": case["workspaceId"]},
    }
    return ".".join((encoded({"alg": "none"}), encoded(claims), "signature"))


def test_oauth_device_fixture_refresh_and_rotation_are_bound_exactly(tmp_path: Path) -> None:
    cases = _oauth_cases()
    active = cases["active-device-binding"]
    rotated = cases["rotated-device-key"]
    missing = cases["missing-device-claim"]
    active_device = active["device"]
    active_machine = active["machine"]
    assert isinstance(active_device, dict) and isinstance(active_machine, dict)
    assert active_device["deviceId"] != active_machine["machineId"]
    parsed = _parse_guard_token_exchange_payload(
        {
            "access_token": _access_token(active),
            "expires_in": 300,
            "refresh_token": "refresh-initial",
            "scope": "guard:runtime.sync guard:offline_access",
            "token_type": "Bearer",
        }
    )
    assert parsed.device_id == active_device["deviceId"]
    assert parsed.machine_id == active_machine["machineId"]
    store = connected_exact_review_store(tmp_path, device_id=str(active_device["deviceId"]))
    credentials = store.get_oauth_local_credentials(allow_primary=False)
    assert isinstance(credentials, dict)
    runner_module._persist_rotated_oauth_refresh_token(
        store=store,
        credentials=credentials,
        refresh_token="refresh-initial",
        access_token=_access_token(active),
    )
    credentials = store.get_oauth_local_credentials(allow_primary=False)
    assert isinstance(credentials, dict)
    enable_exact_cloud_review(store)
    runner_module._persist_rotated_oauth_refresh_token(
        store=store,
        credentials=credentials,
        refresh_token="refresh-same-key",
        access_token=_access_token(active),
    )
    refreshed = store.get_oauth_local_credentials(allow_primary=False)
    assert isinstance(refreshed, dict)
    assert refreshed["device_id"] == active_device["deviceId"]
    assert refreshed["machine_id"] == active_machine["machineId"]
    assert exact_cloud_review_status(store)["enabled"] is True

    runner_module._persist_rotated_oauth_refresh_token(
        store=store,
        credentials=refreshed,
        refresh_token="refresh-rotated-key",
        access_token=_access_token(rotated),
    )
    rotated_device = rotated["device"]
    assert isinstance(rotated_device, dict)
    rotated_credentials = store.get_oauth_local_credentials(allow_primary=False)
    assert isinstance(rotated_credentials, dict)
    assert rotated_credentials["device_id"] == rotated_device["deviceId"]
    status = exact_cloud_review_status(store)
    assert status["enabled"] is False
    assert status["reason"] == "cloud_review_oauth_device_binding_mismatch"

    missing_parsed = _parse_guard_token_exchange_payload(
        {
            "access_token": _access_token(missing),
            "expires_in": 300,
            "refresh_token": "refresh-missing-device",
            "scope": "guard:runtime.sync guard:offline_access",
            "token_type": "Bearer",
        }
    )
    assert missing_parsed.machine_id == active_machine["machineId"]
    assert missing_parsed.device_id is None
    missing_store = connected_exact_review_store(tmp_path / "missing", device_id=str(active_device["deviceId"]))
    missing_credentials = missing_store.get_oauth_local_credentials(allow_primary=False)
    assert isinstance(missing_credentials, dict)
    runner_module._persist_rotated_oauth_refresh_token(
        store=missing_store,
        credentials=missing_credentials,
        refresh_token="refresh-initial",
        access_token=_access_token(active),
    )
    enable_exact_cloud_review(missing_store)
    missing_credentials = missing_store.get_oauth_local_credentials(allow_primary=False)
    assert isinstance(missing_credentials, dict)
    runner_module._persist_rotated_oauth_refresh_token(
        store=missing_store,
        credentials=missing_credentials,
        refresh_token="refresh-missing-device",
        access_token=_access_token(missing),
    )
    persisted_missing = missing_store.get_oauth_local_credentials(allow_primary=False)
    assert isinstance(persisted_missing, dict) and persisted_missing.get("device_id") is None
    missing_status = exact_cloud_review_status(missing_store)
    assert missing_status["enabled"] is False
    assert missing_status["reason"] == "cloud_review_device_binding_missing"


def test_exact_review_rejects_device_claim_not_bound_to_local_dpop_key(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    credentials = store.get_oauth_local_credentials(allow_primary=False)
    assert isinstance(credentials, dict)
    public_jwk = credentials["dpop_public_jwk"]
    assert isinstance(public_jwk, dict)
    store.set_oauth_local_credentials(
        issuer=str(credentials["issuer"]),
        client_id=str(credentials["client_id"]),
        refresh_token=str(credentials["refresh_token"]),
        dpop_private_key_pem=str(credentials["dpop_private_key_pem"]),
        dpop_public_jwk={str(key): str(value) for key, value in public_jwk.items()},
        dpop_public_jwk_thumbprint=str(credentials["dpop_public_jwk_thumbprint"]),
        grant_id=str(credentials["grant_id"]),
        machine_id=str(credentials["machine_id"]),
        device_id="forged-device-not-the-dpop-thumbprint",
        workspace_id=str(credentials["workspace_id"]),
        now=datetime.now(timezone.utc).isoformat(),
    )

    with pytest.raises(ExactCloudReviewError, match="cloud_review_oauth_device_binding_mismatch"):
        enable_exact_cloud_review(store)


def test_malformed_explicit_refresh_clears_stale_exact_authority(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    credentials = store.get_oauth_local_credentials(allow_primary=False)
    assert isinstance(credentials, dict)
    enable_exact_cloud_review(store)

    runner_module._persist_rotated_oauth_refresh_token(
        store=store,
        credentials=credentials,
        refresh_token="refresh-malformed-token",
        access_token="not-a-jwt",
    )

    persisted = store.get_oauth_local_credentials(allow_primary=False)
    assert isinstance(persisted, dict)
    assert persisted.get("device_id") is None
    assert persisted.get("machine_id") is None
    assert persisted.get("grant_id") is None
    assert persisted.get("workspace_id") is None
    status = exact_cloud_review_status(store)
    assert status["enabled"] is False
    assert status["reason"] == "cloud_review_device_binding_missing"
