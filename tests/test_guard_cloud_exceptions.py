"""Cloud exception DTO persistence and API coverage (HGLP046-HGLP060)."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.cloud_exceptions import (
    build_cloud_exceptions_from_sync_payload,
    cloud_exception_from_mapping,
    list_active_cloud_exceptions,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.cloud_exception_bundle_fixtures import (
    build_cloud_exception_bundle_entry,
    build_cloud_exception_policy_bundle,
)
from tests.policy_bundle_signing_helpers import (
    policy_bundle_test_keyring,
    policy_bundle_test_verification_key,
    sign_policy_bundle,
)

_WORKSPACE_ID = "workspace-sync-proof"
_PERSISTED_AT = "2026-06-13T00:00:00+00:00"


def _cache_signed_cloud_exception_bundle(
    store: GuardStore,
    *,
    cloud_exceptions: list[dict[str, object]],
    now: str = _PERSISTED_AT,
) -> tuple[dict[str, object], str, dict[str, object]]:
    """Cache a signed bundle under the same workspace and device used by reads."""

    device_id = str(store.get_device_metadata()["installation_id"])
    bundle = build_cloud_exception_policy_bundle(
        cloud_exceptions=cloud_exceptions,
        workspace_id=_WORKSPACE_ID,
        device_id=device_id,
    )
    acknowledgement = {
        "appliedAt": now,
        "bundleHash": bundle["bundleHash"],
        "bundleVersion": bundle["bundleVersion"],
        "deviceId": device_id,
        "deviceName": "Cloud exception test device",
        "status": "synced",
    }
    # The workspace metadata is the binding that cached-bundle validation reads.
    # No OAuth secret is needed for these storage-only tests.
    store.set_sync_payload("oauth_local_credentials", {"workspace_id": _WORKSPACE_ID}, now)
    store.set_sync_payload(
        "policy_bundle_keyring",
        policy_bundle_test_keyring(workspace_id=_WORKSPACE_ID),
        now,
    )
    store.set_sync_payload("policy_bundle", bundle, now)
    store.set_sync_payload("policy_bundle_ack", acknowledgement, now)
    return bundle, device_id, acknowledgement


def _sample_sync_exception(*, exception_id: str = "artifact:codex:demo") -> dict[str, object]:
    return {
        "exceptionId": exception_id,
        "scope": "artifact",
        "harness": "codex",
        "artifactId": "codex:project:demo",
        "owner": "owner@example.com",
        "approver": "approver@example.com",
        "reason": "Temporary allow for demo artifact",
        "expiresAt": "2099-01-01T00:00:00Z",
        "sourceReceiptId": "receipt_demo_001",
    }


def test_cloud_exception_dto_includes_required_fields() -> None:
    parsed = cloud_exception_from_mapping(_sample_sync_exception())
    assert parsed is not None
    payload = parsed.to_dict()
    for key in (
        "id",
        "effect",
        "scope",
        "harness",
        "owner",
        "approver",
        "expiry",
        "source_receipt_id",
        "bundle_hash",
        "ack_status",
        "last_used_at",
    ):
        assert key in payload


def test_expired_cloud_exceptions_are_not_active() -> None:
    expired = cloud_exception_from_mapping(
        {
            **_sample_sync_exception(exception_id="expired:1"),
            "expiresAt": "2020-01-01T00:00:00Z",
        }
    )
    assert expired is not None
    active = list_active_cloud_exceptions([expired], now="2026-01-01T00:00:00+00:00")
    assert active == []


def test_sync_payload_builder_parses_distinct_ids() -> None:
    items = build_cloud_exceptions_from_sync_payload(
        [_sample_sync_exception(), _sample_sync_exception(exception_id="artifact:codex:other")]
    )
    assert len(items) == 2


def test_signed_bundle_exception_is_hidden_after_bundle_expiry(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "home")
    bundle, _device_id, _acknowledgement = _cache_signed_cloud_exception_bundle(
        store,
        cloud_exceptions=[build_cloud_exception_bundle_entry(exception_id="bundle:expired")],
    )
    bundle["expiresAt"] = "2026-07-01T00:00:00Z"
    store.set_sync_payload("policy_bundle", sign_policy_bundle(bundle, workspace_id=_WORKSPACE_ID), _PERSISTED_AT)

    assert store.list_cloud_exceptions() == []


def test_signed_bundle_exception_is_hidden_after_key_revocation(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "home")
    _cache_signed_cloud_exception_bundle(
        store,
        cloud_exceptions=[build_cloud_exception_bundle_entry(exception_id="bundle:revoked")],
    )
    revoked_key = policy_bundle_test_verification_key(
        state="revoked",
        workspace_id=_WORKSPACE_ID,
    )
    store.set_sync_payload(
        "policy_bundle_keyring",
        policy_bundle_test_keyring(workspace_id=_WORKSPACE_ID, key=revoked_key),
        _PERSISTED_AT,
    )

    assert store.list_cloud_exceptions() == []
