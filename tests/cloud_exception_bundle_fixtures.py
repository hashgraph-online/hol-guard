"""Code-generated Cloud exception bundle fixtures for sync proof tests."""

from __future__ import annotations

from datetime import datetime, timezone

from tests.test_policy_bundle_parser import _sample_policy_bundle, computed_policy_bundle_hash


def build_cloud_exception_bundle_entry(
    *,
    exception_id: str = "artifact:codex:sync-proof",
    expires_at: str = "2099-01-01T00:00:00+00:00",
    workspace_id: str | None = None,
) -> dict[str, object]:
    entry: dict[str, object] = {
        "exceptionId": exception_id,
        "effect": "allow",
        "scope": "artifact",
        "harness": "codex",
        "artifactId": "codex:project:sync-proof",
        "owner": "owner@example.com",
        "approver": "approver@example.com",
        "expiresAt": expires_at,
        "sourceReceiptId": "receipt-sync-proof",
    }
    if workspace_id is not None:
        entry["workspaceId"] = workspace_id
    return entry


def build_cloud_exception_policy_bundle(
    *,
    bundle_hash: str | None = None,
    cloud_exceptions: list[dict[str, object]] | None = None,
    workspace_id: str = "workspace-sync-proof",
    device_id: str = "device-sync-proof",
) -> dict[str, object]:
    bundle = _sample_policy_bundle(bundle_hash=bundle_hash)
    bundle["workspaceId"] = workspace_id
    bundle["cloudExceptions"] = cloud_exceptions or [build_cloud_exception_bundle_entry()]
    bundle["acknowledgements"] = [
        {
            "deviceId": device_id,
            "deviceName": "Sync proof device",
            "acknowledgedAt": datetime.now(timezone.utc).isoformat(),
            "status": "synced",
        }
    ]
    if bundle_hash is None:
        bundle["bundleHash"] = computed_policy_bundle_hash(bundle)
    return bundle
