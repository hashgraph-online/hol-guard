"""Code-generated Cloud exception bundle fixtures for sync proof tests."""

from __future__ import annotations

from datetime import datetime, timezone

from codex_plugin_scanner.guard.policy_bundle_parser import computed_policy_bundle_hash
from tests.policy_bundle_signing_helpers import sign_policy_bundle


def _sample_policy_bundle(*, bundle_hash: str | None = None) -> dict[str, object]:
    bundle: dict[str, object] = {
        "contractVersion": "guard-policy-bundle.v1",
        "bundleVersion": "policy-2026-04-19.1",
        "bundleHash": bundle_hash or "",
        "issuedAt": "2026-04-19T00:00:10+00:00",
        "expiresAt": None,
        "verifier": {
            "algorithm": "rsa-pss-sha256",
            "keyId": "guard-policy-bundle-v1",
            "signature": None,
        },
        "rolloutState": "enforcing",
        "policyDefaults": {
            "mode": "enforce",
            "defaultAction": "warn",
            "unknownPublisherAction": "review",
            "changedHashAction": "require-reapproval",
            "newNetworkDomainAction": "warn",
            "subprocessAction": "block",
            "telemetryEnabled": False,
            "syncEnabled": True,
        },
        "rules": [
            {
                "ruleId": "pkg-block",
                "action": "block",
                "reason": "Block risky package installs before execution.",
                "artifactType": "package_request",
                "matcherFamilies": ["package-request"],
                "scope": {
                    "agents": [],
                    "devices": [],
                    "ecosystems": [],
                    "environments": ["development"],
                    "harnesses": ["codex"],
                    "locations": [],
                },
            }
        ],
        "acknowledgements": [],
    }
    if bundle_hash is None:
        bundle["bundleHash"] = computed_policy_bundle_hash(bundle)
    return bundle


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
    signed_bundle = sign_policy_bundle(bundle, workspace_id=workspace_id)
    if bundle_hash is not None:
        signed_bundle["bundleHash"] = bundle_hash
    return signed_bundle
