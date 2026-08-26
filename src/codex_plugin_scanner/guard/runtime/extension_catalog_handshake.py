"""Pure validation and request preparation for Extension catalog negotiation."""

from __future__ import annotations

import json
import urllib.parse
from collections.abc import Callable, Mapping
from dataclasses import dataclass


@dataclass(frozen=True)
class ExtensionCatalogUpload:
    url: str
    body: bytes


def prepare_extension_catalog_handshake(
    *,
    runtime_sync_url: str,
    runtime_response: dict[str, object],
    session_payload: dict[str, object],
    catalog_factory: Callable[[str], Mapping[str, object]],
    fallback_generated_at: str,
) -> tuple[dict[str, object], ExtensionCatalogUpload | None]:
    """Validate Cloud negotiation and prepare a digest-bound upload without I/O."""

    digest = session_payload.get("extensionCatalogDigest")
    if not isinstance(digest, str):
        return {}, None
    handshake = runtime_response.get("extensionCatalogSync")
    if handshake is None:
        return {
            "managedControlsCapabilities": [],
            "extension_catalog_sync_status": "downgraded",
            "extension_catalog_sync_reason": "catalog_handshake_unavailable",
        }, None
    expected_fields = {"catalogDigest", "catalogKnown", "uploadRequired", "uploadPath"}
    if not isinstance(handshake, dict) or set(handshake) != expected_fields:
        raise RuntimeError("Invalid Extension catalog handshake response")
    known = handshake.get("catalogKnown")
    upload_required = handshake.get("uploadRequired")
    upload_path = handshake.get("uploadPath")
    if (
        handshake.get("catalogDigest") != digest
        or type(known) is not bool
        or type(upload_required) is not bool
        or known is upload_required
        or upload_path != "/api/guard/runtime/extension-catalog/sync"
    ):
        raise RuntimeError("Invalid Extension catalog handshake response")
    if known:
        return {
            "extension_catalog_sync_status": "already_known",
            "extension_catalog_sync_digest": digest,
        }, None
    generated_at = session_payload.get("updatedAt")
    if not isinstance(generated_at, str) or not generated_at:
        generated_at = fallback_generated_at
    catalog = catalog_factory(generated_at)
    if catalog.get("catalogDigest") != digest:
        raise RuntimeError("Extension catalog changed during runtime synchronization")
    upload = ExtensionCatalogUpload(
        url=_normalized_extension_catalog_sync_url(runtime_sync_url, upload_path=str(upload_path)),
        body=json.dumps({"idempotencyKey": f"catalog:{digest}", "catalog": catalog}).encode("utf-8"),
    )
    return {
        "extension_catalog_sync_status": "uploaded",
        "extension_catalog_sync_digest": digest,
    }, upload


def validate_extension_catalog_sync_response(payload: object, *, expected_digest: str) -> None:
    if not isinstance(payload, dict):
        raise RuntimeError("Invalid Extension catalog sync response")
    expected_fields = {
        "schemaVersion",
        "accepted",
        "catalogDigest",
        "alreadyKnown",
        "deviceCount",
        "firstSeenAt",
        "lastSeenAt",
    }
    device_count = payload.get("deviceCount")
    if (
        set(payload) != expected_fields
        or payload.get("schemaVersion") != "guard.extension-catalog-sync.v1"
        or payload.get("accepted") is not True
        or payload.get("catalogDigest") != expected_digest
        or type(payload.get("alreadyKnown")) is not bool
        or not isinstance(device_count, int)
        or isinstance(device_count, bool)
        or device_count < 1
        or not isinstance(payload.get("firstSeenAt"), str)
        or not payload.get("firstSeenAt")
        or not isinstance(payload.get("lastSeenAt"), str)
        or not payload.get("lastSeenAt")
    ):
        raise RuntimeError("Invalid Extension catalog sync response")


def runtime_session_success_summary(
    *,
    session_payload: dict[str, object],
    response_payload: dict[str, object],
    synced_at: str,
    catalog_sync: dict[str, object],
) -> dict[str, object]:
    synced_items = response_payload.get("items")
    trusted_device_id = session_payload["deviceId"]
    if isinstance(synced_items, list):
        matching_item = next(
            (
                item
                for item in synced_items
                if isinstance(item, dict) and item.get("sessionId") == session_payload["sessionId"]
            ),
            None,
        )
        if isinstance(matching_item, dict):
            response_device_id = matching_item.get("deviceId")
            if isinstance(response_device_id, str) and response_device_id:
                trusted_device_id = response_device_id
    summary: dict[str, object] = {
        "synced_at": synced_at,
        "runtime_session_synced_at": synced_at,
        "runtime_session_id": session_payload["sessionId"],
        "runtime_sessions_visible": len(synced_items) if isinstance(synced_items, list) else 0,
        "local_guard_online_at": synced_at,
        "runtime_harness": session_payload["harness"],
        "runtime_surface": session_payload["surface"],
        "runtime_workspace": session_payload["workspace"],
        "runtime_device_id": trusted_device_id,
    }
    for field in (
        "extensionCatalogDigest",
        "extensionControlSchemaVersions",
        "extensionAuthorityRevision",
        "effectiveProjectionDigest",
        "managedControlsCapabilities",
    ):
        if field in session_payload:
            summary[field] = session_payload[field]
    summary.update(catalog_sync)
    return summary


def runtime_summary_device_id(summary: object, fallback: str) -> str:
    """Prefer the server-normalized runtime device identity when available."""

    value = summary.get("runtime_device_id") if isinstance(summary, dict) else None
    return value if isinstance(value, str) and value else fallback


def _normalized_extension_catalog_sync_url(runtime_sync_url: str, *, upload_path: str) -> str:
    if upload_path != "/api/guard/runtime/extension-catalog/sync":
        raise RuntimeError("Invalid Extension catalog upload path")
    parsed = urllib.parse.urlsplit(runtime_sync_url)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, upload_path, parsed.query, ""))
