"""Extension catalog negotiation for a runtime session.

The resident owns every verdict: which summary the session reports, whether the
catalog is uploaded, where, and whether the acknowledgement binds it. This module
only observes what the verdict asks for (it builds the catalog and measures its
bytes) and carries the answer back.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from .extension_catalog_sync import (
    ExtensionCatalogLimitError,
    ExtensionCatalogUnavailableError,
    native_wire_call,
)

# The one summary only Python can name: the resident that judges the negotiation
# could not be reached. Tests pin it to the resident's own wording.
_CATALOG_RUNTIME_UNAVAILABLE: dict[str, object] = {
    "managedControlsCapabilities": [],
    "extension_catalog_sync_status": "downgraded",
    "extension_catalog_sync_reason": "catalog_runtime_unavailable",
}
# Session fields that advertise a catalog posture. A session carrying none of
# them has nothing to negotiate, so no resident round trip is spent on it.
_POSTURE_FIELDS = ("extensionCatalogDigest", "extensionCatalogViewDigest", "managedControlsCapabilities")
# Session fields the verdict reads. Nothing else crosses to the resident.
_SESSION_FIELDS = (*_POSTURE_FIELDS, "updatedAt")
_MALFORMED = "Native Extension catalog answer is malformed"
_INVALID_ACK = "Invalid Extension catalog sync response"


@dataclass(frozen=True)
class ExtensionCatalogUpload:
    url: str
    body: bytes


def prepare_extension_catalog_handshake(
    *,
    guard_home: Path | None,
    runtime_sync_url: str,
    runtime_response: dict[str, object],
    session_payload: dict[str, object],
    catalog_factory: Callable[[str], Mapping[str, object]],
    fallback_generated_at: str,
) -> tuple[dict[str, object], ExtensionCatalogUpload | None]:
    """Ask the resident to judge Cloud negotiation and prepare a digest-bound upload."""

    if not any(field in session_payload for field in _POSTURE_FIELDS):
        return {}, None
    request: dict[str, object] = {
        "session": {field: session_payload[field] for field in _SESSION_FIELDS if field in session_payload},
        "handshake": runtime_response.get("extensionCatalogSync"),
        "runtime_sync_url": runtime_sync_url,
        "fallback_generated_at": fallback_generated_at,
    }
    answer = _negotiate(guard_home, request)
    body: bytes | None = None
    if answer is not None and answer.get("decision") == "need_catalog":
        observation, body = _observe(catalog_factory, answer)
        answer = _negotiate(guard_home, {**request, "catalog": observation})
    if answer is None:
        return dict(_CATALOG_RUNTIME_UNAVAILABLE), None
    summary = answer.get("summary")
    url = answer.get("upload_url")
    if answer.get("decision") != "done" or not isinstance(summary, dict):
        raise RuntimeError(_MALFORMED)
    if url is None:
        return summary, None
    if not isinstance(url, str) or body is None:
        raise RuntimeError(_MALFORMED)
    return summary, ExtensionCatalogUpload(url=url, body=body)


def _negotiate(guard_home: Path | None, request: dict[str, object]) -> dict[str, object] | None:
    try:
        return native_wire_call("v1_handshake", guard_home=guard_home, **request)
    except ExtensionCatalogUnavailableError:
        return None
    except ExtensionCatalogLimitError as error:
        raise RuntimeError("Invalid Extension catalog handshake response") from error


def _observe(
    catalog_factory: Callable[[str], Mapping[str, object]], ask: dict[str, object]
) -> tuple[dict[str, object], bytes | None]:
    """Build the catalog the resident asked for and report how it went and how big it is."""

    generated_at = ask.get("generated_at")
    purpose = ask.get("purpose")
    key = ask.get("idempotency_key")
    if not isinstance(generated_at, str) or purpose not in ("probe", "upload"):
        raise RuntimeError(_MALFORMED)
    try:
        catalog = catalog_factory(generated_at)
    except ExtensionCatalogLimitError:
        return {"outcome": "limit"}, None
    except ExtensionCatalogUnavailableError:
        return {"outcome": "unavailable"}, None
    except (TypeError, ValueError):
        # Only a probe tolerates other build failures; a requested upload raises them.
        if purpose != "probe":
            raise
        return {"outcome": "failed"}, None
    if purpose == "probe":
        return {"outcome": "built"}, None
    if not isinstance(key, str):
        raise RuntimeError(_MALFORMED)
    body = _compact_json({"idempotencyKey": key, "catalog": catalog})
    return {
        "outcome": "built",
        "catalog_digest": catalog.get("catalogDigest"),
        "catalog_bytes": len(_compact_json(catalog)),
        "body_bytes": len(body),
    }, body


def validate_extension_catalog_sync_response(
    payload: object, *, expected_digest: str, guard_home: Path | None
) -> dict[str, object] | None:
    """Fail closed unless the resident accepts the acknowledgement for this digest.

    Returns None once accepted. When the resident cannot be reached the acknowledgement
    stays unverified, so the session reports the same unavailable downgrade as the
    handshake instead of claiming an upload it could not check.
    """

    try:
        verdict = native_wire_call(
            "v1_sync_ack", guard_home=guard_home, response=payload, expected_digest=expected_digest
        )
    except ExtensionCatalogUnavailableError:
        return dict(_CATALOG_RUNTIME_UNAVAILABLE)
    except ValueError as error:
        # An acknowledgement the wire cannot carry (a non-finite number, an oversize body)
        # is as invalid as one the resident refuses.
        raise RuntimeError(_INVALID_ACK) from error
    if verdict.get("accepted") is not True:
        raise RuntimeError(_INVALID_ACK)
    return None


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
        "extensionCatalogViewDigest",
        "extensionCatalogEnforcementDigest",
        "extensionCatalogGeneratedAt",
        "extensionControlSchemaVersions",
        "extensionAuthorityRevision",
        "managedExtensionAuthorityRevision",
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


def _compact_json(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
