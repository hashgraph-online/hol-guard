"""Enqueue memory decision events into the local cloud outbox.

Local Guard approvals and denials previously lived only in local SQLite. This
module is the missing seam that turns a resolved approval request into a
``guard.memory-decision.v1`` event in the existing ``guard_cloud_events``
outbox, so the decision can reach HOL Guard Cloud and become a Suggested Memory
candidate.

Everything here is defensive: if cloud pairing is absent, the store lacks the
outbox, or the request has no command/artifact signal, the enqueue is a no-op.
Local approvals must never fail because the cloud candidate pipeline is not
ready.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Mapping
from dataclasses import replace
from typing import TYPE_CHECKING, Any

from .edge_events import build_memory_decision_event_envelope
from .memory_decision_event import (
    MemoryDecisionSource,
    build_memory_decision_event,
    event_to_cloud_payload,
)
from .receipts.manager import build_receipt

if TYPE_CHECKING:
    from .store import GuardStore

NATIVE_MEMORY_SOURCE_BINDING_FIELD = "native_memory_source_binding"

_LOGGER = logging.getLogger(__name__)


def enqueue_memory_decision_event(
    store: Any,
    *,
    request: Mapping[str, object],
    action: str,
    scope: str,
    resolved_at: str,
    source: MemoryDecisionSource = "local_approval_center",
) -> bool:
    """Build and enqueue a memory decision event. Returns True if enqueued.

    ``store`` is a ``GuardStore`` but typed as ``Any`` here to avoid an import
    cycle (GuardStore imports this module's callers). Returns False on any
    non-fatal miss (no cloud pairing, no usable signal, outbox unavailable).
    """
    try:
        workspace_id = _resolve_workspace_id(store)
        device_id, machine_installation_id = _resolve_device_metadata(store)
        owner_user_id = _resolve_owner_user_id(store)
        machine_id = _resolve_oauth_machine_id(store) or device_id
        redaction_enabled = _resolve_redaction_enabled(store)

        enriched_request = _request_with_project_identity(store, request)
        event = build_memory_decision_event(
            request=enriched_request,
            action=action,
            scope=scope,
            resolved_at=resolved_at,
            owner_user_id=owner_user_id,
            workspace_id=workspace_id,
            device_id=device_id,
            machine_id=machine_id,
            machine_installation_id=machine_installation_id,
            source=source,
            redaction_enabled=redaction_enabled,
        )
        if event is None:
            return False
        source_receipt_id = _ensure_source_receipt_id(
            store,
            enriched_request,
            decision_action=event.decision_action,
            scope=scope,
        )
        if source_receipt_id is None:
            return False
        event = replace(event, source_receipt_id=source_receipt_id)

        envelope = build_memory_decision_event_envelope(
            request_id=event.request_id,
            decision_action=event.decision_action,
            occurred_at=event.occurred_at,
            payload=event_to_cloud_payload(event),
            device_id=device_id,
            workspace_id=workspace_id,
        )
        add_guard_event_v1 = getattr(store, "add_guard_event_v1", None)
        if add_guard_event_v1 is None:
            return False
        add_guard_event_v1(envelope)
        return True
    except Exception as error:
        _LOGGER.debug("memory decision event enqueue skipped: %s", error)
        return False


def _resolve_workspace_id(store: Any) -> str | None:
    getter = getattr(store, "get_cloud_workspace_id", None)
    if callable(getter):
        try:
            value = getter()
        except Exception:
            return None
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _resolve_device_metadata(store: Any) -> tuple[str | None, str | None]:
    getter = getattr(store, "get_device_metadata", None)
    if not callable(getter):
        return None, None
    try:
        metadata = getter()
    except Exception:
        return None, None
    if not isinstance(metadata, Mapping):
        return None, None
    installation_id = metadata.get("installation_id")
    device_id = installation_id if isinstance(installation_id, str) and installation_id.strip() else None
    return device_id, None


def _resolve_owner_user_id(store: Any) -> str | None:
    credentials = _oauth_credentials(store)
    if not credentials:
        return None
    for key in ("user_id", "owner_user_id", "userId", "ownerUserId"):
        value = credentials.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _ensure_source_receipt_id(
    store: Any,
    request: Mapping[str, object],
    *,
    decision_action: str,
    scope: str,
) -> str | None:
    for key in ("source_receipt_id", "sourceReceiptId", "receipt_id", "receiptId"):
        value = request.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()

    request_id = _request_string(request, "request_id")
    if request_id is None:
        return None
    policy_decision = {
        "approved": "allow",
        "blocked": "block",
        "dismissed_keep_asking": "require-reapproval",
    }.get(decision_action)
    if policy_decision is None:
        return None

    getter = getattr(store, "get_receipt_for_approval_request", None)
    if callable(getter):
        try:
            receipt = getter(request_id, policy_decision=policy_decision)
        except Exception:
            receipt = None
        receipt_id = _receipt_id(receipt)
        if receipt_id is not None:
            return receipt_id

    add_receipt = getattr(store, "add_receipt", None)
    if not callable(add_receipt):
        return None
    raw_value = request.get("raw_command_text")
    raw_command = (
        raw_value if isinstance(raw_value, str) and raw_value.strip() else _request_string(request, "review_command")
    )
    artifact_id = _request_string(request, "artifact_id") or f"approval-request:{request_id}"
    artifact_identity = raw_command or artifact_id
    artifact_hash = _request_string(request, "artifact_hash") or (
        "sha256:" + hashlib.sha256(artifact_identity.encode()).hexdigest()
    )
    receipt = build_receipt(
        harness=_request_string(request, "harness") or "guard",
        artifact_id=artifact_id,
        artifact_hash=artifact_hash,
        policy_decision=policy_decision,
        capabilities_summary=_request_string(request, "capabilities_summary") or "approval decision",
        changed_capabilities=[],
        provenance_summary="Guard approval decision",
        artifact_name=_request_string(request, "artifact_name"),
        source_scope=scope,
        approval_source="memory_decision",
        approval_request_id=request_id,
        raw_command_text=raw_command,
    )
    deterministic_receipt_id = (
        "guard-receipt-memory-" + hashlib.sha256(f"{request_id}:{policy_decision}".encode()).hexdigest()[:32]
    )
    receipt = replace(receipt, receipt_id=deterministic_receipt_id)
    add_receipt(receipt)
    _LOGGER.info(
        "Created durable receipt for memory decision",
        extra={"decision_action": decision_action, "scope": scope},
    )
    return receipt.receipt_id


def native_memory_source_binding(store: GuardStore) -> dict[str, object] | None:
    """Current source-disclosure authority, separate from a retained decision."""

    from .config import load_guard_config
    from .native_cloud_review_consent import native_cloud_review_consent
    from .review_oauth_binding import guard_review_oauth_metadata
    from .runtime.command_capability import command_capability_status
    from .runtime.exact_cloud_review import exact_cloud_review_status

    try:
        if load_guard_config(store.guard_home, create_home=False).receipt_redaction_level != "none":
            return None
        capability = command_capability_status(store)
        operations = capability.get("operations")
        if (
            capability["enabled"] is not True
            or capability["capability_valid"] is not True
            or not isinstance(operations, list)
            or "guard.review.syncPolicyMemory" not in operations
        ):
            return None
        if exact_cloud_review_status(store).get("enabled") is not True:
            return None
        consent = native_cloud_review_consent(store.guard_home, "read")
        oauth = guard_review_oauth_metadata(store, require_device_dpop_binding=True)
        if consent["status"] != "enabled" or oauth.grant_id is None:
            return None
    except (OSError, RuntimeError, TypeError, ValueError):
        return None
    return {
        "schema": "guard.policy-memory-source-binding.v1",
        "workspace_id": oauth.workspace_id,
        "machine_id": oauth.machine_id,
        "local_installation_id": oauth.installation_id,
        "device_id": oauth.device_id,
        "grant_id": oauth.grant_id,
        "dpop_thumbprint": oauth.dpop_thumbprint,
        "consent_revision": consent["revision"],
        "revocation_epoch": consent["revocation_epoch"],
    }


def policy_memory_source_for_receipt(
    store: GuardStore,
    receipt: Mapping[str, object],
    *,
    redaction_level: str,
    access_token: str | None,
) -> dict[str, object] | None:
    """Disclose only an explicitly retained, native-bound workspace decision.

    Called again at each actual send, including backlog and OAuth/DPoP retries.
    Neither an ordinary allow-once nor a copied display string is source proof.
    """

    from .runtime.native_cloud_review_origin import frozen_native_approval_origin
    from .runtime.native_cloud_review_v4 import get_native_approval_origin

    if (
        redaction_level != "none"
        or receipt.get("approval_source") != "memory_decision"
        or receipt.get("source_scope") != "workspace"
    ):
        return None
    request_id = receipt.get("approval_request_id")
    command = receipt.get("raw_command_text")
    if not isinstance(request_id, str) or not isinstance(command, str) or not command:
        return None
    try:
        command_bytes = command.encode("utf-8")
    except UnicodeError:
        return None
    if len(command.encode("utf-16-le")) > 16_384 or "\0" in command or not command.strip():
        return None
    artifact_id = receipt.get("artifact_id")
    harness = receipt.get("harness")
    if (
        not isinstance(artifact_id, str)
        or not 1 <= len(artifact_id) <= 512
        or not isinstance(harness, str)
        or not 1 <= len(harness) <= 128
    ):
        return None
    binding = native_memory_source_binding(store)
    credentials = store.get_oauth_local_credentials(allow_primary=False)
    if (
        binding is None
        or not isinstance(credentials, dict)
        or credentials.get("token_type") != "DPoP"
        or not isinstance(access_token, str)
        or credentials.get("access_token") != access_token
    ):
        return None
    try:
        request = store.get_approval_request(request_id)
        if (
            not isinstance(request, dict)
            or request.get("status") != "resolved"
            or request.get("resolution_action") not in {"allow", "block"}
            or request.get("resolution_scope") != "workspace"
            or request.get("raw_command_text") != command
            or request.get("artifact_id") != artifact_id
            or request.get("harness") != harness
        ):
            return None
        frozen_origin = frozen_native_approval_origin(request)
        command_digest = hashlib.sha256(command_bytes).hexdigest()
        if frozen_origin is None or frozen_origin.get("command_sha256") != command_digest:
            return None
        if (
            frozen_origin.get("consent_revision") != binding["consent_revision"]
            or frozen_origin.get("revocation_epoch") != binding["revocation_epoch"]
        ):
            return None
        # Only authenticated immutable snapshots can carry the captured target.
        # A pruned/tombstoned/rebound snapshot has no disclosure fallback.
        snapshots = store.list_review_event_snapshots(request_id)
        matches = False
        for snapshot in snapshots:
            if (
                snapshot.get("raw_command_text") != command
                or snapshot.get("artifact_id") != artifact_id
                or snapshot.get("harness") != harness
                or frozen_native_approval_origin(snapshot) != frozen_origin
            ):
                continue
            envelope = snapshot.get("action_envelope_json")
            if isinstance(envelope, str):
                envelope = json.loads(envelope)
            if isinstance(envelope, dict) and envelope.get(NATIVE_MEMORY_SOURCE_BINDING_FIELD) == binding:
                matches = True
                break
        if not matches:
            return None
        current_origin = get_native_approval_origin(store.guard_home, request_id)
        if current_origin != frozen_origin:
            return None
    except (OSError, RuntimeError, TypeError, ValueError):
        return None
    return {
        "contractVersion": "guard.policy-memory-source.v1",
        "artifactId": artifact_id,
        "commandText": command,
        "harnessId": harness,
        "complete": True,
        "redaction": "none",
        "installationId": binding["machine_id"],
        "localRequestId": request_id,
        "workspaceId": binding["workspace_id"],
    }


def _request_string(request: Mapping[str, object], *keys: str) -> str | None:
    for key in keys:
        value = request.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _receipt_id(receipt: object) -> str | None:
    if not isinstance(receipt, Mapping):
        return None
    value = receipt.get("receipt_id")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _resolve_oauth_machine_id(store: Any) -> str | None:
    """Return the OAuth grant's machine id, distinct from the installation id.

    The installation id (from device metadata) and the OAuth machine id can
    differ; the OAuth credential payload carries the real machine id seeded at
    connect time. Falls back to None so callers can default to the installation
    id.
    """
    credentials = _oauth_credentials(store)
    if not credentials:
        return None
    value = credentials.get("machine_id")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _resolve_redaction_enabled(store: Any) -> bool:
    config_getter = getattr(store, "get_sync_payload", None)
    if not callable(config_getter):
        return False
    try:
        payload = config_getter("guard_redaction_policy")
    except Exception:
        return False
    if isinstance(payload, Mapping):
        value = payload.get("command_redaction_enabled")
        if isinstance(value, bool):
            return value
    return False


def _request_with_project_identity(
    store: Any,
    request: Mapping[str, object],
) -> Mapping[str, object]:
    request_id = request.get("request_id")
    if not isinstance(request_id, str) or not request_id.strip():
        return request
    getter = getattr(store, "get_guard_operation_for_approval_request", None)
    if not callable(getter):
        return request
    try:
        operation = getter(request_id.strip())
    except Exception:
        return request
    if not isinstance(operation, Mapping):
        return request
    metadata = operation.get("metadata")
    if not isinstance(metadata, Mapping):
        return request
    additions: dict[str, object] = {}
    for key in ("project_id", "projectId", "workspace_path", "workspacePath"):
        value = metadata.get(key)
        if isinstance(value, str) and value.strip() and key not in request:
            additions[key] = value.strip()
    if not additions:
        return request
    return {**dict(request), **additions}


def _oauth_credentials(store: Any) -> Mapping[str, object] | None:
    getter = getattr(store, "get_oauth_local_credentials", None)
    if not callable(getter):
        return None
    try:
        credentials = getter()
    except Exception:
        return None
    if isinstance(credentials, Mapping):
        return credentials
    return None
