"""Native workspace-review staging, verification, and local application."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Mapping
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol, cast

from ..native_resident_client import (
    native_resident_client_failure_code,
    native_resident_client_request,
)
from ..native_runtime import _isolated_environment, native_runtime_status
from .exact_cloud_review import EXACT_CLOUD_REVIEW_REVOCATION_STATE_KEY

_REQUEST_SCHEMA = "guard-native-workspace-review-request.v1"
_REQUEST_VERSION = 1
_REQUEST_DIRECTORY = "workspace-review-requests"
_MAX_REQUEST_ID_LENGTH = 128
_MAX_REQUEST_STATE_BYTES = 64 * 1024
_MAX_DECISION_BYTES = 16 * 1024
_NATIVE_RESIDENT_FEATURE = "resident-protocol-v2"
_NATIVE_REVIEW_FEATURE = "native-workspace-review-decision-v1"


class NativeWorkspaceReviewError(ValueError):
    """Finite error raised by the local native review bridge."""

    def __init__(self, code: str):
        self.code: str = code if code else "native_workspace_review_failed"
        super().__init__(self.code)


class NativeWorkspaceReviewStore(Protocol):
    def get_approval_request(self, request_id: str) -> dict[str, object] | None: ...

    def get_sync_payload(self, state_key: str) -> dict[str, object] | list[object] | None: ...

    def resolve_native_workspace_review_request(
        self,
        request_id: str,
        *,
        resolution_action: str,
        expected_request: Mapping[str, object],
        resolved_at: str,
        native_replayed: bool,
    ) -> dict[str, object]: ...


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise NativeWorkspaceReviewError("native_workspace_review_request_invalid") from error


def canonical_workspace_review_decision_bytes(value: object) -> bytes:
    """Return canonical bytes for the signed decision CLI boundary."""

    try:
        return _canonical_json_bytes(value)
    except NativeWorkspaceReviewError as error:
        raise NativeWorkspaceReviewError("native_workspace_review_decision_invalid") from error


def _request_id_is_safe(request_id: str) -> bool:
    return (
        isinstance(request_id, str)
        and bool(request_id)
        and len(request_id) <= _MAX_REQUEST_ID_LENGTH
        and all(char.isascii() and (char.isalnum() or char in "-_.:") for char in request_id)
    )


def _private_request_directory(guard_home: Path) -> Path:
    state_base = guard_home / "native-runtime"
    request_directory = state_base / _REQUEST_DIRECTORY
    for directory in (state_base, request_directory):
        if directory.is_symlink():
            raise NativeWorkspaceReviewError("native_workspace_review_request_invalid")
        try:
            directory.mkdir(mode=0o700, exist_ok=True)
            directory.chmod(0o700)
        except OSError as error:
            raise NativeWorkspaceReviewError("native_workspace_review_request_unavailable") from error
    return request_directory


def _json_field(request: Mapping[str, object], name: str) -> object:
    value = request.get(name)
    if not name.endswith("_json") or not isinstance(value, str):
        return value
    try:
        parsed: object = json.loads(value)
        return parsed
    except (TypeError, ValueError) as error:
        raise NativeWorkspaceReviewError("native_workspace_review_request_invalid") from error


def _request_state(request_id: str, request: Mapping[str, object]) -> dict[str, object]:
    if not _request_id_is_safe(request_id) or request.get("request_id") != request_id:
        raise NativeWorkspaceReviewError("native_workspace_review_request_invalid")
    if request.get("status") != "pending":
        raise NativeWorkspaceReviewError("native_workspace_review_request_not_pending")
    return {
        "schema": _REQUEST_SCHEMA,
        "version": _REQUEST_VERSION,
        "request_id": request_id,
        "status": "pending",
        "action": {
            "action_identity": request.get("action_identity"),
            "action_envelope": _json_field(request, "action_envelope_json"),
            "launch_target": request.get("launch_target"),
            "raw_command_text": request.get("raw_command_text"),
        },
        "intent": {
            "harness": request.get("harness"),
            "artifact_id": request.get("artifact_id"),
            "artifact_type": request.get("artifact_type"),
            "workspace": request.get("workspace"),
            "browser_intent": _json_field(request, "browser_intent_json"),
        },
        "revision": {
            "created_at": request.get("created_at"),
            "last_seen_at": request.get("last_seen_at"),
            "dedupe_count": request.get("dedupe_count"),
            "guard_version": request.get("guard_version"),
            "first_seen_guard_version": request.get("first_seen_guard_version"),
            "last_seen_guard_version": request.get("last_seen_guard_version"),
        },
        "policy": {
            "policy_action": request.get("policy_action"),
            "recommended_scope": request.get("recommended_scope"),
            "source_scope": request.get("source_scope"),
            "decision_v2": _json_field(request, "decision_v2_json"),
        },
    }


def stage_workspace_review_request(
    store: NativeWorkspaceReviewStore,
    guard_home: Path,
    request_id: str,
) -> dict[str, object]:
    """Persist a private native snapshot sourced solely from the local row."""

    request, _ = _stage_workspace_review_request(store, guard_home, request_id)
    return request


def _stage_workspace_review_request(
    store: NativeWorkspaceReviewStore,
    guard_home: Path,
    request_id: str,
) -> tuple[dict[str, object], str]:
    """Stage a request and retain the digest of the exact bytes written."""

    request = store.get_approval_request(request_id)
    if not isinstance(request, dict):
        raise NativeWorkspaceReviewError("native_workspace_review_request_missing")
    state = _request_state(request_id, request)
    encoded = _canonical_json_bytes(state)
    if not encoded or len(encoded) > _MAX_REQUEST_STATE_BYTES:
        raise NativeWorkspaceReviewError("native_workspace_review_request_invalid")
    directory = _private_request_directory(guard_home)
    path = directory / f"{request_id}.json"
    if path.is_symlink():
        raise NativeWorkspaceReviewError("native_workspace_review_request_invalid")
    temporary_path: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(prefix=".request-", dir=directory)
        temporary_path = Path(temporary_name)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_path, path)
        temporary_path = None
        directory_descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except OSError as error:
        raise NativeWorkspaceReviewError("native_workspace_review_request_unavailable") from error
    finally:
        if temporary_path is not None:
            with suppress(OSError):
                temporary_path.unlink()
    return request, hashlib.sha256(encoded).hexdigest()


def _native_response(
    *,
    guard_home: Path,
    request_id: str,
    decision: Mapping[str, object],
    request_snapshot_digest: str,
) -> dict[str, object]:
    status = native_runtime_status()
    identity = status.identity
    capabilities = status.capabilities
    features = capabilities.features if capabilities is not None else ()
    if not status.available or not status.compatible or identity is None or capabilities is None:
        raise NativeWorkspaceReviewError("native_workspace_review_unavailable")
    if _NATIVE_RESIDENT_FEATURE not in features or _NATIVE_REVIEW_FEATURE not in features:
        raise NativeWorkspaceReviewError("native_workspace_review_unsupported")
    payload = _canonical_json_bytes(
        {
            "operation": "workspace_review_decision",
            "request": {"request_id": request_id, "decision": decision},
        }
    )
    if len(payload) > _MAX_DECISION_BYTES:
        raise NativeWorkspaceReviewError("native_workspace_review_decision_invalid")
    encoded = native_resident_client_request(
        executable=identity.path,
        guard_home=guard_home,
        environment=_isolated_environment(),
        payload=payload,
        timeout_seconds=10.0,
    )
    if encoded is None:
        raise NativeWorkspaceReviewError(
            native_resident_client_failure_code() or "native_workspace_review_transport_failed"
        )
    try:
        decoded: object = json.loads(encoded.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise NativeWorkspaceReviewError("native_workspace_review_response_invalid") from error
    if not isinstance(decoded, dict):
        raise NativeWorkspaceReviewError("native_workspace_review_response_invalid")
    response = cast(dict[str, object], decoded)
    error = response.get("error")
    if isinstance(error, str) and error:
        raise NativeWorkspaceReviewError(error)
    if response.get("request_id") != request_id:
        raise NativeWorkspaceReviewError("native_workspace_review_response_invalid")
    if response.get("status") not in {"verified", "replayed"}:
        raise NativeWorkspaceReviewError("native_workspace_review_response_invalid")
    if response.get("replayed") is not (response.get("status") == "replayed"):
        raise NativeWorkspaceReviewError("native_workspace_review_response_invalid")
    if response.get("decision") not in {"allow", "deny"}:
        raise NativeWorkspaceReviewError("native_workspace_review_response_invalid")
    if response.get("request_snapshot_digest") != request_snapshot_digest:
        raise NativeWorkspaceReviewError("native_workspace_review_response_invalid")
    return response


def apply_native_workspace_review_decision(
    store: NativeWorkspaceReviewStore,
    guard_home: Path,
    request_id: str,
    decision: object,
    *,
    resolved_at: str | None = None,
) -> dict[str, object]:
    """Verify a native decision and apply it to the local approval queue.

    The resident claim is durable before SQLite application begins. A retry
    can resume the exact claim while the signed envelope is valid; after
    expiry there is deliberately no automatic recovery or signature bypass.
    """

    if store.get_sync_payload(EXACT_CLOUD_REVIEW_REVOCATION_STATE_KEY) is not None:
        raise NativeWorkspaceReviewError("native_workspace_review_cloud_review_disabled")
    request = store.get_approval_request(request_id)
    if isinstance(request, dict) and request.get("status") == "resolved":
        return {"status": "already_resolved", "resolved_request": request}
    if not isinstance(decision, Mapping):
        raise NativeWorkspaceReviewError("native_workspace_review_decision_invalid")
    expected_request, request_snapshot_digest = _stage_workspace_review_request(store, guard_home, request_id)
    response = _native_response(
        guard_home=guard_home,
        request_id=request_id,
        decision=decision,
        request_snapshot_digest=request_snapshot_digest,
    )
    action_value = response.get("decision")
    if not isinstance(action_value, str):
        raise NativeWorkspaceReviewError("native_workspace_review_response_invalid")
    action = action_value
    # The native contract calls a negative decision ``deny``. The local
    # approval queue and its existing waiters use ``block`` as the deny state.
    resolution_action = "block" if action == "deny" else action
    applied = store.resolve_native_workspace_review_request(
        request_id,
        resolution_action=resolution_action,
        expected_request=expected_request,
        resolved_at=resolved_at or datetime.now(timezone.utc).isoformat(),
        native_replayed=bool(response["replayed"]),
    )
    if applied.get("resolved") is not True:
        raise NativeWorkspaceReviewError(str(applied.get("error") or "native_workspace_review_apply_failed"))
    return {
        "status": "replayed" if response["replayed"] else "verified",
        "request_id": request_id,
        "decision": action,
        "resolution_action": resolution_action,
        "claim_id": response.get("claim_id"),
        "envelope_digest": response.get("envelope_digest"),
        "native_receipt": response,
        "native_replayed": bool(response["replayed"]),
        "application_replayed": bool(applied.get("replayed")),
        "resolved_request": applied.get("resolved_request"),
    }


__all__ = [
    "NativeWorkspaceReviewError",
    "apply_native_workspace_review_decision",
    "canonical_workspace_review_decision_bytes",
    "stage_workspace_review_request",
]
