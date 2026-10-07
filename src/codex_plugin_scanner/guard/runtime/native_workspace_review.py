"""Native workspace-review staging, verification, and local application."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import tempfile
from collections.abc import Mapping
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol, cast

from .. import native_policy_snapshot as _native_policy_snapshot
from ..durable_io import fsync_directory
from ..native_resident_client import (
    native_resident_client_failure_code,
    native_resident_client_request,
)
from ..native_runtime import _isolated_environment, native_runtime_status
from ..store_native_workspace_review import NATIVE_WORKSPACE_REVIEW_RECEIPT_STATE_PREFIX
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
        native_receipt: Mapping[str, object] | None = None,
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
    if os.name == "nt":
        try:
            for directory in (guard_home, state_base, request_directory):
                _native_policy_snapshot._windows_ensure_private_directory(directory)
        except (OSError, RuntimeError, TypeError, ValueError) as error:
            raise NativeWorkspaceReviewError("native_workspace_review_request_unavailable") from error
        return request_directory
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


def _compatible_uploaded_snapshot(
    request_id: str,
    current: Mapping[str, object],
    uploaded: Mapping[str, object],
) -> bool:
    """Accept a frozen upload only when local scope projection narrowed it."""

    try:
        current_state = _request_state(request_id, current)
        uploaded_state = _request_state(request_id, uploaded)
    except NativeWorkspaceReviewError:
        return False
    if any(current_state[field] != uploaded_state[field] for field in ("action", "intent", "revision")):
        return False
    current_policy = current_state["policy"]
    uploaded_policy = uploaded_state["policy"]
    if not isinstance(current_policy, dict) or not isinstance(uploaded_policy, dict):
        return False
    current_decision_value = current_policy.get("decision_v2")
    uploaded_decision_value = uploaded_policy.get("decision_v2")
    if not isinstance(current_decision_value, dict) or not isinstance(uploaded_decision_value, dict):
        return current_policy == uploaded_policy
    current_decision = cast(dict[str, object], current_decision_value)
    uploaded_decision = cast(dict[str, object], uploaded_decision_value)
    if set(current_decision) != set(uploaded_decision):
        return False
    current_scopes = current_decision.get("approval_scopes")
    uploaded_scopes = uploaded_decision.get("approval_scopes")
    if not isinstance(current_scopes, list) or not isinstance(uploaded_scopes, list):
        return current_policy == uploaded_policy
    current_scopes = cast(list[object], current_scopes)
    uploaded_scopes = cast(list[object], uploaded_scopes)
    narrowed = [scope for scope in uploaded_scopes if scope in current_scopes]
    if narrowed != current_scopes:
        return False
    return {
        **current_policy,
        "decision_v2": {**current_decision, "approval_scopes": uploaded_scopes},
    } == uploaded_policy


def matching_workspace_review_snapshot(
    store: NativeWorkspaceReviewStore,
    guard_home: Path,
    request_id: str,
    decision: Mapping[str, object],
    current: Mapping[str, object],
) -> dict[str, object]:
    """Find the immutable upload bound to this decision without widening it."""

    list_snapshots = getattr(store, "list_review_event_snapshots", None)
    if not callable(list_snapshots):
        return dict(current)
    from .native_workspace_review_context import build_native_workspace_review_context

    snapshots: object = list_snapshots(request_id)
    if not isinstance(snapshots, list):
        raise NativeWorkspaceReviewError("native_workspace_review_request_invalid")
    bindings = (
        "request_binding",
        "action_binding",
        "intent_binding",
        "revision_binding",
        "policy_binding",
        "retry_scope_binding",
    )
    seen_states: set[bytes] = set()
    for candidate_value in (current, *cast(list[object], snapshots)):
        if not isinstance(candidate_value, Mapping):
            continue
        candidate = cast(Mapping[str, object], candidate_value)
        if not _compatible_uploaded_snapshot(request_id, current, candidate):
            continue
        encoded = _canonical_json_bytes(_request_state(request_id, candidate))
        if encoded in seen_states:
            continue
        seen_states.add(encoded)
        context = build_native_workspace_review_context(store, guard_home, request_id, candidate)
        if context is not None and all(context.get(field) == decision.get(field) for field in bindings):
            return dict(candidate)
    raise NativeWorkspaceReviewError("native_workspace_review_decision_binding_mismatch")


def stage_workspace_review_request(
    store: NativeWorkspaceReviewStore,
    guard_home: Path,
    request_id: str,
    request_snapshot: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Persist a private native snapshot from a frozen row or the local row."""

    request, _ = _stage_workspace_review_request(store, guard_home, request_id, request_snapshot=request_snapshot)
    return request


def _stage_workspace_review_request(
    store: NativeWorkspaceReviewStore,
    guard_home: Path,
    request_id: str,
    *,
    request_snapshot: Mapping[str, object] | None = None,
) -> tuple[dict[str, object], str]:
    """Stage a request and retain the digest of the exact bytes written."""

    request = dict(request_snapshot) if request_snapshot is not None else store.get_approval_request(request_id)
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
        if os.name == "nt":
            temporary_name = f".request-{secrets.token_hex(16)}.tmp"
            with _native_policy_snapshot._windows_private_directory_binding(directory) as binding:
                _native_policy_snapshot._windows_write_private_file_atomic(
                    parent_path=binding.path,
                    parent_handle=binding.handle,
                    directory_handles=binding.handles,
                    temporary_name=temporary_name,
                    destination_name=path.name,
                    payload=encoded,
                    maximum_bytes=_MAX_REQUEST_STATE_BYTES,
                    kind="workspace_review_request",
                )
        else:
            descriptor, temporary_name = tempfile.mkstemp(prefix=".request-", dir=directory)
            temporary_path = Path(temporary_name)
            fchmod = getattr(os, "fchmod", None)
            if fchmod is not None:
                fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                output.write(encoded)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary_path, path)
            temporary_path = None
            os.chmod(path, 0o600)
            fsync_directory(directory)
    except (OSError, RuntimeError, TypeError, ValueError) as error:
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
    can resume the same decision using a fresh signed envelope. Expired proof
    is never extended locally or accepted without native verification.
    """

    if store.get_sync_payload(EXACT_CLOUD_REVIEW_REVOCATION_STATE_KEY) is not None:
        raise NativeWorkspaceReviewError("native_workspace_review_cloud_review_disabled")
    if not isinstance(decision, Mapping):
        raise NativeWorkspaceReviewError("native_workspace_review_decision_invalid")
    request = store.get_approval_request(request_id)
    if isinstance(request, dict) and request.get("status") == "resolved":
        return _reverify_resolved_decision(store, guard_home, request_id, request, decision, resolved_at=resolved_at)
    if not isinstance(request, dict):
        raise NativeWorkspaceReviewError("native_workspace_review_request_missing")
    snapshot = matching_workspace_review_snapshot(store, guard_home, request_id, decision, request)
    _, request_snapshot_digest = _stage_workspace_review_request(
        store, guard_home, request_id, request_snapshot=snapshot
    )
    expected_request = request
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
        native_receipt=response,
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


def _reverify_resolved_decision(
    store: NativeWorkspaceReviewStore,
    guard_home: Path,
    request_id: str,
    request: Mapping[str, object],
    decision: Mapping[str, object],
    *,
    resolved_at: str | None,
) -> dict[str, object]:
    previous = store.get_sync_payload(NATIVE_WORKSPACE_REVIEW_RECEIPT_STATE_PREFIX + request_id)
    if not isinstance(previous, dict) or previous.get("request_id") != request_id:
        raise NativeWorkspaceReviewError("native_workspace_review_request_resolved")
    snapshot_digest = previous.get("request_snapshot_digest")
    if not isinstance(snapshot_digest, str) or len(snapshot_digest) != 64:
        raise NativeWorkspaceReviewError("native_workspace_review_receipt_invalid")
    # Do not rewrite a resolved row into a new pending snapshot. Revalidate
    # against the original native snapshot and its durably consumed claim.
    response = _native_response(
        guard_home=guard_home,
        request_id=request_id,
        decision=decision,
        request_snapshot_digest=snapshot_digest,
    )
    if response.get("replayed") is not True:
        raise NativeWorkspaceReviewError("native_workspace_review_decision_replay")
    resolution_action = "block" if response.get("decision") == "deny" else "allow"
    applied = store.resolve_native_workspace_review_request(
        request_id,
        resolution_action=resolution_action,
        expected_request=request,
        resolved_at=resolved_at or datetime.now(timezone.utc).isoformat(),
        native_replayed=True,
        native_receipt=response,
    )
    if applied.get("resolved") is not True:
        raise NativeWorkspaceReviewError(str(applied.get("error") or "native_workspace_review_apply_failed"))
    return {
        "status": "already_resolved",
        "request_id": request_id,
        "decision": response.get("decision"),
        "resolution_action": resolution_action,
        "claim_id": response.get("claim_id"),
        "envelope_digest": response.get("envelope_digest"),
        "native_receipt": response,
        "native_replayed": True,
        "application_replayed": True,
        "resolved_request": applied.get("resolved_request"),
    }


__all__ = [
    "NativeWorkspaceReviewError",
    "apply_native_workspace_review_decision",
    "canonical_workspace_review_decision_bytes",
    "stage_workspace_review_request",
]
