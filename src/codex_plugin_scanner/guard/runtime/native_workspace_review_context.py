"""Stage and obtain verified native review context for background Cloud upload."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

from ..native_resident_client import native_resident_client_request
from ..native_runtime import _isolated_environment, native_runtime_status
from .native_workspace_review import (
    NativeWorkspaceReviewError,
    NativeWorkspaceReviewStore,
    _canonical_json_bytes,
    stage_workspace_review_request,
)

_CONTEXT_SCHEMA = "guard-native-workspace-review-context.v1"
_CONTEXT_VERSION = 1
_AUTHORITY_SCHEMA = "guard-native-workspace-review-authority.v1"
_AUTHORITY_VERSION = 1
_AUTHORITY_PURPOSE = "cloud_review_team_delegation"
_AUTHORITY_KEY_ALGORITHM = "ed25519"
_AUTHORITY_SCOPE_VERSION = "guard-native-workspace-review-scope.v1"
_NATIVE_RESIDENT_FEATURE = "resident-protocol-v2"
_NATIVE_CONTEXT_FEATURE = "native-workspace-review-context-v1"
NATIVE_CONTEXT_PROBE_LIMIT = 2
NATIVE_CONTEXT_TIMEOUT_SECONDS = 2.0
_DIGEST_FIELDS = (
    "authority_record_digest",
    "workspace_binding",
    "device_binding",
    "installation_binding",
    "scope_binding",
    "request_snapshot_digest",
    "request_binding",
    "action_binding",
    "intent_binding",
    "revision_binding",
    "policy_binding",
    "retry_scope_binding",
)
_AUTHORITY_FIELDS = {
    "schema",
    "version",
    "purpose",
    "key_algorithm",
    "key_id",
    "public_key",
    "workspace_binding",
    "device_binding",
    "installation_binding",
    "enrollment_generation",
    "previous_key_id",
    "scope_contract_version",
    "scope_binding",
    "issued_at_ms",
    "expires_at_ms",
    "status",
    "enrollment_signature",
}
_CONTEXT_FIELDS = {
    "schema",
    "version",
    "request_id",
    "authority_record",
    "authority_record_digest",
    "authority_generation",
    "authority_key_id",
    "workspace_binding",
    "device_binding",
    "installation_binding",
    "scope_binding",
    "request_snapshot_digest",
    "request_binding",
    "action_binding",
    "intent_binding",
    "revision_binding",
    "policy_binding",
    "retry_scope_binding",
}


@dataclass
class NativeWorkspaceReviewContextProbeState:
    """Bound native context probes and reuse exact immutable snapshots."""

    cache: dict[str, dict[str, object] | None] = field(default_factory=dict)
    remaining: int = NATIVE_CONTEXT_PROBE_LIMIT


def native_workspace_review_context_cache_key(
    request_id: str,
    request_snapshot: Mapping[str, object],
) -> str | None:
    try:
        encoded = json.dumps(
            request_snapshot,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError):
        return None
    return f"{request_id}:{hashlib.sha256(encoded).hexdigest()}"


def _hex(value: object, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and all(char in "0123456789abcdef" for char in value)


def _digest(value: object) -> bool:
    return _hex(value, 64)


def _valid_response(value: object, request_id: str) -> dict[str, object] | None:
    if not isinstance(value, dict) or set(value) != _CONTEXT_FIELDS:
        return None
    response = cast(dict[str, object], value)
    if response["schema"] != _CONTEXT_SCHEMA or response["version"] != _CONTEXT_VERSION:
        return None
    if response["request_id"] != request_id:
        return None
    if not all(_digest(response[field]) for field in _DIGEST_FIELDS):
        return None
    authority = response["authority_record"]
    if not isinstance(authority, dict) or set(authority) != _AUTHORITY_FIELDS:
        return None
    generation = authority.get("enrollment_generation")
    issued_at_ms = authority.get("issued_at_ms")
    expires_at_ms = authority.get("expires_at_ms")
    if (
        authority.get("schema") != _AUTHORITY_SCHEMA
        or authority.get("version") != _AUTHORITY_VERSION
        or authority.get("purpose") != _AUTHORITY_PURPOSE
        or authority.get("key_algorithm") != _AUTHORITY_KEY_ALGORITHM
        or authority.get("scope_contract_version") != _AUTHORITY_SCOPE_VERSION
        or authority.get("status") != "active"
        or not isinstance(generation, int)
        or isinstance(generation, bool)
        or not isinstance(issued_at_ms, int)
        or isinstance(issued_at_ms, bool)
        or not isinstance(expires_at_ms, int)
        or isinstance(expires_at_ms, bool)
        or (authority.get("previous_key_id") is not None and not _digest(authority.get("previous_key_id")))
    ):
        return None
    if not _digest(response["authority_record_digest"]):
        return None
    if response["authority_generation"] != authority.get("enrollment_generation"):
        return None
    if response["authority_key_id"] != authority.get("key_id"):
        return None
    for response_field, authority_field in (
        ("workspace_binding", "workspace_binding"),
        ("device_binding", "device_binding"),
        ("installation_binding", "installation_binding"),
        ("scope_binding", "scope_binding"),
    ):
        if response[response_field] != authority.get(authority_field):
            return None
    if not all(
        _digest(authority.get(field))
        for field in (
            "key_id",
            "public_key",
            "workspace_binding",
            "device_binding",
            "installation_binding",
            "scope_binding",
        )
    ) or not _hex(authority.get("enrollment_signature"), 128):
        return None
    if (
        generation <= 0
        or expires_at_ms <= issued_at_ms
        or authority["device_binding"] == authority["installation_binding"]
        or authority.get("previous_key_id") == authority["key_id"]
    ):
        return None
    return response


def build_native_workspace_review_context(
    store: NativeWorkspaceReviewStore,
    guard_home: Path,
    request_id: str,
    request_snapshot: Mapping[str, object] | None = None,
) -> dict[str, object] | None:
    """Return verified context, or omit native metadata on any local gap.

    This helper is called by the Cloud Review sync projection only. It is
    intentionally fail-closed for optional metadata: legacy event upload
    remains available when the native runtime or authority is unavailable.
    """

    try:
        status = native_runtime_status()
        identity = status.identity
        capabilities = status.capabilities
        features = capabilities.features if capabilities is not None else ()
        if (
            not status.available
            or not status.compatible
            or identity is None
            or capabilities is None
            or _NATIVE_RESIDENT_FEATURE not in features
            or _NATIVE_CONTEXT_FEATURE not in features
        ):
            return None
        stage_workspace_review_request(store, guard_home, request_id, request_snapshot)
        payload = _canonical_json_bytes(
            {
                "operation": "workspace_review_context",
                "request": {"request_id": request_id},
            }
        )
        encoded = native_resident_client_request(
            executable=identity.path,
            guard_home=guard_home,
            environment=_isolated_environment(),
            payload=payload,
            timeout_seconds=NATIVE_CONTEXT_TIMEOUT_SECONDS,
        )
        if encoded is None:
            return None
        response = json.loads(encoded.decode("utf-8"))
        if isinstance(response, dict) and isinstance(response.get("error"), str):
            return None
        return _valid_response(response, request_id)
    except (NativeWorkspaceReviewError, UnicodeDecodeError, ValueError, TypeError, OSError):
        return None


def probe_native_workspace_review_context(
    store: NativeWorkspaceReviewStore,
    guard_home: Path,
    request_id: str,
    request_snapshot: Mapping[str, object] | None = None,
    probe_state: NativeWorkspaceReviewContextProbeState | None = None,
) -> dict[str, object] | None:
    if probe_state is None:
        if request_snapshot is None:
            return build_native_workspace_review_context(store, guard_home, request_id)
        return build_native_workspace_review_context(store, guard_home, request_id, request_snapshot)
    cache_key = (
        native_workspace_review_context_cache_key(request_id, request_snapshot)
        if request_snapshot is not None
        else None
    )
    if cache_key is not None and cache_key in probe_state.cache:
        return probe_state.cache[cache_key]
    if probe_state.remaining <= 0:
        return None
    probe_state.remaining -= 1
    context = (
        build_native_workspace_review_context(store, guard_home, request_id)
        if request_snapshot is None
        else build_native_workspace_review_context(store, guard_home, request_id, request_snapshot)
    )
    if cache_key is not None:
        probe_state.cache[cache_key] = context
    return context


__all__ = [
    "NATIVE_CONTEXT_PROBE_LIMIT",
    "NATIVE_CONTEXT_TIMEOUT_SECONDS",
    "NativeWorkspaceReviewContextProbeState",
    "build_native_workspace_review_context",
    "native_workspace_review_context_cache_key",
    "probe_native_workspace_review_context",
]
