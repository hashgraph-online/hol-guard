"""Revalidate a native Codex browser approval while retaining its control fence."""

from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from ..codex_live_decision import (
    complete_codex_live_decision,
    resolve_codex_consumed_allow_authority,
    resolve_codex_live_allow_authority,
)
from ..codex_live_hook_target import codex_live_hook_wait_deadline
from ..live_process_identity import CODEX_BROWSER_WAIT_PROCESS_KEY, process_identity_matches
from ..native_decision_receipt import receipt_matches_edge, validate_native_decision_receipt
from ..native_runtime import native_mode
from ..store import GuardStore
from .hook_native_review_binding import (
    NATIVE_REVIEW_BINDING_FIELD,
    NATIVE_REVIEW_REQUEST_DIGEST_FIELD,
    native_review_binding_matches,
    native_review_policy_binding,
)
from .hook_native_review_fence import native_review_fence

if TYPE_CHECKING:
    from .hook_worker import HookWorker


def is_native_codex_review(request: object) -> bool:
    if not isinstance(request, Mapping) or request.get("harness") != "codex":
        return False
    artifact_id = request.get("artifact_id")
    return isinstance(artifact_id, str) and artifact_id.startswith("codex:native-pretool:")


def _decode_hook_input(payload: Mapping[str, object]) -> dict[str, object] | None:
    """Decode bounded transport only; Rust's request digest binds exact action identity."""
    raw = payload.get("hook_input")
    if not isinstance(raw, str) or len(raw.encode("utf-8")) > 1_000_000:
        return None
    decoded = json.loads(raw)
    if not isinstance(decoded, dict) or decoded.get("hook_event_name") != "PreToolUse":
        return None
    # Initial daemon ingress consumes these root transport hints before native
    # review. Resume owns its existing deadline and must forward that same
    # semantic input; nested tool arguments remain part of Rust's commitment.
    decoded.pop("guard_remaining_seconds", None)
    decoded.pop("guard_remaining_ms", None)
    return decoded


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _original_hook_is_live(
    store: GuardStore,
    request_id: str,
    hook_input: Mapping[str, object],
    *,
    config_reader: Callable[[Path], dict[str, object]] | None = None,
) -> bool:
    operation = store.get_guard_operation_for_approval_request(request_id)
    if not isinstance(operation, Mapping) or operation.get("status") not in {"waiting_on_approval", "resumed"}:
        return False
    metadata = operation.get("metadata")
    if not isinstance(metadata, Mapping):
        return False
    identity = hook_input.get(CODEX_BROWSER_WAIT_PROCESS_KEY)
    if identity != metadata.get("codex_browser_wait_process") or not process_identity_matches(identity):
        return False
    # A terminal record may be replayed by the same still-live bridge, without
    # extending its original deadline or moving authority to another process.
    waiting = {**operation, "status": "waiting_on_approval"}
    deadline = codex_live_hook_wait_deadline(store, operation=waiting, metadata=metadata, config_reader=config_reader)
    return deadline is not None and deadline > datetime.now(timezone.utc)


def _original_hook_home(store: GuardStore, request_id: str) -> Path | None:
    operation = store.get_guard_operation_for_approval_request(request_id)
    metadata = operation.get("metadata") if isinstance(operation, Mapping) else None
    value = metadata.get("native_hook_home_dir") if isinstance(metadata, Mapping) else None
    if not isinstance(value, str) or not value or len(value) > 32_768 or "\x00" in value:
        return None
    home = Path(value)
    return home if home.is_absolute() else None


def complete_native_codex_live_decision(
    store: GuardStore,
    *,
    worker: HookWorker,
    request_id: str,
    payload: Mapping[str, object],
    deadline: float,
) -> dict[str, object]:
    """Keep the real native result and exact local-once consume in one SH lease.

    Publication occurs before acquiring SH, avoiding a publisher EX upgrade.
    This route has no Python semantic reviewer and cannot authorize from an
    empty harness response or from an asynchronous receipt-writer cache.
    """
    failure: dict[str, object] = {"completed": False, "error": "fresh_policy_revalidation_failed"}
    try:
        request = store.get_approval_request(request_id)
        if not isinstance(request, Mapping) or not is_native_codex_review(request):
            return failure
        if request.get("resolution_action") == "block":
            return complete_codex_live_decision(
                store, request_id=request_id, now=_now(), config_reader=worker.config_reader
            )
        if request.get("status") != "resolved" or request.get("resolution_action") != "allow":
            return failure
        workspace_value = request.get("workspace")
        workspace = Path(workspace_value) if isinstance(workspace_value, str) and workspace_value else None
        hook_input = _decode_hook_input(payload)
        original_home = _original_hook_home(store, request_id)
        if (
            hook_input is None
            or original_home is None
            or native_mode() not in {"auto", "force"}
            or not _original_hook_is_live(store, request_id, hook_input, config_reader=worker.config_reader)
        ):
            return failure
        previous = store.get_request_resume(request_id)
        replay = (
            isinstance(previous, Mapping)
            and previous.get("resolution_action") == "allow"
            and previous.get("status") in {"resumed", "sent"}
        )
        authority = resolve_codex_live_allow_authority(store, request=request, request_id=request_id, now=_now())
        if authority is None and not replay:
            return {"completed": False, "error": "exact_approval_authority_missing"}
        if (
            replay
            and resolve_codex_consumed_allow_authority(store, request=request, request_id=request_id, now=_now())
            is None
        ):
            return {"completed": False, "error": "exact_approval_authority_missing"}
        snapshot = worker.prepare_workspace_policy(workspace, deadline=deadline)
        if snapshot is None or snapshot.get("mode") != "enforce" or time.monotonic() >= deadline:
            return failure
        with native_review_fence(
            policy_snapshot=snapshot,
            event_name="PreToolUse",
            recording_only=False,
            guard_home=store.guard_home,
            deadline=deadline,
        ) as fenced:
            stored_envelope = request.get("action_envelope_json")
            if isinstance(stored_envelope, Mapping) and NATIVE_REVIEW_BINDING_FIELD in stored_envelope and not fenced:
                return failure
            edge = worker._review_raw_hook_native(
                payload=hook_input,
                harness="codex",
                event="PreToolUse",
                guard_home=store.guard_home,
                home_dir=original_home,
                cwd=workspace,
                source_ref_external_allowed=False,
                observe_mode=False,
                deadline=deadline,
                policy_snapshot=snapshot,
            )
            if not isinstance(edge, Mapping):
                return failure
            receipt = validate_native_decision_receipt(edge.get("receipt"))
            result = edge.get("result")
            if (
                receipt is None
                or not receipt_matches_edge(edge, receipt)
                or not isinstance(result, Mapping)
                or edge.get("harness") != "codex"
                or edge.get("event_name") != "PreToolUse"
                or receipt.get("policy_digest") != snapshot.get("policy_digest")
                or receipt.get("policy_generation") != snapshot.get("generation")
                or receipt.get("runtime_identity") != snapshot.get("runtime_identity")
                or receipt.get("observe_mode") is not False
            ):
                return failure
            worker.metrics.record_route("native_resident")
            worker._record_native_decision_receipt(receipt)
            binding = native_review_policy_binding(
                harness="codex",
                native_result=result,
                verified_receipt=receipt,
                policy_snapshot=snapshot,
                workspace_bound=workspace is not None,
            )
            if not native_review_binding_matches(request, binding):
                return failure
            if not isinstance(stored_envelope, Mapping) or receipt.get("request_digest") != stored_envelope.get(
                NATIVE_REVIEW_REQUEST_DIGEST_FIELD
            ):
                return failure
            if receipt.get("request_digest") != request.get("artifact_hash"):
                return failure
            # Review is lifted only by the exact authority consumed below.
            # All independent Rust blocks and uncertainty retain their floor.
            action = result.get("policy_action")
            minimum = result.get("minimum_action")
            allowed = action == "allow" and minimum == "allow" and result.get("decision") == "allow"
            reviewable = action == "review" and minimum == "review" and result.get("decision") == "deny"
            if (
                not (allowed or reviewable)
                or not _original_hook_is_live(store, request_id, hook_input, config_reader=worker.config_reader)
                or time.monotonic() >= deadline
            ):
                return failure
            completed = complete_codex_live_decision(
                store,
                request_id=request_id,
                now=_now(),
                fresh_allow_authorized=True,
                require_consumed_once_for_replay=True,
                config_reader=worker.config_reader,
            )
        # Database acquisition/finalization and lock retirement consume the
        # same absolute budget. A consumed-but-undelivered decision may be
        # retried by the original hook; it must never produce a late allow.
        # The browser wait can expire or its process can exit while SQLite
        # commits, independently of this HTTP request's remaining budget.
        # Retain the committed consume for an exact retry, but never deliver
        # an allow to an expired or replaced original waiter.
        if (
            not _original_hook_is_live(store, request_id, hook_input, config_reader=worker.config_reader)
            or time.monotonic() >= deadline
        ):
            return failure
        return completed
    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
        return failure
