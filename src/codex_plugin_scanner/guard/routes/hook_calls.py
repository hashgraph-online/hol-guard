"""Library steps the native daemon's hook route calls in the resident library process.

The daemon owns ``POST /v1/hooks/<harness>`` and its readiness route: the
caller check, the deadline, directory trust, the admission scheduler and
every reply. What still lives in the Python library -- the hook worker, its
policy publisher and the audit log -- runs here, in the resident process so
the worker and its caches outlive one hook.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

from ..store import GuardStore

_SERVERS: dict[str, Any] = {}
_SERVERS_LOCK = threading.Lock()


def _server(store: GuardStore, args: Mapping[str, Any]) -> Any:
    """The resident's daemon state for this Guard home, built on first use."""

    from ..native_daemon_manage import load_guard_daemon_auth_token
    from .request_host import _replay_server_class

    key = str(store.guard_home)
    with _SERVERS_LOCK:
        server = _SERVERS.get(key)
        if server is None:
            port = args.get("port")
            home_dir = args.get("home_dir")
            daemon_pid = args.get("daemon_pid")
            server = _replay_server_class()(
                store,
                port if isinstance(port, int) else 0,
                "127.0.0.1",
                Path(home_dir) if isinstance(home_dir, str) and home_dir else Path.home(),
                load_guard_daemon_auth_token(store.guard_home) or "",
                daemon_pid if isinstance(daemon_pid, int) else None,
                False,
            )
            _SERVERS[key] = server
        return server


def _text(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _deadline(args: Mapping[str, Any]) -> float:
    remaining = args.get("remaining_seconds")
    seconds = float(remaining) if isinstance(remaining, (int, float)) and not isinstance(remaining, bool) else 0.0
    return time.monotonic() + max(0.0, seconds)


def _payload(args: Mapping[str, Any]) -> dict[str, object]:
    payload = args.get("payload")
    return dict(payload) if isinstance(payload, dict) else {}


def _params(args: Mapping[str, Any]) -> dict[str, list[str]]:
    query = args.get("query")
    return parse_qs(query) if isinstance(query, str) else {}


def hook_warm(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Builds the resident's hook worker before the first hook needs it."""

    server = _server(store, args)
    _ = server.hook_worker
    return {}


def hook_prepare(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Wait for publication and return the facts the native daemon renders."""

    server = _server(store, args)
    workspace = _text(args.get("workspace"))
    worker = server.hook_worker
    deadline = _deadline(args)
    prepared = worker.prepare_workspace_policy(Path(workspace) if workspace else None, deadline=deadline)
    if prepared is None:
        worker.metrics.record_route("native_fail_safe")
        publisher = getattr(worker, "policy_snapshot_publisher", None)
        last_error = getattr(publisher, "last_error", None)
        read_streak = getattr(publisher, "resident_failure_streak", None)
        streak = read_streak() if callable(read_streak) else 0
        return {
            "fail_safe": {
                # Older native callers still need a complete refusal.
                "reason": "HOL Guard could not prepare the native policy safely. "
                "This is usually temporary. Retry this action.",
                "reason_code": "native_policy_not_ready",
                "policy_failure": {
                    "last_error": last_error if isinstance(last_error, str) and len(last_error) <= 128 else None,
                    "resident_failure_streak": min(max(0, streak), 1_000_000) if type(streak) is int else 0,
                },
            }
        }
    return {}


def hook_ready(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Readiness: whether the workspace's policy is published within the readiness window."""

    from ..hook_review.hook_worker import WORKSPACE_POLICY_READINESS_TIMEOUT_SECONDS

    server = _server(store, args)
    workspace = _text(args.get("workspace"))
    if workspace is None:
        return {"prepared": False}
    try:
        prepared = server.hook_worker.prepare_workspace_policy(
            Path(workspace), deadline=time.monotonic() + WORKSPACE_POLICY_READINESS_TIMEOUT_SECONDS
        )
    except Exception:
        server.diagnostics.record_exception("native_workspace_readiness_failed")
        prepared = None
    return {"prepared": isinstance(prepared, dict)}


def hook_review(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """The hook worker's answer, or the fail-safe reason when it raised."""

    from contextlib import nullcontext

    from ..sqlite_tuning import sqlite_operation_deadline

    server = _server(store, args)
    deadline = _deadline(args)
    home_dir = _text(args.get("home_dir_effective"))
    guard_home = _text(args.get("guard_home_effective"))
    workspace = _text(args.get("workspace"))
    with sqlite_operation_deadline(deadline) if deadline is not None else nullcontext():
        try:
            answer = server.hook_worker.review_http_payload(
                payload=_payload(args),
                params=_params(args),
                default_harness=_text(args.get("harness")) or "",
                home_dir=Path(home_dir) if home_dir else server.home_dir,
                guard_home=Path(guard_home) if guard_home else store.guard_home,
                workspace=Path(workspace) if workspace else None,
                deadline=deadline,
            )
        except Exception as error:
            # Fail safe: deny; there is no Python semantic fallback.
            server.hook_worker.metrics.record_failure(stage="server", exception_type=type(error).__name__)
            return {
                "fail_safe": {
                    "reason": "HOL Guard could not complete local hook review safely.",
                    "reason_code": "daemon_worker_exception",
                }
            }
    return {"answer": answer if isinstance(answer, dict) else None}


def hook_integrity_key(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """The policy-integrity key the daemon signs Claude lifecycle state with.

    The secret store stays in Python; the daemon runs the lifecycle ops
    itself and only reads the existing key here. ``{}`` when there is none.
    """

    from ..native_hook_authority_state import hook_authority_integrity_key

    key: dict[str, object] = dict(hook_authority_integrity_key(store) or {})
    return key


def hook_integrity_begin(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Begin a policy-integrity generation before a Rust hook write."""

    from .policy_write_calls import integrity_begin

    return integrity_begin(store, args)


def hook_integrity_finalize(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Finalize Rust's policy-integrity generation in the secret store."""

    next_control_state = args.get("next_control_state")
    if next_control_state is None:
        return {"finalized": True}
    if not isinstance(next_control_state, dict):
        return {"finalized": False}
    try:
        stored = store._finalize_policy_integrity_control_state(next_control_state)
    except (OSError, RuntimeError, TypeError, ValueError):
        return {"finalized": False}
    return {"finalized": stored is True}


def hook_integrity_finalize_locked(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Compatibility alias for the lock-owning finalize operation.

    The old callback could outlive the coordinator lock after a timed-out
    resident request. Finalization now always reacquires and validates its
    own lock before writing the secret-backed generation.
    """

    return hook_integrity_finalize(store, args)


def hook_sink_command(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """The argv prefix of the contained sink, for the daemon's Cursor sink admission."""

    from ..contained_sink_command import contained_sink_command_prefix

    return {"sink_command": list(contained_sink_command_prefix())}


def hook_claude_question_save(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Transport a settled Claude approval plan to the Rust authority op."""

    from ..cli._commands_shared import _now
    from ..native_hook_authority_state import (
        HOOK_AUTHORITY_STATE_CLAUDE_LIFECYCLE_FEATURE,
        hook_authority_state,
    )

    session_id = _text(args.get("session_id"))
    artifact_id = _text(args.get("artifact_id"))
    pending_artifact_hash = _text(args.get("pending_artifact_hash"))
    reason = _text(args.get("reason"))
    source = _text(args.get("source"))
    if not (session_id and artifact_id and pending_artifact_hash and reason and source):
        return {"valid": False}

    def save_under_lock() -> dict[str, object] | None:
        try:
            integrity = hook_integrity_begin(store, {"now": _now(), "sign": True})
        except Exception:
            return None
        payload = {
            "artifact_id": artifact_id,
            "pending_artifact_hash": pending_artifact_hash,
            "reason": reason,
            "source": source,
            "plan": args.get("plan"),
        }
        if isinstance(integrity.get("current_generation"), int):
            payload["current_generation"] = integrity["current_generation"]
        integrity_fields: dict[str, object] = (
            {
                "integrity_key_b64": integrity["integrity_key_b64"],
                "integrity_key_id": integrity["integrity_key_id"],
            }
            if isinstance(integrity.get("current_generation"), int)
            and isinstance(integrity.get("integrity_key_b64"), str)
            and isinstance(integrity.get("integrity_key_id"), str)
            else {}
        )
        return hook_authority_state(
            store,
            "claude_question_save",
            now=_now(),
            required_feature=HOOK_AUTHORITY_STATE_CLAUDE_LIFECYCLE_FEATURE,
            integrity=integrity_fields,
            session_id=session_id,
            payload=payload,
        )

    with store.hold_policy_integrity_generation_lock():
        reply = save_under_lock()
    if not isinstance(reply, dict) or reply.get("saved") is not True:
        return {"valid": False}
    finalized = hook_integrity_finalize(store, {"next_control_state": reply.get("next_control_state")})
    if finalized.get("finalized") is not True:
        return {"valid": False}
    consumed = hook_authority_state(
        store,
        "claude_question_consume",
        now=_now(),
        required_feature=HOOK_AUTHORITY_STATE_CLAUDE_LIFECYCLE_FEATURE,
        session_id=session_id,
        payload={
            "artifact_id": artifact_id,
            "pending_artifact_hash": pending_artifact_hash,
            **({"pending_id": args["pending_id"]} if isinstance(args.get("pending_id"), str) else {}),
        },
    )
    if not isinstance(consumed, dict) or consumed.get("consumed") is not True:
        return {"valid": False}
    return reply


_LIVE_DECISION_REVIEW_SECONDS = 1.45


def codex_live_decision(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """``POST /v1/requests/<id>/live-decision``: the waiting Codex hook's decision.

    The Codex hook bridge holds the original hook open while the request is
    reviewed, then posts the exact hook input here. An allow is honoured only
    when the request still holds its one-shot authority and a fresh review of
    that input, through the resident's hook worker, authorizes it; the store
    then records the terminal decision the bridge answers the harness with.
    """

    from ..codex_live_decision import complete_codex_live_decision, resolve_codex_live_allow_authority
    from ..codex_live_decision_revalidation import revalidate_codex_live_allow
    from ..library_calls import LibraryCallError

    request_id = args.get("request_id")
    payload = args.get("payload")
    if not isinstance(request_id, str) or not request_id or not isinstance(payload, dict):
        raise LibraryCallError("invalid_arguments")
    now = datetime.now(timezone.utc).isoformat()
    request = store.get_approval_request(request_id)
    previous = store.get_request_resume(request_id)
    authority_resolved = False
    if isinstance(request, Mapping) and request.get("resolution_action") == "allow":
        authority_resolved = (
            resolve_codex_live_allow_authority(store, request=request, request_id=request_id, now=now) is not None
        )
    server = _server(store, args)

    def review(
        hook_payload: dict[str, object],
        workspace: Path | None,
        claimed_hash: str | None,
        claimed_request_id: str | None,
    ) -> Mapping[str, object] | None:
        return server.hook_worker.review_http_payload(
            payload=dict(hook_payload),
            params={},
            default_harness="codex",
            home_dir=server.home_dir,
            guard_home=store.guard_home,
            workspace=workspace,
            deadline=time.monotonic() + _LIVE_DECISION_REVIEW_SECONDS,
            claim_saved_approval=False,
            claimed_saved_allow_hash=claimed_hash,
            claimed_approval_request_id=claimed_request_id,
        )

    fresh_allow_authorized = revalidate_codex_live_allow(
        request,
        payload,
        home_dir=server.home_dir,
        guard_home=store.guard_home,
        reviewer=review,
        previous=previous,
        request_id=request_id,
        authority_resolved=authority_resolved,
    )
    result = complete_codex_live_decision(
        store,
        request_id=request_id,
        now=datetime.now(timezone.utc).isoformat(),
        fresh_allow_authorized=fresh_allow_authorized,
    )
    return {"status": 200 if result.get("completed") is True else 409, "body": dict(result), "no_store": False}


HOOK_CALLS = {
    "hook.claude_question_save": hook_claude_question_save,
    "hook.codex_live_decision": codex_live_decision,
    "hook.integrity_key": hook_integrity_key,
    "hook.integrity_begin": hook_integrity_begin,
    "hook.integrity_finalize": hook_integrity_finalize,
    "hook.integrity_finalize_locked": hook_integrity_finalize_locked,
    "hook.sink_command": hook_sink_command,
    "hook.prepare": hook_prepare,
    "hook.ready": hook_ready,
    "hook.warm": hook_warm,
    "hook.review": hook_review,
}
