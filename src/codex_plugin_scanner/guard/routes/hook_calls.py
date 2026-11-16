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
    """Applies the native-policy barrier before the daemon admits the hook."""

    from ..hook_review.hook_policy_admission import _native_policy_not_ready_reason

    server = _server(store, args)
    workspace = _text(args.get("workspace"))
    worker = server.hook_worker
    prepared = worker.prepare_workspace_policy(Path(workspace) if workspace else None, deadline=_deadline(args))
    if prepared is None:
        worker.metrics.record_route("native_fail_safe")
        return {
            "fail_safe": {
                "reason": _native_policy_not_ready_reason(server),
                "reason_code": "native_policy_not_ready",
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


def hook_sink_command(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """The argv prefix of the contained sink, for the daemon's Cursor sink admission."""

    from ..contained_sink_command import contained_sink_command_prefix

    return {"sink_command": list(contained_sink_command_prefix())}


def hook_claude_question_save(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Saves the answer the daemon read from Claude's HOL Guard approval question.

    The daemon settles the question against the session's pending review and
    hands over the plan the op returned; the policy write holds the integrity
    lock, so it stays here. ``valid`` is false for a plan the library refuses.
    """

    from ..cli import commands_support  # noqa: F401
    from ..cli._commands_shared import _now
    from ..cli.commands_support_hook_state import _remove_claude_pending_permission
    from ..cli.commands_support_permission_store import _write_claude_native_permission_plan
    from ..native_hook_decision import NativeHookDecisionError, validated_permission_persist_plan

    session_id = _text(args.get("session_id"))
    artifact_id = _text(args.get("artifact_id"))
    reason = _text(args.get("reason"))
    source = _text(args.get("source"))
    if not (session_id and artifact_id and reason and source):
        return {"valid": False}
    try:
        plan = validated_permission_persist_plan(args.get("plan"))
    except NativeHookDecisionError:
        return {"valid": False}
    saved = _write_claude_native_permission_plan(
        store=store,
        plan=plan,
        artifact_id=artifact_id,
        reason=reason,
        source=source,
        now=_now(),
    )
    if saved:
        _remove_claude_pending_permission(store, session_id=session_id, artifact_id=artifact_id)
    return {"valid": True, "saved": bool(saved)}


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
    "hook.sink_command": hook_sink_command,
    "hook.prepare": hook_prepare,
    "hook.ready": hook_ready,
    "hook.warm": hook_warm,
    "hook.review": hook_review,
}
