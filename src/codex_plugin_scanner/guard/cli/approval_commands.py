"""CLI helpers for Guard approval queue workflows."""

from __future__ import annotations

import argparse
import urllib.parse
import webbrowser
from datetime import datetime, timezone
from pathlib import Path

from ..approval_gate import ApprovalGateError, require_high_risk
from ..approval_gate import public_config as approval_gate_public_config
from ..approvals import apply_approval_resolution, build_runtime_snapshot
from ..codex_resume import retry_request_resume
from ..config import load_guard_config
from ..daemon import load_guard_daemon_url
from ..runtime.surface_server import GuardSurfaceRuntime
from ..store import GuardStore
from .approval_gate_prompt import approval_gate_cli_payload, prompt_for_approval_gate

_HARNESS_RETRY_COPY: dict[str, str] = {
    "codex": "Return to Codex and retry",
    "claude-code": "Return to Claude and retry",
    "opencode": "Return to OpenCode and retry",
    "copilot": "Return to Copilot and retry",
}
_DEFAULT_RETRY_COPY = "Return to your AI assistant and retry"


def _build_retry_hint(action: str, harness: str) -> dict[str, str]:
    title = "Approved. Retry in chat." if action == "allow" else "Blocked. Guard will remember this decision."
    return {"title": title, "body": _HARNESS_RETRY_COPY.get(harness, _DEFAULT_RETRY_COPY)}


def add_approval_parser(
    guard_subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    add_common_args,
) -> None:
    approvals_parser = guard_subparsers.add_parser(
        "approvals",
        help="List, resolve, or clear Guard approval history",
    )
    approvals_subparsers = approvals_parser.add_subparsers(dest="approvals_command")

    add_common_args(approvals_parser)
    approvals_parser.add_argument("--json", action="store_true")

    for name, action in (("approve", "allow"), ("deny", "block")):
        decision_parser = approvals_subparsers.add_parser(name, help=f"{name.title()} a pending approval request")
        decision_parser.add_argument("request_id")
        decision_parser.add_argument(
            "--scope",
            choices=("artifact", "publisher", "workspace", "harness", "global"),
            default="artifact",
        )
        decision_parser.add_argument("--reason")
        add_common_args(decision_parser)
        decision_parser.add_argument("--json", action="store_true")
        decision_parser.set_defaults(approval_action=action)

    clear_history_parser = approvals_subparsers.add_parser(
        "clear-history",
        help="Clear saved allow/deny history so flows can be re-tested",
    )
    clear_history_parser.add_argument(
        "--harness",
        help="The harness to clear history for (for example: codex, claude-code, opencode, copilot)",
    )
    clear_history_parser.add_argument(
        "--all",
        action="store_true",
        help="Clear approval history across every harness; cannot be combined with --harness",
    )
    clear_history_parser.add_argument(
        "--source",
        help="Optional source filter for policy decisions (for example: manual, claude-ask-user-question)",
    )
    add_common_args(clear_history_parser)
    clear_history_parser.add_argument("--json", action="store_true")

    open_parser = approvals_subparsers.add_parser(
        "open",
        help="Show the approval URL for a pending request",
    )
    open_parser.add_argument("request_id", help="The approval request ID to open")
    add_common_args(open_parser)
    open_parser.add_argument("--json", action="store_true")

    retry_hint_parser = approvals_subparsers.add_parser(
        "retry-hint",
        help="Print the retry hint for a resolved approval request",
    )
    retry_hint_parser.add_argument("request_id", help="The approval request ID to get the retry hint for")
    add_common_args(retry_hint_parser)
    retry_hint_parser.add_argument("--json", action="store_true")

    resume_parser = approvals_subparsers.add_parser(
        "resume",
        help="Retry Codex auto-resume for a resolved approval request",
    )
    resume_parser.add_argument("request_id", help="The approval request ID to resume")
    resume_parser.add_argument("--force", action="store_true", help="Retry even if Codex was already resumed")
    add_common_args(resume_parser)
    resume_parser.add_argument("--json", action="store_true")


def run_approval_command(
    args: argparse.Namespace,
    *,
    store: GuardStore,
    workspace: Path | None,
) -> dict[str, object]:
    command = getattr(args, "approvals_command", None)
    if command is None:
        payload = build_runtime_snapshot(
            store=store,
            approval_center_url=load_guard_daemon_url(store.guard_home),
            now=_now(),
        )
        payload["auto_open"] = _auto_open_first_pending_request(store=store, workspace=workspace)
        return payload
    if command == "clear-history":
        harness = getattr(args, "harness", None)
        clear_all = bool(getattr(args, "all", False))
        if clear_all and harness is not None:
            return {
                "history_cleared": False,
                "error": "Choose either --all or --harness <name> when clearing approval history.",
                "cleared_policies": 0,
                "cleared_resolved_requests": 0,
                "exit_code": 2,
            }
        if not clear_all and harness is None:
            return {
                "history_cleared": False,
                "error": "Choose --harness <name> or --all when clearing approval history.",
                "cleared_policies": 0,
                "cleared_resolved_requests": 0,
                "exit_code": 2,
            }
        target_harness = None if clear_all else harness
        source = getattr(args, "source", None)
        try:
            gate_input = prompt_for_approval_gate(store.guard_home, use_cooldown=False)
            approval_gate_grant = require_high_risk(
                store.guard_home,
                purpose="policy_clear",
                approval_gate_input=gate_input,
            )
            cleared_resolved_requests = 0
            if source is None:
                cleared_resolved_requests = store.clear_approval_requests(harness=target_harness, status="resolved")
            cleared_policies = store.clear_policy_decisions(
                target_harness,
                source,
                approval_gate_grant=approval_gate_grant,
            )
        except ApprovalGateError as error:
            return approval_gate_cli_payload(error)
        return {
            "history_cleared": True,
            "harness": target_harness,
            "source": source,
            "cleared_policies": cleared_policies,
            "cleared_resolved_requests": cleared_resolved_requests,
            "exit_code": 0,
        }
    try:
        gate_input = (
            prompt_for_approval_gate(store.guard_home)
            if _approval_resolution_needs_gate(
                store,
                action=str(args.approval_action),
                scope=str(args.scope),
            )
            else None
        )
        item = apply_approval_resolution(
            store=store,
            request_id=args.request_id,
            action=args.approval_action,
            scope=args.scope,
            workspace=str(workspace) if workspace is not None else None,
            reason=args.reason,
            now=_now(),
            approval_gate_input=gate_input,
        )
    except ApprovalGateError as error:
        return approval_gate_cli_payload(error)
    return {"resolved": True, "item": item}


def _approval_resolution_needs_gate(store: GuardStore, *, action: str, scope: str) -> bool:
    gate = approval_gate_public_config(store.guard_home)
    if not gate.enabled:
        return False
    if scope == "global":
        return True
    if gate.cooldown_active:
        return False
    if action == "allow":
        return True
    return gate.strict_all_decisions


def _auto_open_first_pending_request(*, store: GuardStore, workspace: Path | None) -> dict[str, object]:
    request = store.get_next_pending_request()
    if request is None:
        return {"opened": False, "reason": "no-pending-request"}
    approval_url = str(request.get("approval_url") or "")
    approval_center_url = _repaired_approval_url(approval_url, store.guard_home) or load_guard_daemon_url(
        store.guard_home
    )
    if approval_center_url is None:
        return {"opened": False, "reason": "missing-approval-url"}
    request_id = str(request.get("request_id") or "")
    if not request_id:
        return {"opened": False, "reason": "missing-request-id"}
    config = load_guard_config(store.guard_home, workspace)
    approval_surface_policy = config.approval_surface_policy
    if approval_surface_policy == "native-only":
        approval_surface_policy = "never-auto-open"
    result = GuardSurfaceRuntime(store).ensure_surface(
        surface="approval-center",
        approval_center_url=approval_center_url,
        approval_surface_policy=approval_surface_policy,
        open_key=f"approval-request:{request_id}",
        opener=webbrowser.open,
    )
    result["request_id"] = request_id
    return result


def run_approval_open_command(
    args: argparse.Namespace,
    *,
    store: GuardStore,
) -> tuple[dict[str, object], int]:
    request_id = args.request_id
    item = store.get_approval_request(request_id)
    if item is None:
        return {"error": "not_found", "request_id": request_id}, 1
    approval_url = str(item.get("approval_url", ""))
    repaired_url = _repaired_approval_url(approval_url, store.guard_home)
    return {
        "request_id": request_id,
        "approval_url": repaired_url,
        "repaired": repaired_url != approval_url,
    }, 0


def run_approval_retry_hint_command(
    args: argparse.Namespace,
    *,
    store: GuardStore,
) -> tuple[dict[str, object], int]:
    request_id = args.request_id
    item = store.get_approval_request(request_id)
    if item is None:
        return {"error": "not_found", "request_id": request_id}, 1
    status = str(item.get("status", ""))
    if status != "resolved":
        return {"error": "not_resolved", "status": status, "request_id": request_id}, 1
    resolution_action = str(item.get("resolution_action", ""))
    harness = str(item.get("harness", ""))
    hint: dict[str, object] = dict(_build_retry_hint(resolution_action, harness))
    return hint, 0


def run_approval_resume_command(
    args: argparse.Namespace,
    *,
    store: GuardStore,
) -> tuple[dict[str, object], int]:
    request_id = args.request_id
    try:
        payload = retry_request_resume(
            store,
            request_id=request_id,
            now=_now(),
            force=bool(getattr(args, "force", False)),
        )
    except ValueError as error:
        error_code = str(error)
        if error_code == "not_found":
            return {"error": "not_found", "request_id": request_id}, 1
        if error_code == "not_resolved":
            item = store.get_approval_request(request_id)
            status = str(item.get("status", "")) if item is not None else ""
            return {"error": "not_resolved", "status": status, "request_id": request_id}, 1
        return {"error": "resume_not_supported", "request_id": request_id}, 1
    return payload, 0


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _repaired_approval_url(approval_url: str, guard_home: Path) -> str:
    daemon_url = load_guard_daemon_url(guard_home)
    if daemon_url is None:
        return approval_url
    try:
        parsed_approval = urllib.parse.urlparse(approval_url)
        parsed_daemon = urllib.parse.urlparse(daemon_url)
    except ValueError:
        return approval_url
    if parsed_approval.scheme not in {"http", "https"} or parsed_approval.hostname not in {
        "127.0.0.1",
        "::1",
        "localhost",
    }:
        return approval_url
    return urllib.parse.urlunparse(
        (
            parsed_daemon.scheme,
            parsed_daemon.netloc,
            parsed_approval.path,
            parsed_approval.params,
            parsed_approval.query,
            parsed_approval.fragment,
        )
    )
