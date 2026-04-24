"""CLI helpers for Guard approval queue workflows."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

from ..approvals import apply_approval_resolution, build_runtime_snapshot
from ..daemon import load_guard_daemon_url
from ..store import GuardStore


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


def run_approval_command(
    args: argparse.Namespace,
    *,
    store: GuardStore,
    workspace: Path | None,
) -> dict[str, object]:
    command = getattr(args, "approvals_command", None)
    if command is None:
        return build_runtime_snapshot(
            store=store,
            approval_center_url=load_guard_daemon_url(store.guard_home),
            now=_now(),
        )
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
        cleared_resolved_requests = 0
        if source is None:
            cleared_resolved_requests = store.clear_approval_requests(harness=target_harness, status="resolved")
        return {
            "history_cleared": True,
            "harness": target_harness,
            "source": source,
            "cleared_policies": store.clear_policy_decisions(target_harness, source),
            "cleared_resolved_requests": cleared_resolved_requests,
            "exit_code": 0,
        }
    item = apply_approval_resolution(
        store=store,
        request_id=args.request_id,
        action=args.approval_action,
        scope=args.scope,
        workspace=str(workspace) if workspace is not None else None,
        reason=args.reason,
        now=_now(),
    )
    return {"resolved": True, "item": item}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
