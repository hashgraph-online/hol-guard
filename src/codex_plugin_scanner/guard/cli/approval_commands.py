"""CLI helpers for Guard approval queue workflows."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

from ..approvals import apply_approval_resolution
from ..daemon import load_guard_daemon_url
from ..store import GuardStore


def add_approval_parser(
    guard_subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    add_common_args,
) -> None:
    approvals_parser = guard_subparsers.add_parser("approvals", help="List or resolve pending Guard approvals")
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


def run_approval_command(
    args: argparse.Namespace,
    *,
    store: GuardStore,
    workspace: Path | None,
) -> dict[str, object]:
    if getattr(args, "approvals_command", None) is None:
        return {
            "generated_at": _now(),
            "approval_center_url": load_guard_daemon_url(store.guard_home),
            "items": store.list_approval_requests(limit=200),
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
