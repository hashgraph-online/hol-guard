"""``hol-guard hooks remove``: strip every Guard hook from every known harness."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING, TextIO

from ..approval_gate import ApprovalGateError
from ..hook_removal import format_removal_summary, plan_hook_removal, remove_all_guard_hooks
from ..hook_removal_presence import removal_gate_enabled, require_typed_presence
from .approval_gate_prompt import approval_gate_cli_payload
from .commands_lifecycle_gate import LifecycleGateRequirement, lifecycle_authority_home
from .commands_parser_helpers import _add_guard_common_args

if TYPE_CHECKING:
    from ..adapters.base import HarnessContext
    from ..config import GuardConfig
    from ..store import GuardStore

HOOKS_REMOVE_ACTION = "hooks.remove"


def configure_guard_hooks_parser(
    guard_subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    hooks_parser = guard_subparsers.add_parser("hooks", help="Manage Guard hooks in harness configs")
    hooks_subparsers = hooks_parser.add_subparsers(dest="hooks_command", required=True)
    remove_parser = hooks_subparsers.add_parser(
        "remove",
        help="Remove every Guard hook from every known harness config (requires step-up)",
    )
    remove_parser.add_argument(
        "--all",
        action="store_true",
        help="Accepted for clarity; removal always covers every known harness",
    )
    remove_parser.add_argument(
        "--stop-daemon",
        action="store_true",
        help="Also stop the local Guard daemon after the hooks are removed",
    )
    remove_parser.add_argument("--dry-run", action="store_true", help="List what would be removed and change nothing")
    _add_guard_common_args(remove_parser)
    remove_parser.add_argument("--json", action="store_true")


def _print_gate_error(error: ApprovalGateError, *, as_json: bool, output_stream: TextIO | None) -> int:
    if as_json:
        print(json.dumps(approval_gate_cli_payload(error), sort_keys=True), file=output_stream or sys.stdout)
    else:
        print(f"Error: {error}", file=sys.stderr)
    return 4


def run_hook_removal(
    args: argparse.Namespace,
    *,
    guard_home: Path,
    context: HarnessContext,
    store: GuardStore,
    output_stream: TextIO | None = None,
) -> int:
    """Run ``hooks remove``.

    With the approval gate enabled, the router already ran the step-up through
    ``enforce_lifecycle_gate`` before this is reached. With no gate there is
    nothing to step up against, so a typed phrase on an interactive terminal
    stands in; a non-interactive caller is refused.
    """

    as_json = bool(getattr(args, "json", False))
    dry_run = bool(getattr(args, "dry_run", False))
    if not dry_run:
        authority_home = lifecycle_authority_home(
            guard_home,
            requirement=LifecycleGateRequirement(HOOKS_REMOVE_ACTION, "all"),
        )
        if not removal_gate_enabled(authority_home):
            plans = plan_hook_removal(context, store)
            affected = ", ".join(plan.harness for plan in plans) or "no apps"
            try:
                require_typed_presence(affected=affected)
            except ApprovalGateError as error:
                return _print_gate_error(error, as_json=as_json, output_stream=output_stream)
    report = remove_all_guard_hooks(context=context, store=store, dry_run=dry_run)
    if bool(getattr(args, "stop_daemon", False)) and not dry_run:
        from ..daemon_stop import stop_guard_daemon

        report["daemon"] = stop_guard_daemon(guard_home)
    if as_json:
        print(json.dumps(report, sort_keys=True), file=output_stream or sys.stdout)
    else:
        print(format_removal_summary(report), file=output_stream or sys.stdout)
        if isinstance(report.get("daemon"), dict):
            print("Guard daemon stopped.", file=output_stream or sys.stdout)
    return 0 if report.get("status") != "partial" else 1


def _run_guard_hooks_command(
    args: argparse.Namespace,
    *,
    guard_home: Path | None = None,
    workspace: Path | None = None,
    context: HarnessContext | None = None,
    store: GuardStore | None = None,
    config: GuardConfig | None = None,
    input_text: str | None = None,
    output_stream: TextIO | None = None,
) -> int:
    del workspace, config, input_text
    if guard_home is None or context is None or store is None:
        raise RuntimeError("Guard home, context, and store are required")
    if getattr(args, "hooks_command", None) != "remove":
        print("Unknown hooks command.", file=sys.stderr)
        return 2
    return run_hook_removal(args, guard_home=guard_home, context=context, store=store, output_stream=output_stream)


__all__ = ["_run_guard_hooks_command", "configure_guard_hooks_parser", "run_hook_removal"]
