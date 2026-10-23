"""Guard approvals parser construction kept free of approval runtime imports."""

from __future__ import annotations

import argparse

from ..approval_wait_limits import MAX_APPROVAL_WAIT_TIMEOUT_SECONDS


def _wait_timeout(value: str) -> int:
    seconds = int(value)
    if not 0 <= seconds <= MAX_APPROVAL_WAIT_TIMEOUT_SECONDS:
        raise argparse.ArgumentTypeError(f"timeout must be between 0 and {MAX_APPROVAL_WAIT_TIMEOUT_SECONDS} seconds")
    return seconds


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
        decision_parser.add_argument(
            "--remember",
            action="store_true",
            help="Save an exact-action remembered rule for artifact scope instead of resolving only this request.",
        )
        if action == "allow":
            decision_parser.add_argument(
                "--trust-local-tool",
                action="store_true",
                help="Trust the verified read-only local tool capability after authenticated approval.",
            )
            decision_parser.add_argument(
                "--trust-target",
                choices=("capability", "version"),
                default="capability",
                help="Trust only this capability or every verified read-only capability from this tool version.",
            )
            decision_parser.add_argument(
                "--trust-duration",
                choices=("15m", "1h", "5h", "version", "always"),
                default="1h",
                help="How long the local tool grant remains active.",
            )
        add_common_args(decision_parser)
        decision_parser.add_argument("--json", action="store_true")
        decision_parser.set_defaults(approval_action=action)

    list_parser = approvals_subparsers.add_parser(
        "list",
        help="List pending approval requests and recent receipts without opening the approval center",
    )
    add_common_args(list_parser)
    list_parser.add_argument("--json", action="store_true")

    wait_parser = approvals_subparsers.add_parser("wait", help="Wait for a decision without resolving or executing it")
    wait_parser.add_argument("request_id")
    wait_parser.add_argument(
        "--timeout", type=_wait_timeout, default=120, help="Wait at most this many seconds (0-600)"
    )
    add_common_args(wait_parser)
    wait_parser.add_argument("--json", action="store_true")

    clear_history_parser = approvals_subparsers.add_parser(
        "clear-history",
        help="Clear remembered rules and resolved approval history so flows can be re-tested",
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
        help="Optional source filter for remembered rules (for example: manual, claude-ask-user-question)",
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

    unlock_parser = approvals_subparsers.add_parser(
        "unlock",
        help="Unlock approval gate cooldown for 15m or 1h",
    )
    unlock_parser.add_argument("--duration", choices=("15m", "1h"), default="15m")
    add_common_args(unlock_parser)
    unlock_parser.add_argument("--json", action="store_true")

    lock_parser = approvals_subparsers.add_parser(
        "lock",
        help="End the active approval gate cooldown immediately",
    )
    add_common_args(lock_parser)
    lock_parser.add_argument("--json", action="store_true")
