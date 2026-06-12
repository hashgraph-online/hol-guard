"""Guard CLI parser local command groups."""

# fmt: off
# ruff: noqa: F403, F405, I001

from __future__ import annotations

import argparse

from ._commands_shared import *
from .commands_parser_helpers import *

def _configure_guard_local_parsers(
    guard_subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    start_parser = guard_subparsers.add_parser("start", help="Show the first Guard steps for a local harness")
    _add_guard_common_args(start_parser)
    start_parser.add_argument("--json", action="store_true")

    status_parser = guard_subparsers.add_parser("status", help="Show current Guard protection status")
    _add_guard_common_args(status_parser)
    status_parser.add_argument("--json", action="store_true")

    dashboard_parser = guard_subparsers.add_parser(
        "dashboard",
        help="Open the local Guard dashboard in your browser",
    )
    _add_guard_common_args(dashboard_parser)
    dashboard_parser.add_argument("--json", action="store_true")

    init_parser = guard_subparsers.add_parser(
        "init",
        help="Run first-run setup: protect detected apps, connect Cloud, and enable desktop notifications",
    )
    _add_guard_common_args(init_parser)
    init_parser.add_argument("--skip-apps", action="store_true", help="Do not install Guard into detected harnesses")
    init_parser.add_argument("--skip-cloud", action="store_true", help="Do not open Guard Cloud pairing")
    init_parser.add_argument(
        "--skip-notifications",
        action="store_true",
        help="Do not initialize desktop notifications",
    )
    init_parser.add_argument(
        "--yes",
        action="store_true",
        help="Approve every init step without prompting. Intended for automation and docs verification.",
    )
    init_parser.add_argument("--sync-url", default=DEFAULT_GUARD_SYNC_URL, type=_guard_http_url)
    init_parser.add_argument("--connect-url", default=DEFAULT_GUARD_CONNECT_URL, type=_guard_http_url)
    init_parser.add_argument("--wait-timeout-seconds", type=int, default=0)
    init_parser.add_argument("--json", action="store_true")

    apps_parser = guard_subparsers.add_parser("apps", help="Connect, test, repair, or disconnect protected apps")
    _add_guard_common_args(apps_parser)
    apps_parser.add_argument("--json", action="store_true")
    apps_subparsers = apps_parser.add_subparsers(dest="apps_command", parser_class=FriendlyArgumentParser)
    for app_command, help_text in (
        ("connect", "Connect an app to local Guard protection"),
        ("test", "Run a safe local Guard protection check"),
        ("repair", "Repair Guard-managed app config"),
        ("disconnect", "Remove Guard-managed app config"),
    ):
        app_parser = apps_subparsers.add_parser(app_command, help=help_text)
        app_parser.add_argument("harness")
        _add_guard_common_args(app_parser, suppress_defaults=True)
        app_parser.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
        app_parser.add_argument("--surface", choices=("editor", "cli"))
        if app_command in {"connect", "repair"}:
            app_parser.add_argument("--dry-run", action="store_true")
        if app_command == "disconnect":
            app_parser.add_argument("--confirm")

    admin_parser = guard_subparsers.add_parser("admin", help=argparse.SUPPRESS)
    _add_guard_common_args(admin_parser)
    admin_parser.add_argument("--json", action="store_true")

    bootstrap_parser = guard_subparsers.add_parser(
        "bootstrap",
        help="Detect a harness, start the approval center, and install Guard for the best local target",
    )
    bootstrap_parser.add_argument("harness", nargs="?")
    _add_guard_common_args(bootstrap_parser)
    bootstrap_parser.add_argument("--skip-install", action="store_true")
    bootstrap_parser.add_argument("--alias-name", default=DEFAULT_ALIAS_NAME)
    bootstrap_parser.add_argument("--write-shell-alias", action="store_true")
    bootstrap_parser.add_argument("--json", action="store_true")

    detect_parser = guard_subparsers.add_parser("detect", help="Discover supported harnesses and local artifacts")
    detect_parser.add_argument("harness", nargs="?")
    _add_guard_common_args(detect_parser)
    detect_parser.add_argument("--json", action="store_true")

    install_parser = guard_subparsers.add_parser("install", help="Enable Guard management for one or more harnesses")
    install_parser.add_argument("harness", nargs="?")
    install_parser.add_argument("--all", action="store_true")
    _add_guard_common_args(install_parser)
    install_parser.add_argument("--json", action="store_true")

    update_parser = guard_subparsers.add_parser(
        "update",
        help="Update the installed hol-guard package in the current environment",
    )
    _add_guard_common_args(update_parser)
    update_parser.add_argument("--dry-run", action="store_true")
    update_parser.add_argument("--json", action="store_true")

    uninstall_parser = guard_subparsers.add_parser(
        "uninstall",
        help="Disable Guard management for one or more harnesses",
    )
    uninstall_parser.add_argument("harness", nargs="?")
    uninstall_parser.add_argument("--all", action="store_true")
    _add_guard_common_args(uninstall_parser)
    uninstall_parser.add_argument("--json", action="store_true")

    package_shims_parser = guard_subparsers.add_parser(
        "package-shims",
        help="Install, repair, inspect, or remove package-manager PATH shims routed through Guard protect",
    )
    package_shims_parser.add_argument(
        "package_shims_command",
        nargs="?",
        choices=("install", "repair", "status", "uninstall"),
        default="status",
    )
    package_shims_parser.add_argument(
        "--manager",
        action="append",
        dest="package_shim_managers",
        default=[],
    )
    package_shims_parser.add_argument("--approval-password")
    package_shims_parser.add_argument("--approval-totp")
    _add_guard_common_args(package_shims_parser)
    package_shims_parser.add_argument("--json", action="store_true")

    run_parser = guard_subparsers.add_parser("run", help="Evaluate local policy, then launch the harness")
    run_parser.add_argument("harness")
    _add_guard_common_args(run_parser)
    run_parser.add_argument("--json", action="store_true")
    run_parser.add_argument("--dry-run", action="store_true")
    run_parser.add_argument(
        "--default-action",
        choices=("allow", "warn", "review", "block", "sandbox-required", "require-reapproval"),
    )
    run_parser.add_argument("--arg", dest="passthrough_args", action="append", default=[])

    protect_parser = guard_subparsers.add_parser(
        "protect",
        help="Wrap an install or harness registration command and stop risky artifacts before they land",
    )
    _add_guard_common_args(protect_parser)
    protect_parser.add_argument("--dry-run", action="store_true")
    protect_parser.add_argument("--unsafe-raw-output", action="store_true")
    protect_parser.add_argument("--json", action="store_true")
    protect_parser.add_argument("--package-shim-ui", action="store_true", help=argparse.SUPPRESS)
    protect_parser.add_argument("protect_command", nargs=argparse.REMAINDER)

    preflight_parser = guard_subparsers.add_parser(
        "preflight",
        help="Scan an artifact before you add it to a harness config or install path",
    )
    preflight_parser.add_argument("target", nargs="?", default=".")
    preflight_parser.add_argument("--harness")
    preflight_parser.add_argument("--enforce", action="store_true")
    preflight_parser.add_argument("--json", action="store_true")
    _add_guard_cisco_mode_arg(preflight_parser)

    scan_parser = guard_subparsers.add_parser("scan", help="Run a consumer-mode scan for a local artifact")
    scan_parser.add_argument("target", nargs="?", default=".")
    scan_parser.add_argument("--consumer-mode", action="store_true")
    scan_parser.add_argument("--json", action="store_true")
    scan_parser.add_argument("--deep", action="store_true", help="Run first-class local Cisco scanner evidence.")
    _add_guard_common_args(scan_parser)
    _add_guard_cisco_mode_arg(scan_parser)

    diff_parser = guard_subparsers.add_parser("diff", help="Compare current harness artifacts to stored snapshots")
    diff_parser.add_argument("harness")
    _add_guard_common_args(diff_parser)
    diff_parser.add_argument("--json", action="store_true")

    receipts_parser = guard_subparsers.add_parser("receipts", help="List local Guard receipts")
    _add_guard_common_args(receipts_parser)
    receipts_parser.add_argument("--json", action="store_true")

    history_parser = guard_subparsers.add_parser("history", help="Inspect Guard decision history")
    _add_guard_common_args(history_parser)
    history_sub = history_parser.add_subparsers(dest="history_command", metavar="COMMAND")
    history_explain_parser = history_sub.add_parser("explain", help="Show insight and evidence for a receipt ID")
    history_explain_parser.add_argument("receipt_id", help="Receipt ID to explain")
    history_explain_parser.add_argument("--json", action="store_true")

    inventory_parser = guard_subparsers.add_parser("inventory", help="List the local Guard artifact inventory")
    _add_guard_common_args(inventory_parser)
    inventory_parser.add_argument("--json", action="store_true")
    _add_aibom_cli_args(inventory_parser)

    abom_parser = guard_subparsers.add_parser("abom", help="Export a local Guard artifact bill of materials")
    _add_guard_common_args(abom_parser)
    abom_parser.add_argument("--json", action="store_true")
    abom_parser.add_argument("--format", choices=("markdown", "json"), default="markdown")

    aibom_parser = guard_subparsers.add_parser(
        "aibom",
        help="Inspect or export the local AIBOM with trust and source metadata",
    )
    _add_guard_common_args(aibom_parser)
    aibom_sub = aibom_parser.add_subparsers(dest="aibom_command", metavar="COMMAND")
    aibom_status_parser = aibom_sub.add_parser("status", help="Show local AIBOM status and trust coverage")
    _add_guard_common_args(aibom_status_parser)
    _add_aibom_cli_args(aibom_status_parser)
    aibom_status_parser.add_argument("--json", action="store_true")
    aibom_sync_parser = aibom_sub.add_parser("sync", help="Sync local AIBOM snapshots to Guard Cloud")
    _add_guard_common_args(aibom_sync_parser)
    _add_aibom_cli_args(aibom_sync_parser)
    aibom_sync_parser.add_argument("--json", action="store_true")
    aibom_export_parser = aibom_sub.add_parser("export", help="Export the local AIBOM")
    _add_guard_common_args(aibom_export_parser)
    _add_aibom_cli_args(aibom_export_parser)
    aibom_export_parser.add_argument("--json", action="store_true")
    aibom_export_parser.add_argument("--format", choices=("markdown", "json"), default="json")
    _add_aibom_cli_args(aibom_parser)
    aibom_parser.add_argument("--json", action="store_true")
    aibom_parser.add_argument("--format", choices=("markdown", "json"), default="json")

    add_approval_parser(guard_subparsers, _add_guard_common_args)

    explain_parser = guard_subparsers.add_parser(
        "explain",
        help=(
            "Show the latest evidence for a local artifact or local path with offline Cisco MCP evidence when available"
        ),
    )
    explain_parser.add_argument("target")
    _add_guard_common_args(explain_parser)
    explain_parser.add_argument("--json", action="store_true")
    _add_guard_cisco_mode_arg(explain_parser)

    for name, action in (("allow", "allow"), ("deny", "block")):
        policy_parser = guard_subparsers.add_parser(name, help=f"{name.title()} a harness artifact")
        policy_parser.add_argument("harness")
        policy_parser.add_argument("--artifact-id")
        policy_parser.add_argument(
            "--scope",
            choices=("global", "harness", "workspace", "artifact", "publisher"),
            default="harness",
        )
        policy_parser.add_argument("--reason")
        policy_parser.add_argument("--publisher")
        policy_parser.add_argument("--owner")
        policy_parser.add_argument("--expires-in-hours", type=float)
        _add_guard_common_args(policy_parser)
        policy_parser.add_argument("--json", action="store_true")
        policy_parser.set_defaults(policy_action=action)

__all__ = [
    "_configure_guard_local_parsers",
]
