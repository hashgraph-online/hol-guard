"""Guard CLI command handlers."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import sqlite3
import subprocess
import sys
import urllib.error
import urllib.parse
import webbrowser
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TextIO

from ...argparse_utils import FriendlyArgumentParser
from ...models import ScanOptions
from ..adapters import get_adapter
from ..adapters.base import HarnessContext
from ..approvals import (
    approval_center_hint,
    approval_delivery_payload,
    approval_prompt_flow,
    queue_blocked_approvals,
    wait_for_approval_requests,
)
from ..bridge import (
    BridgeConfig,
    GuardBridge,
    HermesBackend,
    TelegramBackend,
    WebhookBackend,
)
from ..config import load_guard_config, overlay_synced_guard_policy, resolve_guard_home
from ..consumer import (
    artifact_hash,
    detect_all,
    detect_harness,
    evaluate_detection,
    record_policy,
    run_consumer_scan,
)
from ..daemon import GuardDaemonServer, ensure_guard_daemon, load_guard_surface_daemon_client
from ..daemon.manager import load_guard_daemon_auth_token
from ..incident import build_incident_context
from ..mcp_tool_calls import (
    allow_tool_call,
    block_tool_call,
    build_tool_call_artifact,
    build_tool_call_hash,
    evaluate_tool_call,
)
from ..models import GuardArtifact, HarnessDetection, PolicyDecision
from ..policy.engine import SAFE_CHANGED_HASH_ACTION, VALID_GUARD_ACTIONS
from ..protect import build_protect_payload
from ..proxy import (
    CodexMcpGuardProxy,
    CopilotMcpGuardProxy,
    OpenCodeMcpGuardProxy,
    RemoteGuardProxy,
    StdioGuardProxy,
)
from ..receipts import build_receipt
from ..risk import artifact_risk_signals, artifact_risk_summary
from ..runtime.runner import (
    GuardSyncNotConfiguredError,
    extract_prompt_requests,
    guard_run,
    prompt_requests_to_artifacts,
    sync_receipts,
)
from ..runtime.secret_file_requests import (
    build_file_read_request_artifact,
    build_tool_action_request_artifact,
    extract_sensitive_file_read_request,
    extract_sensitive_tool_action_request,
)
from ..runtime.surface_server import GuardSurfaceRuntime
from ..store import GuardStore
from .approval_commands import add_approval_parser, run_approval_command
from .bootstrap import DEFAULT_ALIAS_NAME, build_guard_bootstrap_payload
from .connect_flow import (
    DEFAULT_GUARD_CONNECT_URL,
    DEFAULT_GUARD_SYNC_URL,
    run_guard_connect_command,
)
from .install_commands import apply_managed_install
from .product import build_guard_start_payload, build_guard_status_payload
from .update_commands import run_guard_update

_GUARD_CLIENT_VERSION = "2.0.0"
_GUARD_HELP_GROUPS = (
    "Everyday protection:\n"
    "  start        First-run setup and the Guard operating loop\n"
    "  status       Current local protection state and next actions\n"
    "  run          Enforce Guard before a harness launch\n"
    "  approvals    Resolve the current request queue\n"
    "  receipts     Review recent local decisions\n"
    "\n"
    "Team and cloud coordination:\n"
    "  connect      Pair this machine to Guard Cloud\n"
    "  login        Compatibility alias for browser pairing\n"
    "  sync         Send local decisions to Guard Cloud\n"
    "  device       Inspect or rotate this machine identity\n"
    "  bridge       Forward Guard signals to external channels\n"
    "\n"
    "Advanced and diagnostics:\n"
    "  detect       Discover harnesses and managed artifacts\n"
    "  protect      Wrap installs before they land\n"
    "  preflight    Scan a target before you add it\n"
    "  scan         Run a consumer-mode artifact scan\n"
    "  diff         Compare current artifacts to stored snapshots\n"
    "  inventory    Inspect tracked artifacts\n"
    "  abom         Export the local AI-BOM\n"
    "  explain      Show evidence for one artifact\n"
    "  policies     Inspect local Guard policy state\n"
    "  exceptions   Inspect active exception windows\n"
    "  advisories   Inspect cached Guard Cloud advisories\n"
    "  events       Review Guard lifecycle events\n"
    "  doctor       Run local diagnostics\n"
    "  bootstrap    Detect, install, and launch the approval center\n"
    "  install      Enable Guard management for a harness\n"
    "  uninstall    Disable Guard management for a harness\n"
    "  update       Update hol-guard in the current environment"
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def add_guard_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register Guard as a nested command family."""

    program_name = Path(sys.argv[0]).name or "plugin-scanner"
    guard_parser = subparsers.add_parser(
        "guard",
        help="Run local harness protection workflows",
        description=(
            "HOL Guard watches local harness config, records approval receipts, and keeps "
            "Home, Inbox, and Fleet aligned with what this machine is doing."
        ),
        epilog=(
            "Examples:\n"
            f"  {program_name} guard detect\n"
            f"  {program_name} guard doctor cursor\n"
            f"  {program_name} guard run codex --dry-run\n"
            f"  {program_name} guard install claude --workspace .\n\n"
            f"{_GUARD_HELP_GROUPS}"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _configure_guard_parser(guard_parser)


def add_guard_root_parser(parser: argparse.ArgumentParser) -> None:
    """Register Guard as the top-level CLI surface."""

    parser.description = "Protect local harnesses before new or changed tools run."
    parser.epilog = _GUARD_HELP_GROUPS
    parser.set_defaults(command="guard")
    _configure_guard_parser(parser)


def _configure_guard_parser(guard_parser: argparse.ArgumentParser) -> None:
    """Attach Guard subcommands to a parser."""
    guard_subparsers = guard_parser.add_subparsers(
        dest="guard_command",
        required=True,
        parser_class=FriendlyArgumentParser,
        metavar=(
            "{start,status,bootstrap,detect,install,update,uninstall,run,protect,preflight,scan,diff,receipts,inventory,abom,"
            "approvals,explain,allow,deny,policies,exceptions,advisories,events,doctor,connect,login,sync,device,bridge}"
        ),
    )

    start_parser = guard_subparsers.add_parser("start", help="Show the first Guard steps for a local harness")
    _add_guard_common_args(start_parser)
    start_parser.add_argument("--json", action="store_true")

    status_parser = guard_subparsers.add_parser("status", help="Show current Guard protection status")
    _add_guard_common_args(status_parser)
    status_parser.add_argument("--json", action="store_true")

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
    protect_parser.add_argument("--json", action="store_true")
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
    _add_guard_cisco_mode_arg(scan_parser)

    diff_parser = guard_subparsers.add_parser("diff", help="Compare current harness artifacts to stored snapshots")
    diff_parser.add_argument("harness")
    _add_guard_common_args(diff_parser)
    diff_parser.add_argument("--json", action="store_true")

    receipts_parser = guard_subparsers.add_parser("receipts", help="List local Guard receipts")
    _add_guard_common_args(receipts_parser)
    receipts_parser.add_argument("--json", action="store_true")

    inventory_parser = guard_subparsers.add_parser("inventory", help="List the local Guard artifact inventory")
    _add_guard_common_args(inventory_parser)
    inventory_parser.add_argument("--json", action="store_true")

    abom_parser = guard_subparsers.add_parser("abom", help="Export a local Guard artifact bill of materials")
    _add_guard_common_args(abom_parser)
    abom_parser.add_argument("--json", action="store_true")
    abom_parser.add_argument("--format", choices=("markdown", "json"), default="markdown")

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

    policies_parser = guard_subparsers.add_parser("policies", help="List stored Guard policy decisions")
    policies_parser.add_argument("--harness")
    _add_guard_common_args(policies_parser)
    policies_parser.add_argument("--json", action="store_true")

    exceptions_parser = guard_subparsers.add_parser("exceptions", help="List active Guard exceptions with expiry")
    exceptions_parser.add_argument("--harness")
    _add_guard_common_args(exceptions_parser)
    exceptions_parser.add_argument("--json", action="store_true")

    advisories_parser = guard_subparsers.add_parser("advisories", help="List cached Guard advisories and verdicts")
    _add_guard_common_args(advisories_parser)
    advisories_parser.add_argument("--json", action="store_true")

    events_parser = guard_subparsers.add_parser("events", help="List local Guard lifecycle events")
    _add_guard_common_args(events_parser)
    events_parser.add_argument("--name")
    events_parser.add_argument("--json", action="store_true")

    doctor_parser = guard_subparsers.add_parser("doctor", help="Emit Guard diagnostics for a harness")
    doctor_parser.add_argument("harness", nargs="?")
    _add_guard_common_args(doctor_parser)
    doctor_parser.add_argument("--json", action="store_true")

    login_parser = guard_subparsers.add_parser(
        "login",
        help="Compatibility alias for Guard Cloud sign-in and pairing",
    )
    login_parser.add_argument("--sync-url", type=_guard_http_url)
    login_parser.add_argument("--token")
    login_parser.add_argument("--connect-url", default=DEFAULT_GUARD_CONNECT_URL, type=_guard_http_url)
    login_parser.add_argument("--wait-timeout-seconds", type=int, default=180)
    login_parser.add_argument("--home")
    login_parser.add_argument("--guard-home")
    login_parser.add_argument("--json", action="store_true")

    connect_parser = guard_subparsers.add_parser(
        "connect",
        help="Open the browser, pair this runtime to HOL Guard, and send the first sync",
    )
    _add_guard_common_args(connect_parser)
    connect_parser.add_argument("--sync-url", default=DEFAULT_GUARD_SYNC_URL, type=_guard_http_url)
    connect_parser.add_argument("--connect-url", default=DEFAULT_GUARD_CONNECT_URL, type=_guard_http_url)
    connect_parser.add_argument("--wait-timeout-seconds", type=int, default=180)
    connect_parser.add_argument("--json", action="store_true")

    sync_parser = guard_subparsers.add_parser("sync", help="Sync receipts to the configured Guard endpoint")
    sync_parser.add_argument("--home")
    sync_parser.add_argument("--guard-home")
    sync_parser.add_argument("--json", action="store_true")

    device_parser = guard_subparsers.add_parser("device", help="Manage local Guard installation identity")
    _add_guard_common_args(device_parser)
    device_parser.add_argument("--json", action="store_true")
    device_subparsers = device_parser.add_subparsers(
        dest="device_command",
        required=True,
        parser_class=FriendlyArgumentParser,
    )

    device_show_parser = device_subparsers.add_parser("show", help="Show local installation ID and label")
    device_show_parser.add_argument("--json", action="store_true")

    device_rotate_parser = device_subparsers.add_parser("rotate", help="Rotate local installation ID")
    device_rotate_parser.add_argument("--json", action="store_true")

    device_label_parser = device_subparsers.add_parser("label", help="Manage local device label")
    device_label_parser.add_argument("--json", action="store_true")
    device_label_subparsers = device_label_parser.add_subparsers(
        dest="device_label_command",
        required=True,
        parser_class=FriendlyArgumentParser,
    )
    device_label_set_parser = device_label_subparsers.add_parser("set", help="Set local device label")
    device_label_set_parser.add_argument("label")
    device_label_set_parser.add_argument("--json", action="store_true")

    # Bridge command
    bridge_parser = guard_subparsers.add_parser("bridge", help="Start the Guard Bridge notification daemon")
    bridge_parser.add_argument(
        "--poll-interval", type=int, default=10, help="Polling interval in seconds (default: 10)"
    )
    bridge_parser.add_argument("--guard-url", default="http://127.0.0.1:4999", help="Guard daemon URL")
    bridge_parser.add_argument("--telegram-token", help="Telegram bot token for notifications")
    bridge_parser.add_argument("--telegram-chat-id", help="Telegram chat ID for notifications")
    bridge_parser.add_argument("--webhook-url", help="Webhook URL for notifications")
    bridge_parser.add_argument("--hermes-chat-id", help="Hermes chat ID for notifications")
    bridge_parser.add_argument("--dry-run", action="store_true", help="Log notifications without sending")
    _add_guard_common_args(bridge_parser)

    hook_parser = guard_subparsers.add_parser("hook", help=argparse.SUPPRESS)
    _add_guard_common_args(hook_parser)
    hook_parser.add_argument("--harness", default="claude-code")
    hook_parser.add_argument("--artifact-id")
    hook_parser.add_argument("--artifact-name")
    hook_parser.add_argument(
        "--policy-action",
        choices=("allow", "warn", "review", "block", "sandbox-required", "require-reapproval"),
    )
    hook_parser.add_argument("--event-file")
    hook_parser.add_argument("--json", action="store_true")

    daemon_parser = guard_subparsers.add_parser("daemon", help=argparse.SUPPRESS)
    _add_guard_common_args(daemon_parser)
    daemon_parser.add_argument("--serve", action="store_true")
    daemon_parser.add_argument("--port", type=int)
    daemon_parser.add_argument("--json", action="store_true")

    codex_proxy_parser = guard_subparsers.add_parser("codex-mcp-proxy", help=argparse.SUPPRESS)
    _add_guard_common_args(codex_proxy_parser)
    codex_proxy_parser.add_argument("--server-name", required=True)
    codex_proxy_parser.add_argument("--source-scope", default="project")
    codex_proxy_parser.add_argument("--config-path", required=True)
    codex_proxy_parser.add_argument("--transport", default="stdio")
    codex_proxy_parser.add_argument("--command", dest="server_command", required=True)
    codex_proxy_parser.add_argument("--arg", dest="server_args", action="append", default=[])

    opencode_proxy_parser = guard_subparsers.add_parser("opencode-mcp-proxy", help=argparse.SUPPRESS)
    _add_guard_common_args(opencode_proxy_parser)
    opencode_proxy_parser.add_argument("--server-name", required=True)
    opencode_proxy_parser.add_argument("--source-scope", default="project")
    opencode_proxy_parser.add_argument("--config-path", required=True)
    opencode_proxy_parser.add_argument("--transport", default="local")
    opencode_proxy_parser.add_argument("--command", dest="server_command", required=True)
    opencode_proxy_parser.add_argument("--arg", dest="server_args", action="append", default=[])

    copilot_proxy_parser = guard_subparsers.add_parser("copilot-mcp-proxy", help=argparse.SUPPRESS)
    _add_guard_common_args(copilot_proxy_parser)
    copilot_proxy_parser.add_argument("--server-name", required=True)
    copilot_proxy_parser.add_argument("--source-scope", default="project")
    copilot_proxy_parser.add_argument("--config-path", required=True)
    copilot_proxy_parser.add_argument("--transport", default="stdio")
    copilot_proxy_parser.add_argument("--command", dest="server_command", required=True)
    copilot_proxy_parser.add_argument("--arg", dest="server_args", action="append", default=[])

    hermes_mcp_proxy_parser = guard_subparsers.add_parser("hermes-mcp-proxy", help=argparse.SUPPRESS)
    _add_guard_common_args(hermes_mcp_proxy_parser)
    hermes_mcp_proxy_parser.add_argument("--server", required=True)
    hermes_mcp_proxy_parser.add_argument("--stdio", action="store_true")
    hidden_commands = {
        "hook",
        "daemon",
        "codex-mcp-proxy",
        "opencode-mcp-proxy",
        "copilot-mcp-proxy",
        "hermes-mcp-proxy",
    }
    guard_subparsers._choices_actions = [
        action for action in guard_subparsers._choices_actions if action.dest not in hidden_commands
    ]


def _add_guard_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--home")
    parser.add_argument("--guard-home")
    parser.add_argument("--workspace")


def _add_guard_cisco_mode_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--cisco-mode",
        choices=("auto", "on", "off"),
        default="auto",
        help="Control optional Cisco scanner evidence for local consumer-mode artifact scans.",
    )


def _guard_http_url(value: str) -> str:
    parsed = urllib.parse.urlparse(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise argparse.ArgumentTypeError("Guard URLs must be absolute http(s) URLs.")
    return value


def _build_cisco_scan_options(mode: str) -> ScanOptions:
    return ScanOptions(cisco_skill_scan=mode, cisco_mcp_scan=mode)


def _resolve_cisco_scan_options(mode: str) -> ScanOptions | None:
    if mode == "auto":
        return None
    return _build_cisco_scan_options(mode)


def _run_consumer_scan_with_mode(
    target: Path,
    *,
    intended_harness: str | None = None,
    cisco_mode: str,
) -> dict[str, object]:
    options = _resolve_cisco_scan_options(cisco_mode)
    if options is None:
        return run_consumer_scan(target, intended_harness=intended_harness)
    return run_consumer_scan(target, intended_harness=intended_harness, options=options)


def run_guard_command(
    args: argparse.Namespace,
    *,
    input_text: str | None = None,
    output_stream: TextIO | None = None,
) -> int:
    """Execute a Guard subcommand."""

    if args.guard_command == "scan":
        payload = _run_consumer_scan_with_mode(Path(args.target).resolve(), cisco_mode=args.cisco_mode)
        _emit("scan", payload, args.json or args.consumer_mode)
        return 0

    if args.guard_command == "preflight":
        payload = _run_consumer_scan_with_mode(
            Path(args.target).resolve(),
            intended_harness=getattr(args, "harness", None),
            cisco_mode=args.cisco_mode,
        )
        _emit("preflight", payload, getattr(args, "json", False))
        if getattr(args, "enforce", False):
            install_verdict = payload.get("install_verdict")
            if isinstance(install_verdict, dict) and str(install_verdict.get("action")) != "allow":
                return 2
        return 0

    home_override = getattr(args, "home", None)
    guard_home = resolve_guard_home(getattr(args, "guard_home", None) or home_override)
    workspace = Path(args.workspace).resolve() if getattr(args, "workspace", None) else None
    context = HarnessContext(
        home_dir=Path(home_override).resolve() if home_override else Path.home().resolve(),
        workspace_dir=workspace,
        guard_home=guard_home,
    )

    if args.guard_command == "update":
        dry_run = bool(getattr(args, "dry_run", False))
        store: GuardStore | None
        update_store_error: OSError | RuntimeError | sqlite3.Error | None = None
        if dry_run:
            store = None
        else:
            try:
                store = GuardStore(guard_home)
            except (OSError, RuntimeError, sqlite3.Error) as error:
                store = None
                update_store_error = error
        payload, exit_code = run_guard_update(
            dry_run=dry_run,
            context=context,
            store=store,
            workspace=str(workspace) if workspace else None,
            now=_now(),
        )
        if update_store_error is not None:
            notes = [str(item) for item in payload.get("notes", []) if isinstance(item, str)]
            notes.append(f"Skipped local Guard repair during update: {update_store_error}")
            payload["notes"] = notes
        _emit("update", payload, getattr(args, "json", False))
        return exit_code

    store = GuardStore(guard_home)
    config = load_guard_config(guard_home, workspace=workspace)
    config = overlay_synced_guard_policy(config, _synced_policy_payload(store))

    if args.guard_command == "protect":
        _refresh_cloud_policy_bundle(store)
        protect_command = list(getattr(args, "protect_command", []) or [])
        if len(protect_command) == 0:
            print("guard protect requires a command to wrap.", file=sys.stderr)
            return 2
        payload, exit_code = build_protect_payload(
            command=protect_command,
            store=store,
            workspace_dir=workspace or Path.cwd(),
            dry_run=bool(getattr(args, "dry_run", False)),
            now=_now(),
        )
        _emit("protect", payload, getattr(args, "json", False))
        return exit_code

    if args.guard_command == "start":
        payload = build_guard_start_payload(context, store, config)
        _emit("start", payload, getattr(args, "json", False))
        return 0

    if args.guard_command == "status":
        payload = build_guard_status_payload(context, store, config)
        _emit("status", payload, getattr(args, "json", False))
        return 0

    if args.guard_command == "bootstrap":
        try:
            payload = build_guard_bootstrap_payload(
                context=context,
                store=store,
                config=config,
                requested_harness=getattr(args, "harness", None),
                skip_install=bool(getattr(args, "skip_install", False)),
                alias_name=str(getattr(args, "alias_name", DEFAULT_ALIAS_NAME)),
                write_shell_alias=bool(getattr(args, "write_shell_alias", False)),
            )
        except ValueError as error:
            print(str(error), file=sys.stderr)
            return 2
        _emit("bootstrap", payload, getattr(args, "json", False))
        return 0

    if args.guard_command == "detect":
        detections = [detect_harness(args.harness, context)] if args.harness else detect_all(context)
        payload = {
            "generated_at": _now(),
            "harnesses": [detection.to_dict() for detection in detections],
        }
        _emit("detect", payload, getattr(args, "json", False))
        return 0

    if args.guard_command == "install":
        try:
            payload = apply_managed_install(
                "install",
                args.harness,
                bool(getattr(args, "all", False)),
                context,
                store,
                str(workspace) if workspace else None,
                _now(),
            )
        except ValueError as error:
            print(str(error), file=sys.stderr)
            return 2
        _emit("install", payload, getattr(args, "json", False))
        return 0

    if args.guard_command == "codex-mcp-proxy":
        proxy = CodexMcpGuardProxy(
            server_name=args.server_name,
            command=[args.server_command, *list(args.server_args)],
            context=context,
            store=store,
            config=config,
            source_scope=args.source_scope,
            config_path=args.config_path,
            transport=args.transport,
        )
        return proxy.serve()

    if args.guard_command == "opencode-mcp-proxy":
        proxy = OpenCodeMcpGuardProxy(
            server_name=args.server_name,
            command=[args.server_command, *list(args.server_args)],
            context=context,
            store=store,
            config=config,
            source_scope=args.source_scope,
            config_path=args.config_path,
            transport=args.transport,
        )
        return proxy.serve()

    if args.guard_command == "copilot-mcp-proxy":
        proxy = CopilotMcpGuardProxy(
            server_name=args.server_name,
            command=[args.server_command, *list(args.server_args)],
            context=context,
            store=store,
            config=config,
            source_scope=args.source_scope,
            config_path=args.config_path,
            transport=args.transport,
        )
        return proxy.serve()

    if args.guard_command == "hermes-mcp-proxy":
        return _run_hermes_mcp_proxy(args=args, context=context, store=store, config=config)

    if args.guard_command == "uninstall":
        try:
            payload = apply_managed_install(
                "uninstall",
                args.harness,
                bool(getattr(args, "all", False)),
                context,
                store,
                str(workspace) if workspace else None,
                _now(),
            )
        except ValueError as error:
            print(str(error), file=sys.stderr)
            return 2
        _emit("uninstall", payload, getattr(args, "json", False))
        return 0

    if args.guard_command == "run":
        _refresh_cloud_policy_bundle(store)
        config = overlay_synced_guard_policy(config, _synced_policy_payload(store))
        interactive_resolver = None
        blocked_resolver = None
        if (
            not getattr(args, "json", False)
            and not bool(args.dry_run)
            and config.mode == "prompt"
            and sys.stdin.isatty()
        ):
            from .prompt import build_prompt_artifacts, resolve_interactive_decisions

            def interactive_resolver(detection, payload):
                return resolve_interactive_decisions(
                    store=store,
                    evaluation=payload,
                    prompt_artifacts=build_prompt_artifacts(
                        harness=detection.harness,
                        artifacts=list(detection.artifacts),
                        evaluation_artifacts=[item for item in payload.get("artifacts", []) if isinstance(item, dict)],
                    ),
                    workspace=str(workspace) if workspace else None,
                    now=_now(),
                )
        elif not bool(args.dry_run) and config.mode == "prompt":
            blocked_resolver = _headless_approval_resolver(args=args, context=context, store=store, config=config)

        payload = guard_run(
            args.harness,
            context=context,
            store=store,
            config=config,
            dry_run=bool(args.dry_run),
            passthrough_args=list(args.passthrough_args),
            default_action=args.default_action,
            interactive_resolver=interactive_resolver,
            blocked_resolver=blocked_resolver,
        )
        payload["dry_run"] = bool(args.dry_run)
        payload["rerun_command"] = _guard_rerun_command(args)
        payload["diff_command"] = _guard_diff_command(args)
        payload["approvals_command"] = _guard_approvals_command(args)
        _emit("run", payload, getattr(args, "json", False))
        if payload.get("blocked"):
            return 1
        return_code = payload.get("return_code")
        return int(return_code) if isinstance(return_code, int) else 0

    if args.guard_command == "diff":
        detection = detect_harness(args.harness, context)
        payload = evaluate_detection(detection, store, config, default_action="allow", persist=False)
        changed_artifacts = [item for item in payload["artifacts"] if bool(item["changed"])]
        payload["artifacts"] = changed_artifacts
        payload["changed"] = bool(changed_artifacts)
        _emit("diff", payload, getattr(args, "json", False))
        return 0

    if args.guard_command == "receipts":
        _emit("receipts", {"generated_at": _now(), "items": store.list_receipts()}, getattr(args, "json", False))
        return 0

    if args.guard_command == "inventory":
        _emit("inventory", {"generated_at": _now(), "items": store.list_inventory()}, getattr(args, "json", False))
        return 0

    if args.guard_command == "abom":
        payload = _build_abom_payload(store)
        if args.format == "markdown" and not getattr(args, "json", False):
            print(payload["markdown"])
            return 0
        _emit("abom", payload, True)
        return 0

    if args.guard_command == "policies":
        policy_items = store.list_policy_decisions(getattr(args, "harness", None))
        items = _filter_policy_items(policy_items, active_only=True)
        _emit("policies", {"generated_at": _now(), "items": items}, getattr(args, "json", False))
        return 0

    if args.guard_command == "exceptions":
        policy_items = store.list_policy_decisions(getattr(args, "harness", None))
        active_items = _filter_policy_items(policy_items, active_only=True)
        items = [
            item for item in active_items if isinstance(item.get("expires_at"), str) and str(item["expires_at"]).strip()
        ]
        _emit("exceptions", {"generated_at": _now(), "items": items}, getattr(args, "json", False))
        return 0

    if args.guard_command == "advisories":
        _emit(
            "advisories",
            {"generated_at": _now(), "items": store.list_cached_advisories()},
            getattr(args, "json", False),
        )
        return 0

    if args.guard_command == "events":
        _emit(
            "events",
            {"generated_at": _now(), "items": store.list_events(event_name=getattr(args, "name", None))},
            getattr(args, "json", False),
        )
        return 0

    if args.guard_command == "approvals":
        payload = run_approval_command(args, store=store, workspace=workspace)
        _emit("approvals", payload, getattr(args, "json", False))
        return 0

    if args.guard_command == "explain":
        payload = _build_explain_payload_with_mode(store, args.target, cisco_mode=args.cisco_mode)
        _emit("explain", payload, getattr(args, "json", False))
        return 0

    if args.guard_command in {"allow", "deny"}:
        _validate_policy_scope(args.scope, args.artifact_id, workspace, getattr(args, "publisher", None))
        expires_at = _resolve_policy_expiry(args)
        payload = record_policy(
            store=store,
            harness=args.harness,
            action=args.policy_action,
            scope=args.scope,
            artifact_id=args.artifact_id,
            workspace=str(workspace) if workspace else None,
            publisher=getattr(args, "publisher", None),
            reason=args.reason,
            owner=getattr(args, "owner", None),
            expires_at=expires_at,
        )
        _emit(args.guard_command, {"decision": payload}, getattr(args, "json", False))
        return 0

    if args.guard_command == "doctor":
        if args.harness:
            adapter = get_adapter(args.harness)
            payload = adapter.diagnostics(context)
        else:
            payload = {
                "tables": store.list_table_names(),
                "adapters": [detection.to_dict() for detection in detect_all(context)],
            }
        _emit("doctor", payload, getattr(args, "json", False))
        return 0

    if args.guard_command == "login":
        manual_login = _manual_guard_login_payload(args=args, store=store)
        if manual_login is not None:
            payload, exit_code = manual_login
            if payload is not None:
                _emit("login", payload, getattr(args, "json", False))
            return exit_code
        try:
            payload = _run_guard_connect_flow(
                guard_home=guard_home,
                store=store,
                sync_url=getattr(args, "sync_url", None) or DEFAULT_GUARD_SYNC_URL,
                connect_url=args.connect_url,
                wait_timeout_seconds=args.wait_timeout_seconds,
            )
        except ValueError as error:
            print(str(error), file=sys.stderr)
            return 2
        except RuntimeError as error:
            print(str(error), file=sys.stderr)
            return 1
        _emit("connect", payload, getattr(args, "json", False))
        return 0 if bool(payload.get("connected")) else 1

    if args.guard_command == "connect":
        try:
            payload = _run_guard_connect_flow(
                guard_home=guard_home,
                store=store,
                sync_url=args.sync_url,
                connect_url=args.connect_url,
                wait_timeout_seconds=args.wait_timeout_seconds,
            )
        except ValueError as error:
            print(str(error), file=sys.stderr)
            return 2
        except RuntimeError as error:
            print(str(error), file=sys.stderr)
            return 1
        _emit("connect", payload, getattr(args, "json", False))
        return 0 if bool(payload.get("connected")) else 1

    if args.guard_command == "bridge":
        poll_interval = getattr(args, "poll_interval", 10) or 10
        guard_url = getattr(args, "guard_url", None)
        dry_run = getattr(args, "dry_run", False)

        backend = None
        telegram_token = getattr(args, "telegram_token", None)
        telegram_chat_id = getattr(args, "telegram_chat_id", None)
        webhook_url = getattr(args, "webhook_url", None)
        hermes_chat_id = getattr(args, "hermes_chat_id", None)

        if telegram_token and telegram_chat_id:
            backend = TelegramBackend(telegram_token, telegram_chat_id)
        elif webhook_url:
            backend = WebhookBackend(webhook_url)
        elif hermes_chat_id:
            backend = HermesBackend(hermes_chat_id)

        config = BridgeConfig(guard_url=guard_url, poll_interval=poll_interval, dry_run=dry_run)
        bridge = GuardBridge(config=config, store=store, backend=backend)
        bridge.run()
        return 0

    if args.guard_command == "sync":
        try:
            payload = sync_receipts(store)
        except GuardSyncNotConfiguredError:
            message = _guard_sync_prerequisite_message()
            if getattr(args, "json", False):
                _emit("sync", {"synced": False, "error": message}, True)
            else:
                print(message, file=sys.stderr)
            return 1
        except RuntimeError as error:
            if getattr(args, "json", False):
                _emit("sync", {"synced": False, "error": str(error)}, True)
            else:
                print(str(error), file=sys.stderr)
            return 1
        _emit("sync", payload, getattr(args, "json", False))
        return 0

    if args.guard_command == "device":
        command = getattr(args, "device_command", None)
        now = _now()
        if command == "show":
            payload = {"device": store.get_device_metadata()}
            _emit("device", payload, getattr(args, "json", False))
            return 0
        if command == "rotate":
            metadata = store.rotate_installation_id(now)
            store.add_event("device_rotated", {"installation_id": metadata["installation_id"]}, now)
            _emit("device", {"device": metadata, "rotated": True}, getattr(args, "json", False))
            return 0
        if command == "label":
            label_command = getattr(args, "device_label_command", None)
            if label_command != "set":
                print("device label subcommand is required", file=sys.stderr)
                return 2
            metadata = store.set_device_label(getattr(args, "label", ""), now)
            store.add_event("device_labeled", {"device_label": metadata["device_label"]}, now)
            _emit("device", {"device": metadata, "updated": True}, getattr(args, "json", False))
            return 0
        print("device subcommand is required", file=sys.stderr)
        return 2

    if args.guard_command == "daemon":
        daemon = GuardDaemonServer(store, port=args.port or 0)
        if args.serve:
            daemon.serve()
            return 0
        _emit("doctor", {"daemon_url": f"http://127.0.0.1:{daemon.port}"}, getattr(args, "json", False))
        return 0

    if args.guard_command == "hook":
        payload = _load_hook_payload(getattr(args, "event_file", None), input_text=input_text)
        managed_install = _managed_install_for(store, args.harness)
        payload_cwd = payload.get("cwd")
        workspace_was_explicit = workspace is not None
        runtime_workspace = workspace
        if runtime_workspace is None and isinstance(payload_cwd, str) and payload_cwd.strip():
            runtime_workspace = Path(payload_cwd).expanduser().resolve()
        if args.harness == "copilot":
            runtime_workspace = _resolve_copilot_workspace_root(runtime_workspace)
        copilot_hook_stage = _copilot_hook_stage(payload) if args.harness == "copilot" else None
        copilot_runtime_tool_call = (
            _copilot_runtime_tool_call(
                payload=payload,
                home_dir=context.home_dir,
                workspace=runtime_workspace,
                preferred_workspace_config="ide" if workspace_was_explicit else "cli",
            )
            if args.harness == "copilot"
            else None
        )
        if copilot_runtime_tool_call is not None and copilot_hook_stage == "pretooluse":
            runtime_artifact, runtime_artifact_hash, runtime_arguments = copilot_runtime_tool_call
            decision = evaluate_tool_call(
                store=store,
                config=config,
                artifact=runtime_artifact,
                artifact_hash=runtime_artifact_hash,
                arguments=runtime_arguments,
            )
            policy_action = {
                "allow": "allow",
                "warn": "allow",
                "review": "require-reapproval",
                "block": "block",
                "sandbox-required": "sandbox-required",
                "require-reapproval": "require-reapproval",
            }.get(decision.action, "require-reapproval")
            now = _now()
            if policy_action == "allow":
                allow_tool_call(
                    store=store,
                    artifact=runtime_artifact,
                    artifact_hash=runtime_artifact_hash,
                    decision_source="pre-tool-hook",
                    now=now,
                    signals=decision.signals,
                    remember=False,
                )
                if _should_emit_copilot_hook_response(args):
                    _emit_copilot_hook_response(policy_action="allow", reason="", output_stream=output_stream)
                    return 0
            else:
                if policy_action in {"block", "sandbox-required"}:
                    block_tool_call(
                        store=store,
                        artifact=runtime_artifact,
                        artifact_hash=runtime_artifact_hash,
                        decision_source="pre-tool-hook",
                        now=now,
                        signals=decision.signals,
                    )
                if _should_emit_copilot_hook_response(args):
                    _emit_copilot_hook_response(
                        policy_action=policy_action,
                        reason=_copilot_hook_reason(decision.summary, runtime_artifact.name),
                        output_stream=output_stream,
                    )
                    return 0
        copilot_permission_request = (
            _copilot_runtime_tool_call(
                payload=payload,
                home_dir=context.home_dir,
                workspace=runtime_workspace,
                preferred_workspace_config="ide" if workspace_was_explicit else "cli",
            )
            if args.harness == "copilot" and _is_copilot_permission_request(payload)
            else None
        )
        if copilot_permission_request is not None:
            runtime_artifact, runtime_artifact_hash, runtime_arguments = copilot_permission_request
            artifact_id = runtime_artifact.artifact_id
            artifact_name = runtime_artifact.name
            decision = evaluate_tool_call(
                store=store,
                config=config,
                artifact=runtime_artifact,
                artifact_hash=runtime_artifact_hash,
                arguments=runtime_arguments,
            )
            policy_action = {
                "allow": "allow",
                "warn": "allow",
                "review": "require-reapproval",
                "block": "block",
                "sandbox-required": "sandbox-required",
                "require-reapproval": "require-reapproval",
            }.get(decision.action, "require-reapproval")
            runtime_detection = _runtime_detection(args.harness, runtime_artifact)
            evaluation_payload = {
                "artifacts": [
                    {
                        "artifact_id": artifact_id,
                        "artifact_name": artifact_name,
                        "artifact_hash": runtime_artifact_hash,
                        "policy_action": policy_action,
                        "changed_fields": ["runtime_tool_call", *decision.signals],
                        "artifact_type": runtime_artifact.artifact_type,
                        "source_scope": runtime_artifact.source_scope,
                        "config_path": runtime_artifact.config_path,
                        "launch_target": json.dumps(runtime_arguments, sort_keys=True)
                        if runtime_arguments is not None
                        else runtime_artifact.command,
                    }
                ]
            }
            now = _now()
            response_payload = {
                "recorded": True,
                "harness": _canonical_harness_name(args.harness),
                "artifact_id": artifact_id,
                "artifact_name": artifact_name,
                "artifact_type": runtime_artifact.artifact_type,
                "policy_action": policy_action,
                "risk_signals": list(decision.signals),
                "risk_summary": decision.summary,
                "launch_summary": json.dumps(runtime_arguments, sort_keys=True)
                if runtime_arguments is not None
                else runtime_artifact.command,
            }
            if policy_action == "allow":
                allow_tool_call(
                    store=store,
                    artifact=runtime_artifact,
                    artifact_hash=runtime_artifact_hash,
                    decision_source=decision.source,
                    now=now,
                    signals=decision.signals,
                    remember=False,
                )
                if _should_emit_copilot_hook_response(args):
                    _emit_copilot_permission_request_response(behavior="allow", output_stream=output_stream)
                    return 0
                _emit("hook", response_payload, getattr(args, "json", False))
                return 0
            block_tool_call(
                store=store,
                artifact=runtime_artifact,
                artifact_hash=runtime_artifact_hash,
                decision_source="permission-request-hook",
                now=now,
                signals=decision.signals,
            )
            approval_center_url = ensure_guard_daemon(guard_home)
            approval_flow = get_adapter(args.harness).approval_flow(managed_install=managed_install)
            try:
                daemon_client = load_guard_surface_daemon_client(guard_home)
            except RuntimeError:
                queued = queue_blocked_approvals(
                    detection=runtime_detection,
                    evaluation=evaluation_payload,
                    store=store,
                    approval_center_url=approval_center_url,
                    now=now,
                )
            else:
                session = daemon_client.start_session(
                    harness=args.harness,
                    surface="harness-adapter",
                    workspace=str(runtime_workspace) if runtime_workspace else None,
                    client_name=f"{args.harness}-permission-hook",
                    client_title=f"{args.harness} permission hook",
                    client_version="1.0.0",
                    capabilities=["approval-resolution", "receipt-view"],
                )
                blocked_operation = daemon_client.queue_blocked_operation(
                    session_id=str(session["session_id"]),
                    operation_type="tool_call",
                    harness=args.harness,
                    metadata={
                        "tool_name": str(payload.get("tool_name", "")),
                        "hook_name": "permissionRequest",
                    },
                    detection=runtime_detection.to_dict(),
                    evaluation=evaluation_payload,
                    approval_center_url=approval_center_url,
                    approval_surface_policy=_approval_surface_policy_for_flow(
                        config.approval_surface_policy,
                        approval_flow,
                    ),
                    open_key=artifact_id,
                )
                queued = (
                    blocked_operation["approval_requests"]
                    if isinstance(blocked_operation.get("approval_requests"), list)
                    else []
                )
            response_payload["approval_requests"] = queued
            response_payload["approval_center_url"] = approval_center_url
            response_payload["review_hint"] = approval_center_hint(
                context=context,
                harness=args.harness,
                approval_center_url=approval_center_url,
                queued=queued,
                managed_install=managed_install,
            )
            if _should_emit_copilot_hook_response(args):
                _emit_copilot_permission_request_response(
                    behavior="deny",
                    message=(
                        f"HOL Guard blocked {artifact_name}. {decision.summary} "
                        f"Approve the exact call in Guard, then retry."
                    ),
                    interrupt=True,
                    output_stream=output_stream,
                )
                return 0
            _emit("hook", response_payload, getattr(args, "json", False))
            return 1
        runtime_artifact = _hook_runtime_artifact(
            harness=args.harness,
            payload=payload,
            home_dir=context.home_dir,
            guard_home=context.guard_home,
            workspace=runtime_workspace,
        )
        if _is_claude_permission_request(args, payload):
            notice = _peek_claude_permission_notice(store, payload)
            if notice is None:
                _emit_claude_permission_request_passthrough(output_stream=output_stream)
                return 0
            _mark_claude_pending_permission_prompt_seen(store=store, payload=payload, notice=notice)
            _emit_native_hook_response(
                harness=args.harness,
                policy_action="require-reapproval",
                event_name="PermissionRequest",
                reason="HOL Guard is keeping Claude's native permission prompt open for user review.",
                system_message=_claude_permission_prompt_system_message(payload=payload, notice=notice),
                additional_context=_claude_permission_prompt_additional_context(notice),
                output_stream=output_stream,
            )
            return 0
        if _is_claude_permission_prompt_notification(args, payload):
            notice = _load_claude_permission_notice(store, payload)
            _mark_claude_pending_permission_prompt_seen(store=store, payload=payload, notice=notice)
            store.add_event(
                "claude/permission_prompt",
                {
                    "session_id": payload.get("session_id"),
                    "notification_type": payload.get("notification_type"),
                    "tool_name": payload.get("tool_name"),
                    "notice": notice or {},
                },
                _now(),
            )
            system_message = _claude_permission_prompt_system_message(payload=payload, notice=notice)
            additional_context = _claude_permission_prompt_additional_context(notice)
            if not getattr(args, "json", False):
                _emit_native_hook_notification_stderr(
                    _claude_permission_prompt_terminal_notice(payload=payload, notice=notice)
                )
            _emit_native_hook_response(
                harness=args.harness,
                policy_action="allow",
                event_name="Notification",
                reason="HOL Guard intercepted the tool request and opened this Claude approval prompt.",
                system_message=system_message,
                additional_context=additional_context,
                output_stream=output_stream,
            )
            return 0
        if _canonical_harness_name(args.harness) == "claude-code" and _hook_event_name(payload) == "Stop":
            denied = _persist_claude_pending_permission_denials(store, payload)
            store.add_event(
                "claude/turn_stop",
                {"session_id": payload.get("session_id"), "saved_denials": denied},
                _now(),
            )
            return 0
        if runtime_artifact is not None:
            event_name = _hook_event_name(payload) or "PreToolUse"
            runtime_artifact_hash = artifact_hash(runtime_artifact)
            artifact_id = runtime_artifact.artifact_id
            artifact_name = runtime_artifact.name
            policy_harness = _canonical_harness_name(args.harness)
            stored_policy_action = store.resolve_policy(
                policy_harness,
                artifact_id,
                runtime_artifact_hash,
                str(runtime_workspace) if runtime_workspace else None,
            )
            if stored_policy_action is None:
                legacy_artifact = _legacy_claude_alias_runtime_artifact(
                    artifact=runtime_artifact,
                    requested_harness=args.harness,
                    home_dir=context.home_dir,
                    workspace=runtime_workspace,
                )
                if legacy_artifact is not None:
                    stored_policy_action = store.resolve_policy(
                        args.harness,
                        legacy_artifact.artifact_id,
                        artifact_hash(legacy_artifact),
                        str(runtime_workspace) if runtime_workspace else None,
                    )
            policy_action = _coalesce_string(
                getattr(args, "policy_action", None),
                stored_policy_action,
                payload.get("policy_action"),
            )
            if policy_action not in VALID_GUARD_ACTIONS:
                policy_action = SAFE_CHANGED_HASH_ACTION
            if _canonical_harness_name(args.harness) == "claude-code" and event_name in {
                "PostToolUse",
                "PostToolUseFailure",
            }:
                saved = _persist_claude_native_permission_for_runtime_artifact(
                    store=store,
                    payload=payload,
                    artifact=runtime_artifact,
                    artifact_hash=runtime_artifact_hash,
                    action="allow",
                    reason="Approved in Claude native approval prompt.",
                )
                if saved:
                    receipt = build_receipt(
                        harness=policy_harness,
                        artifact_id=artifact_id,
                        artifact_hash=runtime_artifact_hash,
                        policy_decision="allow",
                        capabilities_summary=_runtime_capabilities_summary(runtime_artifact),
                        changed_capabilities=[runtime_artifact.artifact_type, "claude-native-approved"],
                        provenance_summary=f"runtime tool request approved from {runtime_artifact.config_path}",
                        artifact_name=artifact_name,
                        source_scope=runtime_artifact.source_scope,
                        user_override="claude-native-approve",
                    )
                    store.add_receipt(receipt)
                return 0
            changed_capabilities = [runtime_artifact.artifact_type]
            risk_signals = list(artifact_risk_signals(runtime_artifact))
            risk_summary = artifact_risk_summary(runtime_artifact)
            incident = build_incident_context(
                harness=args.harness,
                artifact=runtime_artifact,
                artifact_id=artifact_id,
                artifact_name=artifact_name,
                artifact_type=runtime_artifact.artifact_type,
                source_scope=runtime_artifact.source_scope,
                config_path=runtime_artifact.config_path,
                changed_fields=changed_capabilities,
                policy_action=policy_action,  # type: ignore[arg-type]
                launch_target=_runtime_request_summary(runtime_artifact),
                risk_summary=risk_summary,
            )
            receipt = build_receipt(
                harness=args.harness,
                artifact_id=artifact_id,
                artifact_hash=runtime_artifact_hash,
                policy_decision=policy_action,
                capabilities_summary=_runtime_capabilities_summary(runtime_artifact),
                changed_capabilities=changed_capabilities,
                provenance_summary=f"runtime tool request evaluated from {runtime_artifact.config_path}",
                artifact_name=artifact_name,
                source_scope=runtime_artifact.source_scope,
                user_override=_optional_string(payload.get("user_override")),
            )
            store.add_receipt(receipt)
            response_payload = {
                "recorded": True,
                "harness": _canonical_harness_name(args.harness),
                "artifact_id": artifact_id,
                "artifact_name": artifact_name,
                "artifact_type": runtime_artifact.artifact_type,
                "policy_action": policy_action,
                "risk_signals": risk_signals,
                "risk_summary": risk_summary,
                "artifact_label": incident["artifact_label"],
                "source_label": incident["source_label"],
                "trigger_summary": incident["trigger_summary"],
                "why_now": incident["why_now"],
                "launch_summary": incident["launch_summary"],
                "risk_headline": incident["risk_headline"],
                "path_summary": _runtime_requested_path(runtime_artifact),
            }
            if (
                _canonical_harness_name(args.harness) == "claude-code"
                and event_name == "UserPromptSubmit"
                and policy_action == "require-reapproval"
                and not _prompt_requires_hard_block(runtime_artifact)
                and (not getattr(args, "json", False) or output_stream is not None)
            ):
                return 0
            if policy_action in {"block", "sandbox-required", "require-reapproval"}:
                native_reason = _runtime_artifact_native_reason(runtime_artifact, response_payload)
                additional_context = _claude_prompt_additional_context(
                    harness=args.harness,
                    event_name=event_name,
                    policy_action=policy_action,
                    artifact=runtime_artifact,
                    native_reason=native_reason,
                )
                if (
                    _canonical_harness_name(args.harness) == "claude-code"
                    and event_name == "PreToolUse"
                    and policy_action == "require-reapproval"
                ):
                    _record_claude_permission_notice(
                        store=store,
                        payload=payload,
                        reason=native_reason,
                        artifact=runtime_artifact,
                        artifact_hash=runtime_artifact_hash,
                    )
                if _should_emit_copilot_hook_response(args):
                    _emit_copilot_hook_response(
                        policy_action=policy_action,
                        reason=_copilot_hook_reason(
                            response_payload.get("why_now"),
                            response_payload.get("risk_headline"),
                            response_payload.get("path_summary"),
                        ),
                        output_stream=output_stream,
                    )
                    return 0
                if _should_emit_prequeue_native_hook_response(args, output_stream=output_stream):
                    if _should_emit_claude_native_pretooluse_notice(
                        args,
                        event_name=event_name,
                        policy_action=policy_action,
                    ):
                        _emit_native_hook_notification_stderr(
                            _claude_native_pretooluse_terminal_notice(payload=payload, reason=native_reason)
                        )
                    system_message = None
                    if _canonical_harness_name(args.harness) == "claude-code":
                        system_message = _claude_prompt_system_message(
                            event_name=event_name,
                            policy_action=policy_action,
                            artifact=runtime_artifact,
                            native_reason=native_reason,
                        )
                    _emit_native_hook_response(
                        harness=args.harness,
                        policy_action=policy_action,
                        event_name=event_name,
                        reason=native_reason,
                        system_message=system_message,
                        additional_context=additional_context,
                        output_stream=output_stream,
                    )
                    return 0
                approval_flow = get_adapter(args.harness).approval_flow(managed_install=managed_install)
                approval_center_url = ensure_guard_daemon(guard_home)
                runtime_detection = _runtime_detection(args.harness, runtime_artifact)
                evaluation_payload = {
                    "artifacts": [
                        {
                            "artifact_id": artifact_id,
                            "artifact_name": artifact_name,
                            "artifact_hash": runtime_artifact_hash,
                            "policy_action": policy_action,
                            "changed_fields": changed_capabilities,
                            "artifact_type": runtime_artifact.artifact_type,
                            "source_scope": runtime_artifact.source_scope,
                            "config_path": runtime_artifact.config_path,
                            "launch_target": _runtime_request_summary(runtime_artifact),
                        }
                    ]
                }
                try:
                    daemon_client = load_guard_surface_daemon_client(guard_home)
                except RuntimeError:
                    queued = queue_blocked_approvals(
                        detection=runtime_detection,
                        evaluation=evaluation_payload,
                        store=store,
                        approval_center_url=approval_center_url,
                        now=_now(),
                    )
                else:
                    session = daemon_client.start_session(
                        harness=args.harness,
                        surface="harness-adapter",
                        workspace=str(workspace) if workspace else None,
                        client_name=f"{args.harness}-hook",
                        client_title=f"{args.harness} hook",
                        client_version="1.0.0",
                        capabilities=["approval-resolution", "receipt-view"],
                    )
                    response_payload["session_id"] = str(session["session_id"])
                    blocked_operation = daemon_client.queue_blocked_operation(
                        session_id=str(session["session_id"]),
                        operation_type="tool_call",
                        harness=args.harness,
                        metadata={
                            "tool_name": str(payload.get("tool_name", "")),
                            "event": str(payload.get("event", "")),
                        },
                        detection=runtime_detection.to_dict(),
                        evaluation=evaluation_payload,
                        approval_center_url=approval_center_url,
                        approval_surface_policy=_approval_surface_policy_for_flow(
                            config.approval_surface_policy,
                            approval_flow,
                        ),
                        open_key=artifact_id,
                    )
                    operation = (
                        blocked_operation["operation"] if isinstance(blocked_operation.get("operation"), dict) else {}
                    )
                    queued = (
                        blocked_operation["approval_requests"]
                        if isinstance(blocked_operation.get("approval_requests"), list)
                        else []
                    )
                    response_payload["operation_id"] = str(operation["operation_id"])
                response_payload["approval_requests"] = queued
                response_payload["approval_center_url"] = approval_center_url
                response_payload["review_hint"] = approval_center_hint(
                    context=context,
                    harness=args.harness,
                    approval_center_url=approval_center_url,
                    queued=queued,
                    managed_install=managed_install,
                )
                response_payload["approval_delivery"] = _approval_delivery_payload(
                    args.harness,
                    managed_install=managed_install,
                )
            if _should_emit_copilot_hook_response(args):
                _emit_copilot_hook_response(
                    policy_action=policy_action,
                    reason=_copilot_hook_reason(
                        response_payload.get("why_now"),
                        response_payload.get("review_hint"),
                        response_payload.get("risk_headline"),
                    ),
                    output_stream=output_stream,
                )
                return 0
            if _should_emit_native_hook_exit_block(args, event_name=event_name, policy_action=policy_action):
                _emit_native_hook_block_stderr(
                    _native_hook_reason_for_harness(
                        args.harness,
                        _runtime_artifact_native_reason(runtime_artifact, response_payload),
                    )
                )
                return 2
            runtime_reason = _native_hook_reason_for_harness(
                args.harness,
                _runtime_artifact_native_reason(runtime_artifact, response_payload),
            )
            if _should_emit_claude_native_pretooluse_notice(
                args,
                event_name=event_name,
                policy_action=policy_action,
            ):
                _emit_native_hook_notification_stderr(
                    _claude_native_pretooluse_terminal_notice(payload=payload, reason=runtime_reason)
                )
            if _should_emit_native_hook_response(args) or _should_emit_native_hook_json_response(
                args,
                event_name=event_name,
                output_stream=output_stream,
            ):
                system_message = None
                if _canonical_harness_name(args.harness) == "claude-code":
                    system_message = _claude_prompt_system_message(
                        event_name=event_name,
                        policy_action=policy_action,
                        artifact=runtime_artifact,
                        native_reason=runtime_reason,
                    )
                _emit_native_hook_response(
                    harness=args.harness,
                    policy_action=policy_action,
                    event_name=event_name,
                    reason=runtime_reason,
                    system_message=system_message,
                    output_stream=output_stream,
                )
                return 0
            _emit("hook", response_payload, getattr(args, "json", False))
            return 1 if policy_action in {"block", "require-reapproval"} else 0
        artifact_id = _coalesce_string(
            getattr(args, "artifact_id", None),
            payload.get("artifact_id"),
            _artifact_id_from_event(args.harness, payload),
        )
        artifact_name = _coalesce_string(
            getattr(args, "artifact_name", None),
            payload.get("artifact_name"),
            payload.get("tool_name"),
            artifact_id,
        )
        stored_policy_action = store.resolve_policy(
            args.harness,
            artifact_id,
            str(payload.get("artifact_hash")) if isinstance(payload.get("artifact_hash"), str) else None,
            str(runtime_workspace) if runtime_workspace else None,
        )
        policy_action = _coalesce_string(
            getattr(args, "policy_action", None),
            stored_policy_action,
            payload.get("policy_action"),
            config.default_action,
        )
        if policy_action not in VALID_GUARD_ACTIONS:
            policy_action = SAFE_CHANGED_HASH_ACTION
        hook_event_name = _hook_event_name(payload) or "PreToolUse"
        changed_capabilities = _string_list(payload.get("changed_capabilities"))
        if not changed_capabilities and isinstance(payload.get("event"), str):
            changed_capabilities = [str(payload["event"])]
        should_record_generic_hook_receipt = not (
            args.harness == "codex"
            and hook_event_name == "PreToolUse"
            and policy_action not in {"block", "sandbox-required", "require-reapproval"}
        )
        if should_record_generic_hook_receipt:
            receipt = build_receipt(
                harness=args.harness,
                artifact_id=artifact_id,
                artifact_hash=str(payload.get("artifact_hash", f"hook:{artifact_id}")),
                policy_decision=policy_action,
                capabilities_summary=_coalesce_string(
                    payload.get("capabilities_summary"),
                    f"hook artifact • {args.harness}",
                ),
                changed_capabilities=changed_capabilities or ["hook"],
                provenance_summary=_coalesce_string(
                    payload.get("provenance_summary"),
                    f"hook event for {artifact_name}",
                ),
                artifact_name=artifact_name,
                source_scope=_coalesce_string(payload.get("source_scope"), "project"),
                user_override=_optional_string(payload.get("user_override")),
            )
            store.add_receipt(receipt)
        if _should_emit_copilot_hook_response(args):
            _emit_copilot_hook_response(
                policy_action=policy_action,
                reason=_copilot_hook_reason(payload.get("permission_decision_reason")),
                output_stream=output_stream,
            )
            return 0
        if _should_emit_native_hook_exit_block(args, event_name=hook_event_name, policy_action=policy_action):
            _emit_native_hook_block_stderr(
                _native_hook_reason_for_harness(args.harness, payload.get("permission_decision_reason"))
            )
            return 2
        reason = _native_hook_reason_for_harness(args.harness, payload.get("permission_decision_reason"))
        if _should_emit_claude_native_pretooluse_notice(
            args,
            event_name=hook_event_name,
            policy_action=policy_action,
        ):
            _emit_native_hook_notification_stderr(
                _claude_native_pretooluse_terminal_notice(payload=payload, reason=reason)
            )
        if _should_emit_native_hook_response(args) or _should_emit_native_hook_json_response(
            args,
            event_name=hook_event_name,
            output_stream=output_stream,
        ):
            system_message = None
            if (
                _canonical_harness_name(args.harness) == "claude-code"
                and hook_event_name in {"UserPromptSubmit", "PreToolUse"}
                and policy_action in {"block", "sandbox-required", "require-reapproval"}
            ):
                system_message = _ensure_terminal_punctuation(reason)
            _emit_native_hook_response(
                harness=args.harness,
                policy_action=policy_action,
                event_name=hook_event_name,
                reason=reason,
                system_message=system_message,
                output_stream=output_stream,
            )
            return 0
        _emit(
            "hook",
            {
                "recorded": True,
                "artifact_id": artifact_id,
                "artifact_name": artifact_name,
                "policy_action": policy_action,
            },
            getattr(args, "json", False),
        )
        return 1 if policy_action in {"block", "require-reapproval"} else 0

    return 1


def _emit(command: str, payload: dict[str, object], as_json: bool) -> None:
    from .render import emit_guard_payload

    emit_guard_payload(command, payload, as_json)


def _should_emit_copilot_hook_response(args: argparse.Namespace) -> bool:
    return args.harness == "copilot" and not getattr(args, "json", False)


def _should_emit_native_hook_response(args: argparse.Namespace) -> bool:
    return _canonical_harness_name(args.harness) in {"claude-code", "codex"} and not getattr(args, "json", False)


def _should_emit_claude_native_pretooluse_notice(
    args: argparse.Namespace,
    *,
    event_name: str,
    policy_action: str,
) -> bool:
    return (
        _canonical_harness_name(args.harness) == "claude-code"
        and not getattr(args, "json", False)
        and event_name == "PreToolUse"
        and policy_action == "require-reapproval"
    )


def _should_emit_native_hook_json_response(
    args: argparse.Namespace,
    *,
    event_name: str,
    output_stream: TextIO | None,
) -> bool:
    harness = _canonical_harness_name(args.harness)
    return (
        harness in {"claude-code", "codex"}
        and getattr(args, "json", False)
        and output_stream is not None
        and (
            event_name in {"PreToolUse", "Notification"}
            or (harness == "claude-code" and event_name == "UserPromptSubmit")
        )
    )


def _should_emit_native_hook_exit_block(args: argparse.Namespace, *, event_name: str, policy_action: str) -> bool:
    codex_runtime_marker = (
        os.environ.get("CODEX_HOME", "").strip() or os.environ.get("CODEX_MANAGED_BY_BUN", "").strip()
    )
    return (
        args.harness == "codex"
        and event_name == "PreToolUse"
        and policy_action in {"block", "sandbox-required", "require-reapproval"}
        and not getattr(args, "json", False)
        and bool(codex_runtime_marker)
    )


def _should_emit_prequeue_native_hook_response(
    args: argparse.Namespace,
    *,
    output_stream: TextIO | None,
) -> bool:
    if _canonical_harness_name(args.harness) != "claude-code":
        return False
    if not getattr(args, "json", False):
        return True
    return output_stream is not None


def _emit_claude_permission_request_passthrough(*, output_stream: TextIO | None = None) -> None:
    if output_stream is not None:
        output_stream.write("")


def _claude_permission_notice_state_key(session_id: str, tool_name: str | None = None) -> str:
    if tool_name is not None:
        return f"claude_permission_notice:{session_id}:{tool_name}"
    return f"claude_permission_notice:{session_id}"


def _claude_pending_permission_index_key(session_id: str) -> str:
    return f"claude_pending_permissions:{session_id}"


def _claude_pending_permission_state_key(session_id: str, artifact_id: str) -> str:
    fingerprint = hashlib.sha256(artifact_id.encode("utf-8")).hexdigest()[:24]
    return f"claude_pending_permission:{session_id}:{fingerprint}"


def _sync_payload_list_from_row(row: sqlite3.Row | None) -> list[str]:
    if row is None:
        return []
    try:
        payload = json.loads(str(row["payload_json"]))
    except json.JSONDecodeError:
        return []
    return [str(item) for item in payload] if isinstance(payload, list) else []


def _append_claude_pending_permission_key(
    store: GuardStore,
    *,
    session_id: str,
    pending_key: str,
    now: str,
) -> None:
    index_key = _claude_pending_permission_index_key(session_id)
    with store._connect() as connection:
        connection.execute("begin immediate")
        row = connection.execute(
            "select payload_json from sync_state where state_key = ?",
            (index_key,),
        ).fetchone()
        pending_keys = _sync_payload_list_from_row(row)
        if pending_key in pending_keys:
            return
        pending_keys.append(pending_key)
        connection.execute(
            """
            insert into sync_state (state_key, payload_json, updated_at)
            values (?, ?, ?)
            on conflict(state_key) do update set
              payload_json = excluded.payload_json,
              updated_at = excluded.updated_at
            """,
            (index_key, json.dumps(pending_keys), now),
        )


def _record_claude_permission_notice(
    *,
    store: GuardStore,
    payload: dict[str, object],
    reason: str,
    artifact: GuardArtifact,
    artifact_hash: str,
) -> None:
    session_id = _optional_string(payload.get("session_id"))
    if session_id is None:
        return
    tool_name = _optional_string(payload.get("tool_name"))
    notice_payload: dict[str, object] = {
        "saved_at": _now(),
        "reason": reason,
        "artifact_id": artifact.artifact_id,
        "artifact_hash": artifact_hash,
        "artifact_name": artifact.name,
        "artifact_type": artifact.artifact_type,
        "config_path": artifact.config_path,
        "source_scope": artifact.source_scope,
    }
    if tool_name is not None:
        notice_payload["tool_name"] = tool_name
    try:
        store.set_sync_payload(_claude_permission_notice_state_key(session_id, tool_name), notice_payload, _now())
        pending_key = _claude_pending_permission_state_key(session_id, artifact.artifact_id)
        store.set_sync_payload(pending_key, notice_payload, _now())
        _append_claude_pending_permission_key(store, session_id=session_id, pending_key=pending_key, now=_now())
    except (OSError, sqlite3.Error):
        return


def _load_claude_permission_notice(store: GuardStore, payload: dict[str, object]) -> dict[str, object] | None:
    session_id = _optional_string(payload.get("session_id"))
    if session_id is None:
        return None
    tool_name = _claude_notification_tool_name(payload)
    try:
        selected_key = _claude_permission_notice_state_key(session_id, tool_name)
        persisted = store.get_sync_payload(selected_key)
        if persisted is None and tool_name is not None:
            selected_key = _claude_permission_notice_state_key(session_id)
            persisted = store.get_sync_payload(selected_key)
        if persisted is not None:
            store.delete_sync_payload(selected_key)
    except (OSError, sqlite3.Error):
        return None
    if isinstance(persisted, dict):
        return persisted
    return None


def _peek_claude_permission_notice(store: GuardStore, payload: dict[str, object]) -> dict[str, object] | None:
    session_id = _optional_string(payload.get("session_id"))
    if session_id is None:
        return None
    tool_name = _claude_notification_tool_name(payload)
    try:
        persisted = store.get_sync_payload(_claude_permission_notice_state_key(session_id, tool_name))
        if persisted is None and tool_name is not None:
            persisted = store.get_sync_payload(_claude_permission_notice_state_key(session_id))
    except (OSError, sqlite3.Error):
        return None
    return persisted if isinstance(persisted, dict) else None


def _mark_claude_pending_permission_prompt_seen(
    *,
    store: GuardStore,
    payload: dict[str, object],
    notice: dict[str, object] | None,
) -> None:
    session_id = _optional_string(payload.get("session_id"))
    artifact_id = _optional_string((notice or {}).get("artifact_id"))
    if session_id is None or artifact_id is None:
        return
    pending_key = _claude_pending_permission_state_key(session_id, artifact_id)
    try:
        pending = store.get_sync_payload(pending_key)
    except (OSError, sqlite3.Error):
        return
    if not isinstance(pending, dict):
        return
    updated = dict(pending)
    updated["permission_prompt_seen"] = True
    updated["permission_prompt_seen_at"] = _now()
    try:
        store.set_sync_payload(pending_key, updated, _now())
    except (OSError, sqlite3.Error):
        return


def _load_claude_pending_permission(
    store: GuardStore,
    payload: dict[str, object],
    artifact: GuardArtifact,
) -> dict[str, object] | None:
    session_id = _optional_string(payload.get("session_id"))
    if session_id is None:
        return None
    pending_key = _claude_pending_permission_state_key(session_id, artifact.artifact_id)
    try:
        persisted = store.get_sync_payload(pending_key)
    except (OSError, sqlite3.Error):
        return None
    return persisted if isinstance(persisted, dict) else None


def _remove_claude_pending_permission(
    store: GuardStore,
    *,
    session_id: str,
    pending_key: str,
) -> None:
    try:
        index_key = _claude_pending_permission_index_key(session_id)
        with store._connect() as connection:
            connection.execute("begin immediate")
            connection.execute("delete from sync_state where state_key = ?", (pending_key,))
            row = connection.execute(
                "select payload_json from sync_state where state_key = ?",
                (index_key,),
            ).fetchone()
            remaining = [key for key in _sync_payload_list_from_row(row) if key != pending_key]
            if remaining:
                connection.execute(
                    """
                    insert into sync_state (state_key, payload_json, updated_at)
                    values (?, ?, ?)
                    on conflict(state_key) do update set
                      payload_json = excluded.payload_json,
                      updated_at = excluded.updated_at
                    """,
                    (index_key, json.dumps(remaining), _now()),
                )
            else:
                connection.execute("delete from sync_state where state_key = ?", (index_key,))
    except (OSError, sqlite3.Error):
        return


def _persist_claude_native_permission_policy(
    *,
    store: GuardStore,
    artifact_id: str,
    artifact_hash: str,
    action: str,
    reason: str,
    now: str,
) -> bool:
    try:
        store.upsert_policy(
            PolicyDecision(
                harness="claude-code",
                scope="artifact",
                action="allow" if action == "allow" else "block",
                artifact_id=artifact_id,
                artifact_hash=artifact_hash,
                reason=reason,
                source="claude-native-approval",
            ),
            now,
        )
        store.add_event(
            "claude/native_permission_saved",
            {
                "artifact_id": artifact_id,
                "artifact_hash": artifact_hash,
                "action": action,
                "reason": reason,
            },
            now,
        )
    except (OSError, sqlite3.Error):
        return False
    return True


def _persist_claude_native_permission_for_runtime_artifact(
    *,
    store: GuardStore,
    payload: dict[str, object],
    artifact: GuardArtifact,
    artifact_hash: str,
    action: str,
    reason: str,
) -> bool:
    pending = _load_claude_pending_permission(store, payload, artifact)
    if pending is None:
        return False
    now = _now()
    saved_policy = _persist_claude_native_permission_policy(
        store=store,
        artifact_id=artifact.artifact_id,
        artifact_hash=artifact_hash,
        action=action,
        reason=reason,
        now=now,
    )
    if not saved_policy:
        return False
    try:
        store.record_inventory_artifact(
            artifact=artifact,
            artifact_hash=artifact_hash,
            policy_action="allow" if action == "allow" else "block",
            changed=False,
            now=now,
            approved=action == "allow",
        )
    except (OSError, sqlite3.Error):
        return False
    session_id = _optional_string(payload.get("session_id"))
    if session_id is not None:
        _remove_claude_pending_permission(
            store,
            session_id=session_id,
            pending_key=_claude_pending_permission_state_key(session_id, artifact.artifact_id),
        )
    return True


def _persist_claude_pending_permission_denials(store: GuardStore, payload: dict[str, object]) -> int:
    session_id = _optional_string(payload.get("session_id"))
    if session_id is None:
        return 0
    index_key = _claude_pending_permission_index_key(session_id)
    try:
        index_payload = store.get_sync_payload(index_key)
    except (OSError, sqlite3.Error):
        return 0
    if not isinstance(index_payload, list):
        return 0
    pending_keys = [str(item) for item in index_payload]
    processed_keys: list[str] = []
    denied = 0
    for pending_key in pending_keys:
        try:
            pending = store.get_sync_payload(pending_key)
        except (OSError, sqlite3.Error):
            continue
        if not isinstance(pending, dict):
            continue
        if pending.get("permission_prompt_seen") is not True:
            continue
        artifact_id = _optional_string(pending.get("artifact_id"))
        artifact_hash_value = _optional_string(pending.get("artifact_hash"))
        if artifact_id is None or artifact_hash_value is None:
            continue
        reason = _optional_string(pending.get("reason")) or "Denied in Claude's native approval prompt."
        saved_policy = _persist_claude_native_permission_policy(
            store=store,
            artifact_id=artifact_id,
            artifact_hash=artifact_hash_value,
            action="block",
            reason=f"Denied in Claude native approval prompt. {reason}",
            now=_now(),
        )
        if not saved_policy:
            continue
        processed_keys.append(pending_key)
        denied += 1
    if processed_keys:
        processed_set = set(processed_keys)
        try:
            with store._connect() as connection:
                connection.execute("begin immediate")
                for pending_key in processed_keys:
                    connection.execute("delete from sync_state where state_key = ?", (pending_key,))
                row = connection.execute(
                    "select payload_json from sync_state where state_key = ?",
                    (index_key,),
                ).fetchone()
                current_keys = _sync_payload_list_from_row(row)
                remaining_keys = [pending_key for pending_key in current_keys if pending_key not in processed_set]
                if remaining_keys:
                    connection.execute(
                        """
                        insert into sync_state (state_key, payload_json, updated_at)
                        values (?, ?, ?)
                        on conflict(state_key) do update set
                          payload_json = excluded.payload_json,
                          updated_at = excluded.updated_at
                        """,
                        (index_key, json.dumps(remaining_keys), _now()),
                    )
                else:
                    connection.execute("delete from sync_state where state_key = ?", (index_key,))
        except (OSError, sqlite3.Error):
            return denied
    return denied


def _is_claude_permission_prompt_notification(args: argparse.Namespace, payload: dict[str, object]) -> bool:
    return (
        _canonical_harness_name(args.harness) == "claude-code"
        and _hook_event_name(payload) == "Notification"
        and _optional_string(payload.get("notification_type")) == "permission_prompt"
    )


def _is_claude_permission_request(args: argparse.Namespace, payload: dict[str, object]) -> bool:
    return _canonical_harness_name(args.harness) == "claude-code" and _hook_event_name(payload) == "PermissionRequest"


def _claude_permission_prompt_system_message(
    *,
    payload: dict[str, object],
    notice: dict[str, object] | None,
) -> str:
    tool_name = _claude_notification_tool_name(payload)
    if tool_name is None and notice is not None:
        tool_name = _optional_string(notice.get("tool_name"))
    reason = _optional_string(notice.get("reason")) if notice is not None else None
    intro = "HOL Guard intercepted a sensitive request and opened this Claude approval prompt."
    if tool_name is not None:
        intro = f"HOL Guard intercepted Claude's attempt to use {tool_name} and opened this approval prompt."
    if reason is not None:
        return (
            f"{intro} This approval dialog came from HOL Guard, not from Claude alone. "
            f"{_ensure_terminal_punctuation(reason)} "
            "Use the Claude choices below: Yes to allow it once, Yes during this session to trust the same action "
            "for the rest of this session, or No to keep the sensitive action blocked."
        )
    return (
        f"{intro} This approval dialog came from HOL Guard, not from Claude alone. "
        "Use the Claude choices below: Yes to allow it once, Yes during this session to trust the same action for "
        "the rest of this session, or No to keep the sensitive action blocked."
    )


def _claude_permission_prompt_additional_context(notice: dict[str, object] | None) -> str:
    reason = _optional_string(notice.get("reason")) if notice is not None else None
    if reason is not None:
        return (
            "HOL Guard intercepted the sensitive request and opened the Claude approval dialog that is currently "
            "open. "
            "This approval dialog came from HOL Guard, not from Claude alone. "
            f"{_ensure_terminal_punctuation(reason)} The user can choose Yes, Yes during this session, or No in the "
            "prompt that is already visible. If the user denies it, do not retry the same sensitive access."
        )
    return (
        "HOL Guard intercepted the sensitive request and opened the Claude approval dialog that is currently open. "
        "This approval dialog came from HOL Guard, not from Claude alone. "
        "The user can choose Yes, Yes during this session, or No in the prompt that is already visible. "
        "If the user denies it, do not retry the same action."
    )


def _claude_permission_prompt_terminal_notice(
    *,
    payload: dict[str, object],
    notice: dict[str, object] | None,
) -> str:
    tool_name = _claude_notification_tool_name(payload)
    reason = _optional_string(notice.get("reason")) if notice is not None else None
    if tool_name is not None and reason is not None:
        return (
            f"HOL Guard opened this Claude approval prompt for {tool_name}. "
            f"{_ensure_terminal_punctuation(reason)} "
            "Review the request below, then choose Yes, Yes during this session, or No."
        )
    if tool_name is not None:
        return (
            f"HOL Guard opened this Claude approval prompt for {tool_name}. "
            "Review the request below, then choose Yes, Yes during this session, or No."
        )
    return (
        "HOL Guard opened this Claude approval prompt to protect a sensitive action. "
        "Review the request below, then choose Yes, Yes during this session, or No."
    )


def _claude_native_pretooluse_terminal_notice(*, payload: dict[str, object], reason: str) -> str:
    tool_name = _claude_notification_tool_name(payload)
    if tool_name is not None:
        return f"HOL Guard opened this Claude approval prompt for {tool_name}. {_ensure_terminal_punctuation(reason)}"
    return (
        "HOL Guard opened this Claude approval prompt to protect a sensitive action. "
        f"{_ensure_terminal_punctuation(reason)}"
    )


def _claude_notification_tool_name(payload: dict[str, object]) -> str | None:
    direct_name = _optional_string(payload.get("tool_name"))
    if direct_name is not None:
        return direct_name
    for key in ("message", "title"):
        value = _optional_string(payload.get(key))
        if value is None:
            continue
        match = re.search(r"\buse\s+([A-Za-z][A-Za-z0-9_]*)\b", value)
        if match is not None:
            return match.group(1)
    return None


def _approval_delivery_payload(
    harness: str,
    *,
    managed_install: dict[str, object] | None = None,
) -> dict[str, object]:
    return approval_delivery_payload(approval_prompt_flow(harness, managed_install=managed_install))


def _native_hook_reason(*values: object | None) -> str:
    messages: list[str] = []
    for value in values:
        if isinstance(value, str) and value.strip():
            candidate = value.strip()
            if candidate not in messages:
                messages.append(candidate)
    if messages:
        return " ".join(messages)
    return "HOL Guard flagged this tool call for review."


def _ensure_terminal_punctuation(message: str) -> str:
    trimmed = message.strip()
    if trimmed.endswith((".", "!", "?")):
        return trimmed
    return f"{trimmed}."


def _native_hook_reason_for_harness(harness: str, *values: object | None) -> str:
    reason = _native_hook_reason(*values)
    if harness != "codex":
        return reason
    if "approve it in hol guard, then retry." in reason.lower():
        return reason
    return f"{reason} Approve it in HOL Guard, then retry."


def _prompt_requires_hard_block(artifact: GuardArtifact) -> bool:
    prompt_classes = artifact.metadata.get("prompt_request_classes")
    if isinstance(prompt_classes, list):
        return "guard_bypass_intent" in {str(item) for item in prompt_classes}
    prompt_class = artifact.metadata.get("prompt_request_class")
    return isinstance(prompt_class, str) and prompt_class == "guard_bypass_intent"


def _prompt_request_classes(artifact: GuardArtifact) -> set[str]:
    prompt_classes = artifact.metadata.get("prompt_request_classes")
    values = prompt_classes if isinstance(prompt_classes, list) else [artifact.metadata.get("prompt_request_class")]
    return {str(item) for item in values if isinstance(item, str) and item.strip()}


def _native_prompt_context(artifact: GuardArtifact) -> str:
    if _prompt_requires_hard_block(artifact):
        return "HOL Guard blocked this prompt because it asks to bypass or disable Guard."
    prompt_classes = _prompt_request_classes(artifact)
    if "secret_read" in prompt_classes:
        return (
            "HOL Guard flagged this prompt because it asks for direct local secret access and is protecting your "
            "local secrets. "
            "If that is intentional, continue and Guard will ask again on the actual tool call."
        )
    return (
        "HOL Guard flagged this prompt as higher risk. Continue only if you expect the next tool call to need "
        "explicit approval."
    )


def _runtime_artifact_native_reason(artifact: GuardArtifact, response_payload: dict[str, object]) -> str:
    if artifact.artifact_type == "prompt_request":
        policy_action = response_payload.get("policy_action")
        if policy_action in {"block", "sandbox-required"} and not _prompt_requires_hard_block(artifact):
            return "HOL Guard blocked this prompt because it requests guarded local secret access."
        return _native_prompt_context(artifact)
    path_class = artifact.metadata.get("path_class")
    tool_name = artifact.metadata.get("tool_name")
    if isinstance(path_class, str) and isinstance(tool_name, str):
        harness = response_payload.get("harness")
        policy_action = response_payload.get("policy_action")
        if harness == "claude-code" and policy_action == "require-reapproval":
            return (
                f"HOL Guard intercepted Claude's attempt to use {tool_name} for {path_class} to protect your local "
                "secrets. This approval prompt came from HOL Guard, not from Claude alone. "
                "Choose Yes to allow it once, Yes during this session to trust the same action for the rest of this "
                "session, or No to keep the secret private."
            )
        return (
            f"HOL Guard blocked Claude's attempt to use {tool_name} for {path_class} to protect your local secrets. "
            "This request cannot continue in the current approval flow."
        )
    risk_summary = response_payload.get("risk_summary")
    if isinstance(risk_summary, str) and risk_summary.strip():
        trimmed_summary = risk_summary.strip()
        if len(trimmed_summary) > 180:
            trimmed_summary = f"{trimmed_summary[:177].rstrip()}..."
        return f"HOL Guard flagged this request: {trimmed_summary}"
    return "HOL Guard flagged this request for review."


def _claude_prompt_additional_context(
    *,
    harness: str,
    event_name: str,
    policy_action: str,
    artifact: GuardArtifact,
    native_reason: str,
) -> str | None:
    if _canonical_harness_name(harness) != "claude-code":
        return None
    if event_name != "UserPromptSubmit":
        return None
    if policy_action != "require-reapproval":
        return None
    if _prompt_requires_hard_block(artifact):
        return None
    briefing_sentence = "HOL Guard intercepted the next sensitive action and opened the approval dialog below."
    if "secret_read" in _prompt_request_classes(artifact):
        briefing_sentence = (
            "HOL Guard intercepted Claude's next attempt to access local secrets and opened the approval dialog "
            "shown below to protect you."
        )
    else:
        briefing_sentence = (
            "HOL Guard intercepted Claude's next sensitive action and opened the approval dialog shown below."
        )
    return (
        f"{_ensure_terminal_punctuation(native_reason)} "
        "Before you use the first sensitive tool for this request, tell the user exactly: "
        f"'{briefing_sentence}' "
        "Attempt that sensitive tool at most once. If HOL Guard or Claude denies it, do not retry the same sensitive "
        "action automatically. Instead, tell the user approval is required in Claude to continue."
    )


def _claude_prompt_system_message(
    *,
    event_name: str,
    policy_action: str,
    artifact: GuardArtifact,
    native_reason: str,
) -> str | None:
    if event_name == "UserPromptSubmit":
        if policy_action == "require-reapproval" and not _prompt_requires_hard_block(artifact):
            if "secret_read" in _prompt_request_classes(artifact):
                return (
                    "HOL Guard intercepted this prompt because it asks Claude to access local secrets. "
                    "If Claude opens a permission dialog on the next tool call, that approval prompt came from HOL "
                    "Guard."
                )
            return (
                "HOL Guard intercepted this prompt because it leads to a sensitive action. "
                "If Claude opens a permission dialog on the next tool call, that approval prompt came from HOL Guard."
            )
        if policy_action in {"block", "sandbox-required"}:
            return _ensure_terminal_punctuation(native_reason)
        return None
    if event_name == "PreToolUse" and policy_action in {"require-reapproval", "block", "sandbox-required"}:
        return _ensure_terminal_punctuation(native_reason)
    return None


def _copilot_hook_reason(*values: object | None) -> str:
    reason = _native_hook_reason(*values)
    if reason.startswith("Guard "):
        reason = f"HOL {reason}"
    if "approve" in reason.lower():
        return reason
    return f"{reason} Approve it in HOL Guard, then retry."


def _guard_rerun_command(args: argparse.Namespace) -> str:
    command = ["hol-guard", "run", str(args.harness)]
    _append_guard_context_args(command, args)
    default_action = getattr(args, "default_action", None)
    if isinstance(default_action, str) and default_action:
        command.extend(["--default-action", default_action])
    passthrough_args = getattr(args, "passthrough_args", [])
    if isinstance(passthrough_args, list):
        for value in passthrough_args:
            if isinstance(value, str) and value:
                command.extend(["--arg", value])
    return _shell_join(command)


def _guard_diff_command(args: argparse.Namespace) -> str:
    command = ["hol-guard", "diff", str(args.harness)]
    _append_guard_context_args(command, args)
    return _shell_join(command)


def _guard_approvals_command(args: argparse.Namespace) -> str:
    command = ["hol-guard", "approvals"]
    _append_guard_context_args(command, args)
    return _shell_join(command)


def _shell_join(command: list[str]) -> str:
    if sys.platform.startswith("win"):
        return subprocess.list2cmdline(command)
    return shlex.join(command)


def _append_guard_context_args(command: list[str], args: argparse.Namespace) -> None:
    for option_name in ("home", "guard_home", "workspace"):
        value = getattr(args, option_name, None)
        if isinstance(value, str) and value:
            flag = f"--{option_name.replace('_', '-')}"
            command.extend([flag, value])


def _write_json_line(payload: dict[str, object], *, output_stream: TextIO | None = None) -> None:
    stream = output_stream or sys.stdout
    stream.write(f"{json.dumps(payload, separators=(',', ':'))}\n")
    stream.flush()


def _emit_copilot_hook_response(
    *,
    policy_action: str,
    reason: str,
    output_stream: TextIO | None = None,
) -> None:
    payload = {"permissionDecision": _copilot_hook_permission_decision(policy_action)}
    if payload["permissionDecision"] != "allow":
        payload["permissionDecisionReason"] = reason
    _write_json_line(payload, output_stream=output_stream)


def _emit_copilot_permission_request_response(
    *,
    behavior: str,
    message: str | None = None,
    interrupt: bool | None = None,
    output_stream: TextIO | None = None,
) -> None:
    payload: dict[str, object] = {"behavior": behavior}
    if isinstance(message, str) and message.strip():
        payload["message"] = message.strip()
    if isinstance(interrupt, bool):
        payload["interrupt"] = interrupt
    _write_json_line(payload, output_stream=output_stream)


def _emit_native_hook_response(
    *,
    harness: str,
    policy_action: str,
    reason: str,
    event_name: str = "PreToolUse",
    additional_context: str | None = None,
    system_message: str | None = None,
    output_stream: TextIO | None = None,
) -> None:
    payload: dict[str, object] = {}
    if isinstance(system_message, str) and system_message.strip():
        payload["systemMessage"] = system_message.strip()
    if event_name == "UserPromptSubmit":
        if policy_action in {"block", "sandbox-required", "require-reapproval"} and not additional_context:
            payload["decision"] = "block"
            payload["reason"] = reason
        elif additional_context:
            payload["hookSpecificOutput"] = {
                "hookEventName": event_name,
                "additionalContext": additional_context,
            }
        if payload:
            _write_json_line(payload, output_stream=output_stream)
        return
    if event_name in {"Notification", "PermissionRequest"}:
        if additional_context:
            payload["hookSpecificOutput"] = {
                "hookEventName": event_name,
                "additionalContext": additional_context,
            }
        if payload:
            _write_json_line(payload, output_stream=output_stream)
        return
    permission_decision = _native_hook_permission_decision(policy_action, harness=harness)
    if harness == "codex" and event_name == "PreToolUse" and permission_decision is None:
        return
    hook_specific_output: dict[str, object] = {"hookEventName": event_name}
    if permission_decision is not None:
        hook_specific_output["permissionDecision"] = permission_decision
        if permission_decision != "allow":
            hook_specific_output["permissionDecisionReason"] = reason
    payload["hookSpecificOutput"] = hook_specific_output
    _write_json_line(payload, output_stream=output_stream)


def _emit_native_hook_block_stderr(reason: str) -> None:
    print(reason, file=sys.stderr)


def _emit_native_hook_notification_stderr(reason: str) -> None:
    print(reason, file=sys.stderr)


def _native_hook_permission_decision(policy_action: str, *, harness: str) -> str | None:
    if policy_action in {"block", "sandbox-required"}:
        return "deny"
    if policy_action == "require-reapproval":
        if harness == "codex":
            return "deny"
        return "ask"
    if harness == "codex":
        return None
    return "allow"


def _copilot_hook_permission_decision(policy_action: str) -> str:
    if policy_action in {"block", "sandbox-required", "require-reapproval"}:
        return "deny"
    return "allow"


def _headless_approval_resolver(
    *,
    args: argparse.Namespace,
    context: HarnessContext,
    store: GuardStore,
    config,
):
    should_wait_for_approvals = not bool(getattr(args, "json", False))

    def resolve(detection, payload):
        managed_install = _managed_install_for(store, args.harness)
        approval_flow = approval_prompt_flow(args.harness, managed_install=managed_install)
        approval_center_url = ensure_guard_daemon(context.guard_home)
        try:
            daemon_client = load_guard_surface_daemon_client(context.guard_home)
        except RuntimeError:
            queued = queue_blocked_approvals(
                detection=detection,
                evaluation=payload,
                store=store,
                approval_center_url=approval_center_url,
                now=_now(),
            )
            payload["approval_requests"] = queued
            payload["approval_center_url"] = approval_center_url
            payload["review_hint"] = approval_center_hint(
                context=context,
                harness=args.harness,
                approval_center_url=approval_center_url,
                queued=queued,
            )
            payload["approval_delivery"] = _approval_delivery_payload(args.harness, managed_install=managed_install)
            if str(approval_flow["tier"]) != "native-or-center" or not should_wait_for_approvals:
                payload["approval_wait"] = {
                    "resolved": False,
                    "pending_request_ids": [str(item["request_id"]) for item in queued if "request_id" in item],
                    "items": [],
                }
                return payload
            wait_result = wait_for_approval_requests(
                store=store,
                request_ids=[str(item["request_id"]) for item in queued if "request_id" in item],
                timeout_seconds=config.approval_wait_timeout_seconds,
            )
            payload["approval_wait"] = wait_result
            if bool(wait_result.get("resolved")):
                resolved_items = [item for item in wait_result.get("items", []) if isinstance(item, dict)]
                payload["blocked"] = any(str(item.get("resolution_action")) == "block" for item in resolved_items)
                if not payload["blocked"]:
                    payload["blocked"] = False
                    payload["review_hint"] = "Approval received. Guard is resuming the harness launch."
            else:
                payload["review_hint"] = (
                    f"Approval is still pending in the Guard approval center at {approval_center_url}. Resolve request "
                    f"{', '.join(str(item) for item in wait_result.get('pending_request_ids', []))}."
                )
            return payload
        session = daemon_client.start_session(
            harness=args.harness,
            surface="cli",
            workspace=str(context.workspace_dir) if context.workspace_dir is not None else None,
            client_name="hol-guard",
            client_title="HOL Guard CLI",
            client_version=_GUARD_CLIENT_VERSION,
            capabilities=["approval-resolution", "receipt-view"],
        )
        blocked_operation = daemon_client.queue_blocked_operation(
            session_id=str(session["session_id"]),
            operation_type="run",
            harness=args.harness,
            metadata={"command": f"hol-guard run {args.harness}"},
            detection=detection.to_dict(),
            evaluation=payload,
            approval_center_url=approval_center_url,
            approval_surface_policy=_approval_surface_policy_for_flow(
                config.approval_surface_policy,
                approval_flow,
            ),
            open_key=None,
        )
        operation = blocked_operation["operation"] if isinstance(blocked_operation.get("operation"), dict) else {}
        queued = (
            blocked_operation["approval_requests"]
            if isinstance(blocked_operation.get("approval_requests"), list)
            else []
        )
        payload["session_id"] = str(session["session_id"])
        payload["operation_id"] = str(operation["operation_id"])
        payload["approval_requests"] = queued
        payload["approval_center_url"] = approval_center_url
        payload["review_hint"] = approval_center_hint(
            context=context,
            harness=args.harness,
            approval_center_url=approval_center_url,
            queued=queued,
            managed_install=managed_install,
        )
        payload["approval_delivery"] = _approval_delivery_payload(args.harness, managed_install=managed_install)
        if str(approval_flow["tier"]) != "native-or-center" or not should_wait_for_approvals:
            payload["approval_wait"] = {
                "resolved": False,
                "pending_request_ids": [str(item["request_id"]) for item in queued if "request_id" in item],
                "items": [],
            }
            return payload
        wait_result = wait_for_approval_requests(
            store=store,
            request_ids=[str(item["request_id"]) for item in queued if "request_id" in item],
            timeout_seconds=config.approval_wait_timeout_seconds,
        )
        payload["approval_wait"] = wait_result
        if bool(wait_result.get("resolved")):
            resolved_items = [item for item in wait_result.get("items", []) if isinstance(item, dict)]
            payload["blocked"] = any(str(item.get("resolution_action")) == "block" for item in resolved_items)
            if not payload["blocked"]:
                payload["blocked"] = False
                daemon_client.update_operation_status(
                    operation_id=str(operation["operation_id"]),
                    status="completed",
                )
                payload["review_hint"] = "Approval received. Guard is resuming the harness launch."
            else:
                daemon_client.update_operation_status(
                    operation_id=str(operation["operation_id"]),
                    status="blocked",
                )
        else:
            daemon_client.update_operation_status(
                operation_id=str(operation["operation_id"]),
                status="waiting_on_approval",
                approval_request_ids=[str(item["request_id"]) for item in queued if "request_id" in item],
            )
            payload["review_hint"] = (
                f"Approval is still pending in the Guard approval center at {approval_center_url}. Resolve request "
                f"{', '.join(str(item) for item in wait_result.get('pending_request_ids', []))}."
            )
        return payload

    return resolve


def _open_approval_center(approval_center_url: str, *, store: GuardStore, config, open_key: str | None = None) -> None:
    surface_runtime = GuardSurfaceRuntime(store)
    auth_token = load_guard_daemon_auth_token(store.guard_home)
    surface_runtime.ensure_surface(
        surface="approval-center",
        approval_center_url=approval_center_url,
        browser_url=_approval_center_browser_url(approval_center_url, auth_token),
        approval_surface_policy=config.approval_surface_policy,
        open_key=open_key or approval_center_url,
        opener=webbrowser.open,
    )


def _approval_center_browser_url(approval_center_url: str, auth_token: str | None) -> str | None:
    if auth_token is None:
        return None
    parsed = urllib.parse.urlparse(approval_center_url)
    fragment_pairs = [
        (key, value)
        for key, value in urllib.parse.parse_qsl(parsed.fragment, keep_blank_values=True)
        if key != "guard-token"
    ]
    fragment_pairs.append(("guard-token", auth_token))
    return urllib.parse.urlunparse(parsed._replace(fragment=urllib.parse.urlencode(fragment_pairs)))


def _approval_surface_policy_for_flow(config_policy: str, approval_flow: dict[str, object]) -> str:
    if approval_flow.get("tier") != "approval-center":
        return "notify-only"
    if approval_flow.get("auto_open_browser") is False:
        return "never-auto-open"
    if approval_flow.get("prompt_channel") == "native-fallback":
        return "never-auto-open"
    return config_policy


def _load_hook_payload(event_file: str | None, *, input_text: str | None = None) -> dict[str, object]:
    if event_file:
        payload = json.loads(Path(event_file).read_text(encoding="utf-8"))
        return _normalize_hook_payload(payload) if isinstance(payload, dict) else {}
    raw = input_text.strip() if isinstance(input_text, str) else sys.stdin.read().strip()
    if not raw:
        return {}
    payload = json.loads(raw)
    return _normalize_hook_payload(payload) if isinstance(payload, dict) else {}


def _normalize_hook_payload(payload: dict[str, object]) -> dict[str, object]:
    normalized = dict(payload)
    for source_key, target_key in (
        ("artifactId", "artifact_id"),
        ("artifactHash", "artifact_hash"),
        ("artifactName", "artifact_name"),
        ("changedCapabilities", "changed_capabilities"),
        ("hookEventName", "hook_event_name"),
        ("hookName", "hook_name"),
        ("policyAction", "policy_action"),
        ("sourceScope", "source_scope"),
        ("toolName", "tool_name"),
        ("userOverride", "user_override"),
    ):
        if target_key not in normalized and source_key in payload:
            normalized[target_key] = payload[source_key]
    if "tool_name" not in normalized or "tool_input" not in normalized:
        tool_name, tool_input = _first_hook_tool_call(
            payload.get("toolCalls"),
            expected_tool_name=normalized.get("tool_name"),
        )
        if "tool_name" not in normalized and tool_name is not None:
            normalized["tool_name"] = tool_name
        if "tool_input" not in normalized and tool_input is not None:
            normalized["tool_input"] = tool_input
    arguments = _normalize_hook_arguments(
        normalized.get("tool_input"),
        normalized.get("arguments"),
        payload.get("toolArgs"),
        payload.get("toolInput"),
    )
    if arguments is not None:
        normalized["tool_input"] = arguments
        normalized["arguments"] = arguments
    return normalized


def _normalize_hook_arguments(*values: object | None) -> object | None:
    for value in values:
        normalized = _normalize_hook_argument_value(value)
        if normalized is not None:
            return normalized
    return None


def _normalize_hook_argument_value(value: object | None) -> object | None:
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return None
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            return stripped
        if isinstance(parsed, (dict, list, str)):
            return parsed
        return stripped
    return value


def _first_hook_tool_call(
    value: object | None,
    *,
    expected_tool_name: object | None = None,
) -> tuple[str | None, object | None]:
    if not isinstance(value, list):
        return None, None
    normalized_expected_tool_name = expected_tool_name.strip() if isinstance(expected_tool_name, str) else None
    fallback_tool_call: tuple[str, object | None] | None = None
    for item in value:
        if not isinstance(item, dict):
            continue
        tool_name = item.get("name")
        tool_input = _normalize_hook_argument_value(item.get("args"))
        if isinstance(tool_name, str) and tool_name.strip():
            stripped_tool_name = tool_name.strip()
            if fallback_tool_call is None:
                fallback_tool_call = (stripped_tool_name, tool_input)
            if normalized_expected_tool_name is None or stripped_tool_name == normalized_expected_tool_name:
                return stripped_tool_name, tool_input
    if fallback_tool_call is not None:
        return fallback_tool_call
    return None, None


def _coalesce_string(*values: object | None) -> str:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "unknown-artifact"


def _optional_string(value: object | None) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _hook_event_name(payload: dict[str, object]) -> str | None:
    for key in ("event", "hook_event_name", "hookEventName", "hook_name"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _artifact_id_from_event(harness: str, payload: dict[str, object]) -> str:
    source_scope = _coalesce_string(payload.get("source_scope"), "project")
    tool_name = payload.get("tool_name")
    if isinstance(tool_name, str) and tool_name.strip():
        return f"{harness}:{source_scope}:{tool_name.strip()}"
    event_name = _hook_event_name(payload)
    if isinstance(event_name, str) and event_name.strip():
        return f"{harness}:{source_scope}:{event_name.strip().lower()}"
    return f"{harness}:{source_scope}:hook"


def _string_list(value: object | None) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str) and item.strip()]


def _merged_prompt_runtime_artifact(harness: str, artifacts: list[GuardArtifact]) -> GuardArtifact:
    if len(artifacts) == 1:
        return artifacts[0]
    prompt_signals: list[str] = []
    prompt_matched_texts: list[str] = []
    prompt_request_classes: list[str] = []
    request_identity = "|".join(sorted(artifact.artifact_id for artifact in artifacts))
    for artifact in artifacts:
        metadata = artifact.metadata
        prompt_signals.extend(_string_list(metadata.get("prompt_signals")))
        matched_text = metadata.get("prompt_matched_text")
        if isinstance(matched_text, str) and matched_text.strip():
            prompt_matched_texts.append(matched_text.strip())
        request_class = metadata.get("prompt_request_class")
        if isinstance(request_class, str) and request_class.strip():
            prompt_request_classes.append(request_class.strip())
    deduped_signals = list(dict.fromkeys(prompt_signals))
    deduped_matches = list(dict.fromkeys(prompt_matched_texts))
    deduped_classes = list(dict.fromkeys(prompt_request_classes))
    return GuardArtifact(
        artifact_id=f"{harness}:session:prompt:multi:{hashlib.sha256(request_identity.encode('utf-8')).hexdigest()[:24]}",
        name="prompt multi-signal request",
        harness=harness,
        artifact_type="prompt_request",
        source_scope=artifacts[0].source_scope,
        config_path=artifacts[0].config_path,
        metadata={
            "prompt_signals": deduped_signals,
            "prompt_summary": "Prompt matches multiple guarded request classes.",
            "prompt_matched_texts": deduped_matches,
            "prompt_request_classes": deduped_classes,
        },
    )


def _hook_runtime_artifact(
    *,
    harness: str,
    payload: dict[str, object],
    home_dir: Path,
    guard_home: Path,
    workspace: Path | None,
) -> GuardArtifact | None:
    harness = _canonical_harness_name(harness)
    event_name = _hook_event_name(payload)
    if event_name == "UserPromptSubmit":
        prompt_text = payload.get("prompt")
        if isinstance(prompt_text, str) and prompt_text.strip():
            config_path = str(_runtime_policy_path(harness, home_dir, workspace))
            prompt_detection = HarnessDetection(
                harness=harness,
                installed=True,
                command_available=True,
                config_paths=(config_path,),
                artifacts=(),
            )
            prompt_context = HarnessContext(
                home_dir=home_dir,
                guard_home=guard_home,
                workspace_dir=workspace,
            )
            prompt_requests = extract_prompt_requests(prompt_text)
            if prompt_requests:
                prompt_artifacts = prompt_requests_to_artifacts(
                    detection=prompt_detection,
                    context=prompt_context,
                    requests=prompt_requests,
                )
                if prompt_artifacts:
                    return _merged_prompt_runtime_artifact(harness, prompt_artifacts)
    request = extract_sensitive_file_read_request(
        payload.get("tool_name"),
        payload.get("tool_input", payload.get("arguments")),
        cwd=workspace,
        home_dir=home_dir,
    )
    source_scope = _coalesce_string(payload.get("source_scope"), "project")
    config_path = str(_runtime_policy_path(harness, home_dir, workspace))
    if request is not None:
        return build_file_read_request_artifact(
            harness=harness,
            request=request,
            config_path=config_path,
            source_scope=source_scope,
        )
    tool_request = extract_sensitive_tool_action_request(
        payload.get("tool_name"),
        payload.get("tool_input", payload.get("arguments")),
        cwd=workspace,
        home_dir=home_dir,
    )
    if tool_request is None:
        return None
    return build_tool_action_request_artifact(
        harness=harness,
        request=tool_request,
        config_path=config_path,
        source_scope=source_scope,
    )


def _legacy_claude_alias_runtime_artifact(
    *,
    artifact: GuardArtifact,
    requested_harness: str,
    home_dir: Path,
    workspace: Path | None,
) -> GuardArtifact | None:
    if requested_harness == artifact.harness:
        return None
    if requested_harness != "claude" or artifact.harness != "claude-code":
        return None
    legacy_prefix = "claude-code:"
    if not artifact.artifact_id.startswith(legacy_prefix):
        return None
    return replace(
        artifact,
        artifact_id=f"claude:{artifact.artifact_id[len(legacy_prefix) :]}",
        harness="claude",
        config_path=str(_runtime_policy_path("claude", home_dir, workspace)),
    )


def _is_copilot_permission_request(payload: dict[str, object]) -> bool:
    for key in ("hook_name", "hook_event_name", "hookEventName"):
        hook_name = payload.get(key)
        if isinstance(hook_name, str) and hook_name == "permissionRequest":
            return True
    return False


def _copilot_hook_stage(payload: dict[str, object]) -> str | None:
    for key in ("hook_name", "hook_event_name", "hookEventName"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
    return None


def _copilot_runtime_tool_call(
    *,
    payload: dict[str, object],
    home_dir: Path,
    workspace: Path | None,
    preferred_workspace_config: str | None = None,
) -> tuple[GuardArtifact, str, object] | None:
    tool_name = payload.get("tool_name")
    if not isinstance(tool_name, str) or not tool_name.strip():
        return None
    server_name: str | None = None
    runtime_tool_name: str | None = None
    source_scope = _coalesce_string(payload.get("source_scope"), "project" if workspace is not None else "global")
    config_path = str(_runtime_policy_path("copilot", home_dir, workspace))
    if "/" in tool_name:
        server_name, runtime_tool_name = tool_name.split("/", 1)
    elif tool_name.startswith("mcp_"):
        resolved = _resolve_copilot_mcp_runtime_tool(
            tool_name=tool_name,
            home_dir=home_dir,
            workspace=workspace,
            preferred_workspace_config=preferred_workspace_config,
        )
        if resolved is None:
            return None
        server_name, runtime_tool_name, source_scope, config_path = resolved
    if (
        not isinstance(server_name, str)
        or not server_name.strip()
        or not isinstance(runtime_tool_name, str)
        or not runtime_tool_name.strip()
    ):
        return None
    artifact = build_tool_call_artifact(
        harness="copilot",
        server_name=server_name.strip(),
        tool_name=runtime_tool_name.strip(),
        source_scope=source_scope,
        config_path=config_path,
        transport="stdio",
    )
    arguments = payload.get("tool_input", payload.get("arguments"))
    artifact_hash = build_tool_call_hash(artifact, arguments)
    return artifact, artifact_hash, arguments


def _resolve_copilot_mcp_runtime_tool(
    *,
    tool_name: str,
    home_dir: Path,
    workspace: Path | None,
    preferred_workspace_config: str | None = None,
) -> tuple[str, str, str, str] | None:
    if not tool_name.startswith("mcp_"):
        return None
    suffix = tool_name[len("mcp_") :]
    if not suffix:
        return None
    matches: list[tuple[int, int, str, str, str, str]] = []
    for server_name, source_scope, config_path in _copilot_runtime_server_entries(home_dir, workspace):
        server_token = _copilot_mcp_tool_token(server_name)
        if suffix.startswith(f"{server_token}_"):
            runtime_tool_name = suffix[len(server_token) + 1 :]
            if runtime_tool_name:
                matches.append(
                    (
                        len(server_token),
                        _copilot_runtime_match_priority(
                            config_path=config_path,
                            preferred_workspace_config=preferred_workspace_config,
                        ),
                        server_name,
                        runtime_tool_name,
                        source_scope,
                        config_path,
                    )
                )
    if matches:
        _length, _priority, server_name, runtime_tool_name, source_scope, config_path = max(
            matches,
            key=lambda item: (item[0], item[1], item[5]),
        )
        return server_name, runtime_tool_name, source_scope, config_path
    return None


def _copilot_runtime_server_entries(home_dir: Path, workspace: Path | None) -> list[tuple[str, str, str]]:
    entries: list[tuple[str, str, str]] = []
    if workspace is not None:
        for path in (workspace / ".vscode" / "mcp.json", workspace / ".mcp.json"):
            entries.extend(_mcp_server_entries_from_path(path, source_scope="project"))
    entries.extend(_mcp_server_entries_from_path(home_dir / ".copilot" / "mcp-config.json", source_scope="global"))
    return entries


def _copilot_runtime_match_priority(*, config_path: str, preferred_workspace_config: str | None) -> int:
    path = Path(config_path)
    is_cli_workspace_config = path.name == ".mcp.json"
    is_ide_workspace_config = path.name == "mcp.json" and path.parent.name == ".vscode"
    if preferred_workspace_config == "cli":
        if is_cli_workspace_config:
            return 2
        if is_ide_workspace_config:
            return 1
        return 0
    if preferred_workspace_config == "ide":
        if is_ide_workspace_config:
            return 2
        if is_cli_workspace_config:
            return 1
        return 0
    return 0


def _resolve_copilot_workspace_root(workspace: Path | None) -> Path | None:
    if workspace is None:
        return None
    candidates = [workspace, *workspace.parents]
    for candidate in candidates:
        if (candidate / ".mcp.json").is_file() or (candidate / ".vscode" / "mcp.json").is_file():
            return candidate
    return workspace


def _mcp_server_entries_from_path(path: Path, *, source_scope: str) -> list[tuple[str, str, str]]:
    if not path.exists():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(payload, dict):
        return []
    servers = _mcp_servers_payload(payload)
    if not isinstance(servers, dict):
        return []
    return [
        (str(server_name), source_scope, str(path))
        for server_name in servers
        if isinstance(server_name, str) and server_name.strip()
    ]


def _mcp_servers_payload(payload: dict[str, object]) -> dict[str, object] | None:
    servers = payload.get("servers")
    if isinstance(servers, dict):
        return servers
    mcp_servers = payload.get("mcpServers")
    if isinstance(mcp_servers, dict):
        return mcp_servers
    return None


def _copilot_mcp_tool_token(value: str) -> str:
    token = re.sub(r"[^a-z0-9]+", "_", value.strip().lower())
    return token.strip("_")


def _runtime_policy_path(harness: str, home_dir: Path, workspace: Path | None) -> Path:
    if harness == "hermes":
        return home_dir / ".hermes" / "config.yaml"
    if harness == "claude-code":
        if workspace is not None:
            return workspace / ".claude" / "settings.local.json"
        return home_dir / ".claude" / "settings.json"
    if harness == "codex":
        if workspace is not None:
            return workspace / ".codex" / "config.toml"
        return home_dir / ".codex" / "config.toml"
    if harness == "copilot":
        if workspace is not None:
            return workspace / ".github" / "hooks" / "hol-guard-copilot.json"
        return home_dir / ".copilot" / "config.json"
    if workspace is not None:
        return workspace / ".mcp.json"
    return home_dir / ".mcp.json"


def _runtime_detection(harness: str, artifact: GuardArtifact) -> HarnessDetection:
    return HarnessDetection(
        harness=harness,
        installed=True,
        command_available=True,
        config_paths=(artifact.config_path,),
        artifacts=(artifact,),
    )


def _runtime_capabilities_summary(artifact: GuardArtifact) -> str:
    tool_name = artifact.metadata.get("tool_name")
    if isinstance(tool_name, str) and tool_name:
        if artifact.artifact_type == "tool_action_request":
            return f"tool action request • {tool_name}"
        return f"file read request • {tool_name}"
    return "file read request"


def _runtime_request_summary(artifact: GuardArtifact) -> str | None:
    summary = artifact.metadata.get("request_summary")
    if isinstance(summary, str) and summary:
        return summary
    return None


def _runtime_requested_path(artifact: GuardArtifact) -> str | None:
    normalized_path = artifact.metadata.get("normalized_path")
    if isinstance(normalized_path, str) and normalized_path:
        return normalized_path
    return None


def _canonical_harness_name(harness: str) -> str:
    try:
        return get_adapter(harness).harness
    except ValueError:
        return harness


def _managed_install_for(store: GuardStore, harness: str) -> dict[str, object] | None:
    managed_install = store.get_managed_install(_canonical_harness_name(harness))
    if managed_install is None or not bool(managed_install.get("active")):
        return None
    return managed_install


def _managed_manifest_server(
    managed_install: dict[str, object],
    server_name: str,
) -> dict[str, object] | None:
    manifest = managed_install.get("manifest")
    if not isinstance(manifest, dict):
        return None
    servers = manifest.get("servers")
    if not isinstance(servers, dict):
        return None
    server = servers.get(server_name)
    if not isinstance(server, dict):
        return None
    return server


def _server_headers(server: dict[str, object]) -> dict[str, str]:
    headers = server.get("headers")
    if not isinstance(headers, dict):
        return {}
    return {str(key): value for key, value in headers.items() if isinstance(key, str) and isinstance(value, str)}


def _server_env(server: dict[str, object]) -> dict[str, str]:
    env = server.get("env")
    if not isinstance(env, dict):
        return {}
    return {str(key): value for key, value in env.items() if isinstance(key, str) and isinstance(value, str)}


def _run_hermes_mcp_proxy(
    *,
    args: argparse.Namespace,
    context: HarnessContext,
    store: GuardStore,
    config,
) -> int:
    managed_install = _managed_install_for(store, "hermes")
    if managed_install is None:
        print("Guard is not managing Hermes in this Guard home.", file=sys.stderr)
        return 2
    manifest = managed_install.get("manifest")
    if not isinstance(manifest, dict):
        print("Hermes managed install manifest is missing.", file=sys.stderr)
        return 2
    if not isinstance(manifest.get("servers"), dict):
        print("Hermes managed install has no MCP server manifest.", file=sys.stderr)
        return 2
    server = _managed_manifest_server(managed_install, str(args.server))
    if server is None:
        print(f"Unknown Hermes MCP server: {args.server}", file=sys.stderr)
        return 2
    transport = str(server.get("transport") or "stdio")
    if transport == "http":
        base_url = server.get("url")
        if not isinstance(base_url, str) or not base_url:
            print(f"Hermes MCP server {args.server} is missing a remote URL.", file=sys.stderr)
            return 2
        proxy = RemoteGuardProxy(base_url=base_url, allow_insecure_localhost=True)
        for raw_line in sys.stdin:
            line = raw_line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"Guard Hermes MCP proxy received invalid JSON: {exc}", file=sys.stderr)
                return 2
            expect_response = message.get("id") is not None
            response = proxy.forward(
                "",
                message,
                headers=_server_headers(server),
                expect_response=expect_response,
            )
            if response is not None:
                print(json.dumps(response, separators=(",", ":")), flush=True)
        return 0
    approval_center_url = ensure_guard_daemon(context.guard_home)
    command = _server_command(server)
    if len(command) == 0:
        print(f"Hermes MCP server {args.server} is missing a launch command.", file=sys.stderr)
        return 2
    proxy = StdioGuardProxy(
        command=command,
        cwd=context.workspace_dir,
        guard_store=store,
        guard_config=config,
        approval_center_url=approval_center_url,
        harness="hermes",
        env=_server_env(server),
    )
    return proxy.run_stream(
        input_stream=sys.stdin,
        output_stream=sys.stdout,
        error_stream=sys.stderr,
    )


def _server_command(server: dict[str, object]) -> list[str]:
    command = server.get("command")
    args = server.get("args")
    command_parts: list[str] = []
    if isinstance(command, str) and command:
        command_parts.append(command)
    if isinstance(args, list):
        command_parts.extend(str(value) for value in args if isinstance(value, str) and value)
    return command_parts


def _validate_policy_scope(
    scope: str,
    artifact_id: str | None,
    workspace: Path | None,
    publisher: str | None,
) -> None:
    if scope == "artifact" and not artifact_id:
        print("--artifact-id is required when --scope artifact", file=sys.stderr)
        raise SystemExit(2)
    if scope == "workspace" and workspace is None:
        print("--workspace is required when --scope workspace", file=sys.stderr)
        raise SystemExit(2)
    if scope == "publisher" and not publisher:
        print("--publisher is required when --scope publisher", file=sys.stderr)
        raise SystemExit(2)


def _resolve_policy_expiry(args: argparse.Namespace) -> str | None:
    hours = getattr(args, "expires_in_hours", None)
    if hours is None:
        return None
    if hours <= 0:
        print("--expires-in-hours must be greater than 0.", file=sys.stderr)
        raise SystemExit(2)
    return (datetime.now(timezone.utc) + timedelta(hours=float(hours))).isoformat()


def _synced_policy_payload(store: GuardStore) -> dict[str, object] | None:
    payload = store.get_sync_payload("policy")
    return payload if isinstance(payload, dict) else None


def _refresh_cloud_policy_bundle(store: GuardStore) -> None:
    if store.get_sync_credentials() is None:
        return
    try:
        sync_receipts(store)
    except Exception:
        return


def _filter_policy_items(items: list[dict[str, object]], *, active_only: bool) -> list[dict[str, object]]:
    if not active_only:
        return items
    current_time = datetime.now(timezone.utc)
    filtered: list[dict[str, object]] = []
    for item in items:
        expires_at = item.get("expires_at")
        if not isinstance(expires_at, str) or not expires_at.strip():
            filtered.append(item)
            continue
        try:
            expires_on = datetime.fromisoformat(expires_at)
        except ValueError:
            filtered.append(item)
            continue
        if expires_on > current_time:
            filtered.append(item)
    return filtered


def _run_guard_connect_flow(
    *,
    guard_home: Path,
    store: GuardStore,
    sync_url: str,
    connect_url: str,
    wait_timeout_seconds: int,
) -> dict[str, object]:
    return run_guard_connect_command(
        guard_home=guard_home,
        store=store,
        sync_url=sync_url,
        connect_url=connect_url,
        opener=webbrowser.open,
        wait_timeout_seconds=wait_timeout_seconds,
    )


def _manual_guard_login_payload(
    *,
    args: argparse.Namespace,
    store: GuardStore,
) -> tuple[dict[str, object] | None, int] | None:
    manual_token = _optional_string(getattr(args, "token", None))
    if manual_token is None:
        return None
    manual_sync_url = _optional_string(getattr(args, "sync_url", None))
    if manual_sync_url is None:
        print(
            "Pass both --sync-url and --token to save credentials manually, "
            "or run `hol-guard login` with no token to open browser sign-in.",
            file=sys.stderr,
        )
        return None, 2
    store.set_sync_credentials(manual_sync_url, manual_token, _now())
    store.add_event("sign_in", {"sync_url": manual_sync_url, "source": "local-cli"}, _now())
    return {"logged_in": True, "sync_url": manual_sync_url}, 0


def _guard_sync_prerequisite_message() -> str:
    return (
        "Guard Cloud is not connected yet. Run `hol-guard connect` to sign in and pair this machine, "
        "or use `hol-guard login` as a compatibility alias for the same browser flow."
    )


def _build_abom_payload(store: GuardStore) -> dict[str, object]:
    inventory = store.list_inventory()
    artifacts = []
    markdown_lines = [
        "# HOL Guard ABOM",
        "",
        "| Artifact | Harness | Type | Scope | Verdict | Present | Last changed |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for item in inventory:
        trust_verdict = str(item.get("last_policy_action") or "unknown")
        artifacts.append({**item, "trust_verdict": trust_verdict})
        markdown_lines.append(
            "| "
            f"{item['artifact_name']} | {item['harness']} | {item['artifact_type']} | {item['source_scope']} | "
            f"{trust_verdict} | {'yes' if item['present'] else 'no'} | {item.get('last_changed_at') or 'never'} |"
        )
    return {
        "generated_at": _now(),
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
        "markdown": "\n".join(markdown_lines) + "\n",
    }


def _build_explain_payload(
    store: GuardStore,
    target: str,
    options: ScanOptions | None = None,
) -> dict[str, object]:
    target_path = Path(target).expanduser()
    if target_path.exists():
        return run_consumer_scan(target_path.resolve(), options=options)
    inventory_item = store.find_inventory_item(target)
    if inventory_item is None:
        raise ValueError(f"Guard does not know artifact {target}.")
    advisories = _matching_advisories(store, inventory_item.get("publisher"))
    latest_receipt = store.get_latest_receipt(str(inventory_item["harness"]), str(inventory_item["artifact_id"]))
    latest_diff = store.get_latest_diff(str(inventory_item["harness"]), str(inventory_item["artifact_id"]))
    return {
        "generated_at": _now(),
        "artifact": inventory_item,
        "latest_receipt": latest_receipt,
        "latest_diff": latest_diff,
        "advisories": advisories,
    }


def _build_explain_payload_with_mode(store: GuardStore, target: str, cisco_mode: str) -> dict[str, object]:
    options = _resolve_cisco_scan_options(cisco_mode)
    if options is None:
        return _build_explain_payload(store, target)
    return _build_explain_payload(store, target, options=options)


def _matching_advisories(store: GuardStore, publisher: object) -> list[dict[str, object]]:
    if not isinstance(publisher, str) or not publisher.strip():
        return []
    return [item for item in store.list_cached_advisories() if item.get("publisher") == publisher]
