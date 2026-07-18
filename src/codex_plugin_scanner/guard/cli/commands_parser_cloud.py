"""Guard CLI parser cloud and hidden command groups."""

# fmt: off
# ruff: noqa: F403, F405, I001

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ._commands_shared import _SERVICE_RUNTIME_CHOICES


import argparse

from ._commands_shared import *
from .commands_parser_helpers import *

def _configure_guard_cloud_parsers(
    guard_subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    login_parser = guard_subparsers.add_parser(
        "login",
        help="Compatibility alias for Guard Cloud browser sign-in and pairing",
    )
    login_parser.add_argument("--sync-url", type=_guard_http_url)
    login_parser.add_argument("--token")
    login_parser.add_argument("--connect-url", default=DEFAULT_GUARD_CONNECT_URL, type=_guard_http_url)
    login_parser.add_argument("--wait-timeout-seconds", type=int, default=180)
    login_parser.add_argument("--home")
    login_parser.add_argument("--guard-home")
    login_parser.add_argument(
        "--source",
        default="default",
        help="Named connection profile for multi-environment usage.",
    )
    login_parser.add_argument("--json", action="store_true")

    connect_parser = guard_subparsers.add_parser(
        "connect",
        help="Open browser OAuth, pair this runtime to HOL Guard, and send the first sync",
    )
    connect_parser.add_argument(
        "connect_command",
        nargs="?",
        choices=("status", "repair", "re-pair", "sources", "reassign-quarantined"),
    )
    _add_guard_common_args(connect_parser)
    connect_parser.add_argument("--sync-url", default=DEFAULT_GUARD_SYNC_URL, type=_guard_http_url)
    connect_parser.add_argument("--connect-url", default=DEFAULT_GUARD_CONNECT_URL, type=_guard_http_url)
    connect_parser.add_argument("--wait-timeout-seconds", type=int, default=180)
    connect_parser.add_argument("--headless", action="store_true")
    connect_parser.add_argument(
        "--ci-safe",
        action="store_true",
        help=(
            "Use restricted headless OAuth scopes and require explicit workspace metadata "
            "for CI or hosted automation."
        ),
    )
    connect_parser.add_argument(
        "--label",
        help="With --ci-safe, require an explicit label for the CI or hosted runtime being connected.",
    )
    connect_parser.add_argument(
        "--open-browser",
        action="store_true",
        help="With --headless, open the Device Code approval page before waiting for approval.",
    )
    connect_parser.add_argument(
        "--no-browser",
        action="store_true",
        dest="headless",
        help="Alias for --headless. Start Device Code approval without opening a browser.",
    )
    connect_parser.add_argument(
        "--source",
        default="default",
        help="Named connection profile for multi-environment usage (e.g. 'staging'). Defaults to 'default'.",
    )
    connect_parser.add_argument(
        "--confirm-source",
        help="With reassign-quarantined, approve the exact destination source name.",
    )
    connect_parser.add_argument(
        "--confirm-workspace",
        help="With reassign-quarantined, approve the exact destination workspace ID.",
    )
    connect_parser.add_argument("--json", action="store_true")

    remote_pair_parser = guard_subparsers.add_parser(
        "remote-pair",
        help="Pair a hosted OpenClaw or Hermes runtime with a Guard Cloud pairing code",
    )
    remote_pair_parser.add_argument(
        "remote_pair_command",
        nargs="?",
        choices=("status",),
        help="Inspect remote pairing status without claiming a new code",
    )
    remote_pair_parser.add_argument("--runtime", choices=("openclaw", "hermes"))
    remote_pair_parser.add_argument("--pair-code")
    remote_pair_parser.add_argument("--label")
    remote_pair_parser.add_argument(
        "--no-root",
        action="store_true",
        help="Install and pair using user-space paths only; refuse root or sudo sessions",
    )
    remote_pair_parser.add_argument(
        "--verify",
        action="store_true",
        help="Run the first Guard Cloud sync after pairing succeeds",
    )
    remote_pair_parser.add_argument("--connect-url", default=DEFAULT_GUARD_CONNECT_URL, type=_guard_http_url)
    _add_guard_common_args(remote_pair_parser)
    remote_pair_parser.add_argument("--json", action="store_true")

    disconnect_parser = guard_subparsers.add_parser(
        "disconnect",
        help="Revoke local Guard Cloud OAuth credentials and optionally revoke the cloud grant",
    )
    _add_guard_common_args(disconnect_parser)
    disconnect_parser.add_argument(
        "--revoke-cloud-grant",
        action="store_true",
        help="Also revoke the machine and runtime grant state in Guard Cloud.",
    )
    disconnect_parser.add_argument(
        "--source",
        default="default",
        help="Named connection profile to disconnect. Defaults to 'default'.",
    )
    disconnect_parser.add_argument("--json", action="store_true")

    sync_parser = guard_subparsers.add_parser("sync", help="Sync receipts to the configured Guard endpoint")
    sync_parser.add_argument("--home")
    sync_parser.add_argument("--guard-home")
    sync_parser.add_argument(
        "--source",
        default="default",
        help="Named connection profile to sync from. Defaults to 'default'.",
    )
    sync_parser.add_argument("--json", action="store_true")
    sync_parser.add_argument(
        "--deep",
        action="store_true",
        help="Also refresh AIBOM inventory during this foreground sync.",
    )

    commands_parser = guard_subparsers.add_parser(
        "commands",
        help="Inspect Guard Cloud command queue state",
    )
    _add_guard_common_args(commands_parser)
    commands_subparsers = commands_parser.add_subparsers(
        dest="commands_command",
        required=True,
        parser_class=FriendlyArgumentParser,
    )
    commands_status_parser = commands_subparsers.add_parser(
        "status",
        help="Show local Guard Cloud command queue status",
    )
    _add_guard_common_args(commands_status_parser)
    commands_status_parser.add_argument("--json", action="store_true")
    commands_enable_parser = commands_subparsers.add_parser(
        "enable",
        help="Opt this device into an exact set of Guard Cloud command operations",
    )
    _add_guard_common_args(commands_enable_parser)
    commands_enable_parser.add_argument(
        "--operations",
        action="append",
        required=True,
        metavar="OPERATION[,OPERATION...]",
        help="Use 'read-only' or list exact operation names; may be repeated",
    )
    commands_enable_parser.add_argument(
        "--expires-in-days",
        type=int,
        default=30,
        help="Capability lifetime from 1 through 365 days (default: 30)",
    )
    commands_enable_parser.add_argument("--json", action="store_true")
    commands_approve_parser = commands_subparsers.add_parser(
        "approve",
        help="Approve one pending state-changing Cloud command on this device",
    )
    _add_guard_common_args(commands_approve_parser)
    commands_approve_parser.add_argument("job_id", metavar="JOB_ID")
    commands_approve_parser.add_argument(
        "--confirm",
        required=True,
        metavar="JOB_ID",
        help="Repeat the exact job id to prevent accidental approval",
    )
    commands_approve_parser.add_argument("--json", action="store_true")
    commands_revoke_parser = commands_subparsers.add_parser(
        "revoke",
        help="Revoke this device's Guard Cloud command capability",
    )
    _add_guard_common_args(commands_revoke_parser)
    commands_revoke_parser.add_argument(
        "--confirm",
        required=True,
        choices=("revoke",),
        help="Confirm local command capability revocation",
    )
    commands_revoke_parser.add_argument("--json", action="store_true")

    cloud_parser = guard_subparsers.add_parser(
        "cloud",
        help="Sync Guard Cloud supply-chain intelligence and diagnostics",
    )
    cloud_subparsers = cloud_parser.add_subparsers(
        dest="cloud_command",
        required=True,
        parser_class=FriendlyArgumentParser,
    )
    cloud_sync_intel_parser = cloud_subparsers.add_parser(
        "sync-intel",
        help="Fetch and verify the latest Guard supply-chain bundle for this workspace",
    )
    _add_guard_common_args(cloud_sync_intel_parser)
    cloud_sync_intel_parser.add_argument("--json", action="store_true")

    supply_chain_parser = guard_subparsers.add_parser(
        "supply-chain",
        help="Inspect and refresh local Guard supply-chain firewall coverage",
    )
    _add_guard_common_args(supply_chain_parser)
    supply_chain_subparsers = supply_chain_parser.add_subparsers(
        dest="supply_chain_command",
        required=True,
        parser_class=FriendlyArgumentParser,
    )
    supply_chain_scan_parser = supply_chain_subparsers.add_parser(
        "scan",
        help="Evaluate the current workspace manifests and lockfiles against the signed bundle",
    )
    _add_guard_common_args(supply_chain_scan_parser)
    supply_chain_scan_parser.add_argument("--json", action="store_true")
    supply_chain_audit_parser = supply_chain_subparsers.add_parser(
        "audit",
        help="Audit workspace dependencies with local inventory extraction and Guard Cloud batch evaluation",
    )
    _add_guard_common_args(supply_chain_audit_parser)
    supply_chain_audit_parser.add_argument("--after-workspace")
    supply_chain_audit_parser.add_argument("--before-workspace")
    supply_chain_audit_parser.add_argument("--ci", action="store_true")
    supply_chain_audit_parser.add_argument("--fail-on", choices=("low", "medium", "high", "critical"), default="high")
    supply_chain_audit_parser.add_argument("--sbom", action="append", default=[])
    supply_chain_audit_parser.add_argument("--json", action="store_true")
    supply_chain_sync_parser = supply_chain_subparsers.add_parser(
        "sync",
        help="Fetch and verify the latest signed supply-chain bundle for this workspace",
    )
    _add_guard_common_args(supply_chain_sync_parser)
    supply_chain_sync_parser.add_argument("--json", action="store_true")
    supply_chain_explain_parser = supply_chain_subparsers.add_parser(
        "explain",
        help="Explain one package version with the current signed supply-chain bundle",
    )
    supply_chain_explain_parser.add_argument("package")
    supply_chain_explain_parser.add_argument(
        "--ecosystem",
        choices=("npm", "pypi", "cargo", "go", "maven", "packagist", "rubygems"),
        default="npm",
    )
    _add_guard_common_args(supply_chain_explain_parser)
    supply_chain_explain_parser.add_argument("--json", action="store_true")

    supply_chain_matrix_parser = supply_chain_subparsers.add_parser(
        "support-matrix",
        help="Print supported package managers and probe coverage as JSON",
    )
    _add_guard_common_args(supply_chain_matrix_parser)
    supply_chain_matrix_parser.add_argument("--json", action="store_true")

    service_parser = guard_subparsers.add_parser(
        "service",
        help="Manage headless hosted-runtime Guard Cloud login, sync, and status",
    )
    service_subparsers = service_parser.add_subparsers(
        dest="service_command",
        required=True,
        parser_class=FriendlyArgumentParser,
    )

    service_login_parser = service_subparsers.add_parser(
        "login",
        help="Redirect to `hol-guard connect`; pasted hosted-runtime tokens are retired",
    )
    _add_guard_common_args(service_login_parser)
    service_login_parser.add_argument("--runtime", choices=_SERVICE_RUNTIME_CHOICES, required=True)
    service_login_parser.add_argument("--label", required=True)
    service_login_parser.add_argument("--sync-url", type=_guard_http_url)
    service_login_parser.add_argument("--token")
    service_login_parser.add_argument("--json", action="store_true")

    service_sync_parser = service_subparsers.add_parser(
        "sync",
        help="Publish the hosted runtime session, then sync receipts",
    )
    _add_guard_common_args(service_sync_parser)
    service_sync_parser.add_argument("--json", action="store_true")

    service_status_parser = service_subparsers.add_parser(
        "status",
        help="Show hosted-runtime Guard Cloud login state and latest sync summaries",
    )
    _add_guard_common_args(service_status_parser)
    service_status_parser.add_argument("--json", action="store_true")

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
    bridge_parser.add_argument(
        "--webhook-include-artifact-details",
        action="store_true",
        help="Include artifact details in webhook notifications",
    )
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
        choices=GUARD_ACTION_VALUES,
    )
    hook_parser.add_argument("--event-file")
    hook_parser.add_argument("--json", action="store_true")

    daemon_parser = guard_subparsers.add_parser("daemon", help=argparse.SUPPRESS)
    _add_guard_common_args(daemon_parser)
    daemon_parser.add_argument("--serve", action="store_true")
    daemon_parser.add_argument("--port", type=int)
    daemon_subparsers = daemon_parser.add_subparsers(dest="daemon_command")
    status_p = daemon_subparsers.add_parser("status", help="Show local Guard daemon status")
    _add_guard_common_args(status_p)
    status_p.add_argument("--json", action="store_true")
    repair_p = daemon_subparsers.add_parser("repair", help="Repair stale Guard daemon state")
    _add_guard_common_args(repair_p)
    repair_p.add_argument("--json", action="store_true")
    stop_p = daemon_subparsers.add_parser("stop", help="Stop a running Guard daemon")
    _add_guard_common_args(stop_p)
    stop_p.add_argument("--json", action="store_true")

    codex_proxy_parser = guard_subparsers.add_parser("codex-mcp-proxy", help=argparse.SUPPRESS)
    _add_guard_common_args(codex_proxy_parser)
    codex_proxy_parser.add_argument("--server-name", required=True)
    codex_proxy_parser.add_argument("--server-id")
    codex_proxy_parser.add_argument("--source-scope", default="project")
    codex_proxy_parser.add_argument("--config-path", required=True)
    codex_proxy_parser.add_argument("--transport", default="stdio")
    codex_proxy_parser.add_argument("--command", dest="server_command", required=True)
    codex_proxy_parser.add_argument("--arg", dest="server_args", action="append", default=[])
    codex_proxy_parser.add_argument("--server-env-key", dest="server_env_keys", action="append", default=[])

    opencode_proxy_parser = guard_subparsers.add_parser("opencode-mcp-proxy", help=argparse.SUPPRESS)
    _add_guard_common_args(opencode_proxy_parser)
    opencode_proxy_parser.add_argument("--server-name", required=True)
    opencode_proxy_parser.add_argument("--server-id")
    opencode_proxy_parser.add_argument("--source-scope", default="project")
    opencode_proxy_parser.add_argument("--config-path", required=True)
    opencode_proxy_parser.add_argument("--transport", default="local")
    opencode_proxy_parser.add_argument("--command", dest="server_command", required=True)
    opencode_proxy_parser.add_argument("--arg", dest="server_args", action="append", default=[])
    opencode_proxy_parser.add_argument("--server-env-key", dest="server_env_keys", action="append", default=[])

    copilot_proxy_parser = guard_subparsers.add_parser("copilot-mcp-proxy", help=argparse.SUPPRESS)
    _add_guard_common_args(copilot_proxy_parser)
    copilot_proxy_parser.add_argument("--server-name", required=True)
    copilot_proxy_parser.add_argument("--server-id")
    copilot_proxy_parser.add_argument("--source-scope", default="project")
    copilot_proxy_parser.add_argument("--config-path", required=True)
    copilot_proxy_parser.add_argument("--transport", default="stdio")
    copilot_proxy_parser.add_argument("--command", dest="server_command", required=True)
    copilot_proxy_parser.add_argument("--arg", dest="server_args", action="append", default=[])
    copilot_proxy_parser.add_argument("--server-env-key", dest="server_env_keys", action="append", default=[])

    cursor_proxy_parser = guard_subparsers.add_parser("cursor-mcp-proxy", help=argparse.SUPPRESS)
    _add_guard_common_args(cursor_proxy_parser)
    cursor_proxy_parser.add_argument("--server-name", required=True)
    cursor_proxy_parser.add_argument("--server-id")
    cursor_proxy_parser.add_argument("--source-scope", default="project")
    cursor_proxy_parser.add_argument("--config-path", required=True)
    cursor_proxy_parser.add_argument("--transport", default="stdio")
    cursor_proxy_parser.add_argument("--command", dest="server_command", required=True)
    cursor_proxy_parser.add_argument("--arg", dest="server_args", action="append", default=[])
    cursor_proxy_parser.add_argument("--server-env-key", dest="server_env_keys", action="append", default=[])

    hermes_mcp_proxy_parser = guard_subparsers.add_parser("hermes-mcp-proxy", help=argparse.SUPPRESS)
    _add_guard_common_args(hermes_mcp_proxy_parser)
    hermes_mcp_proxy_parser.add_argument("--server", required=True)
    hermes_mcp_proxy_parser.add_argument("--stdio", action="store_true")

    mcp_parser = guard_subparsers.add_parser(
        "mcp",
        help="Serve the local Guard MCP server (guard-mcp.v1)",
    )
    mcp_subparsers = mcp_parser.add_subparsers(
        dest="mcp_command",
        required=True,
        parser_class=FriendlyArgumentParser,
    )
    mcp_serve_parser = mcp_subparsers.add_parser(
        "serve",
        help="Start the MCP server over stdio transport",
    )
    _add_guard_common_args(mcp_serve_parser)
    mcp_serve_parser.add_argument("--stdio", action="store_true", default=True)
    hidden_commands = {
        "admin",
        "hook",
        "daemon",
        "codex-mcp-proxy",
        "opencode-mcp-proxy",
        "copilot-mcp-proxy",
        "cursor-mcp-proxy",
        "hermes-mcp-proxy",
    }
    guard_subparsers._choices_actions = [
        action for action in guard_subparsers._choices_actions if action.dest not in hidden_commands
    ]

__all__ = [
    "_configure_guard_cloud_parsers",
]
