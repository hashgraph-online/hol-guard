"""Guard CLI parser construction helpers."""

# fmt: off
# ruff: noqa: F401

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import http.client
import json
import os
import re
import secrets
import shlex
import sqlite3
import subprocess
import sys
import urllib.error
import urllib.parse
import webbrowser
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Protocol, TextIO

from ...argparse_utils import FriendlyArgumentParser
from ...models import ScanOptions
from ..adapters import get_adapter
from ..adapters.base import HarnessContext
from ..aibom_cli import (
    AibomCliOptions,
    build_aibom_export_payload,
    build_aibom_status_payload,
    build_inventory_json_payload,
    sync_aibom_snapshots,
)
from ..approval_gate import (
    ApprovalGateError,
    ApprovalGateInput,
    begin_totp_enrollment,
    confirm_totp_enrollment,
    disable_totp,
    require_approval_decision,
    require_high_risk,
)
from ..approval_gate import (
    public_config as approval_gate_public_config,
)
from ..approval_gate import (
    update_settings as update_approval_gate_settings,
)
from ..approvals import (
    approval_center_hint,
    approval_delivery_payload,
    approval_prompt_flow,
    attach_primary_approval_link,
    build_approval_browser_url,
    first_approval_url,
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
from ..codex_app_server import codex_resume_metadata_from_hook_payload
from ..codex_resume import inspect_codex_resume_capabilities
from ..config import (
    DEFAULT_SECURITY_LEVEL,
    VALID_RISK_ACTION_KEYS,
    VALID_SECURITY_LEVELS,
    GuardConfig,
    editable_guard_settings,
    load_guard_config,
    overlay_synced_guard_policy,
    resolve_guard_home,
    resolve_risk_action,
    update_guard_settings,
)
from ..consumer import (
    artifact_hash,
    detect_all,
    detect_harness,
    evaluate_detection,
    record_policy,
    run_consumer_scan,
)
from ..daemon import (
    GuardDaemonServer,
    ensure_guard_daemon,
    load_guard_surface_daemon_client,
    repair_approval_center_locator,
)
from ..daemon.manager import (
    _guard_daemon_pid_is_running,
    _guard_daemon_pid_matches_command,
    load_guard_daemon_auth_token,
    load_guard_daemon_url,
)
from ..desktop_notifications import (
    desktop_notification_setup_payload,
    desktop_notification_setup_supported,
    ensure_desktop_notification_setup,
    macos_notification_guidance,
)
from ..harness_usage import record_harness_usage_events
from ..incident import build_incident_context
from ..local_dashboard_session import build_local_dashboard_session_token
from ..local_supply_chain import (
    build_local_supply_chain_posture,
    build_supply_chain_explain_payload,
    build_supply_chain_status_payload,
    build_workspace_audit_payload,
    build_workspace_scan_payload,
    resolve_package_firewall_entitlement_with_refresh,
)
from ..mcp_tool_calls import (
    allow_tool_call,
    block_tool_call,
    build_tool_call_artifact,
    build_tool_call_hash,
    evaluate_tool_call,
)
from ..models import SEVERITY_RANK, GuardArtifact, HarnessDetection, PolicyDecision
from ..package_firewall_entitlement import (
    package_firewall_action_states,
    package_firewall_available_actions,
    package_firewall_block_details,
)
from ..policy.engine import SAFE_CHANGED_HASH_ACTION, VALID_GUARD_ACTIONS, build_decision_v2, guard_action_severity
from ..protect import build_protect_payload
from ..proxy import (
    CodexMcpGuardProxy,
    CopilotMcpGuardProxy,
    CursorMcpGuardProxy,
    OpenCodeMcpGuardProxy,
    RemoteGuardProxy,
    StdioGuardProxy,
)
from ..receipts import build_receipt
from ..risk import artifact_risk_signals, artifact_risk_signals_v2, artifact_risk_summary
from ..runtime.actions import GuardActionEnvelope, normalize_harness_payload
from ..runtime.cisco_preflight import (
    build_cisco_deep_scan_payload,
    cisco_risk_signal_v3_to_v2,
    policy_action_for_cisco_signals,
    scan_action_for_cisco_evidence,
)
from ..runtime.data_flow_rules import detect_data_flow_exfiltration
from ..runtime.false_positive_rules import (
    SOURCE_INSPECTION_BENIGN_DOTFILES,
    SOURCE_INSPECTION_EXTENSIONS,
    SOURCE_INSPECTION_PARTS,
    SOURCE_INSPECTION_SENSITIVE_PARTS,
    fd_arg_requests_exec,
    fd_args_follow_symlinks,
    fd_exec_token_is_plain_sed,
    fd_search_targets,
    split_fd_args_and_exec,
    target_is_known_skill_doc_path,
)
from ..runtime.harness_attribution import resolve_runtime_hook_harness
from ..runtime.package_intent import build_package_request_artifact, extract_package_intent_request
from ..runtime.runner import (
    GuardSyncAuthorizationExpiredError,
    GuardSyncNotAvailableError,
    GuardSyncNotConfiguredError,
    extract_prompt_requests,
    guard_run,
    prompt_requests_to_artifacts,
    sync_local_guard_cloud_proof,
    sync_receipts,
    sync_runtime_session,
    sync_supply_chain_bundle,
)
from ..runtime.secret_file_requests import (
    build_file_read_request_artifact,
    build_tool_action_request_artifact,
    extract_sensitive_file_read_request,
    extract_sensitive_file_read_request_from_action,
    extract_sensitive_tool_action_request,
    is_explicitly_benign_tool_action_request,
)
from ..runtime.secret_sensitivity import (
    SecretContentMatch,
    SecretPathMatch,
    classify_secret_content,
    classify_secret_path,
)
from ..runtime.sed_scripts import sed_script_is_bounded_print
from ..runtime.signals import RiskSignalV2
from ..runtime.supply_chain_package_eval import evaluate_package_request_artifact
from ..runtime.surface_server import GuardSurfaceRuntime
from ..shims import activate_package_shims, package_shim_status, uninstall_package_shims
from ..store import GuardStore
from .approval_commands import (
    add_approval_parser,
    run_approval_command,
    run_approval_open_command,
    run_approval_resume_command,
    run_approval_retry_hint_command,
)
from .approval_gate_prompt import approval_gate_cli_payload, prompt_for_approval_gate
from .bootstrap import DEFAULT_ALIAS_NAME, build_guard_bootstrap_payload
from .connect_flow import (
    CONNECT_SYNC_AUTH_CONTEXT_KEY,
    DEFAULT_GUARD_CONNECT_URL,
    DEFAULT_GUARD_SYNC_URL,
    build_connect_status_payload,
    connect_recovery_command,
    resolve_connect_url,
    run_guard_browser_connect_command,
    run_guard_connect_repair_command,
    run_guard_device_connect_command,
    run_guard_disconnect_command,
)
from .docs import build_install_connect_docs_payload
from .install_commands import (
    apply_managed_install,
    build_harness_setup_plan,
    build_harness_verification,
    list_harness_setup_items,
    uninstall_confirmation_token,
)
from .product import build_guard_start_payload, build_guard_status_payload
from .protect_approvals import _queue_local_protect_approvals, _suppress_package_shim_allow_output
from .remote_pair_flow import dispatch_guard_remote_pair_command
from .update_commands import run_guard_update

DEFAULT_GUARD_APPS_URL = "https://hol.org/guard/apps"


class GuardBrowserOpener(Protocol):
    def __call__(self, url: str) -> bool: ...


_GUARD_CLIENT_VERSION = "2.0.0"
_SERVICE_RUNTIME_PROFILE_STATE_KEY = "service_runtime_profile"
_SERVICE_RUNTIME_CHOICES = ("hermes", "openclaw", "custom")
_SERVICE_RUNTIME_SURFACE = "agent-sdk"
_NAMED_SECURITY_LEVELS = {"relaxed", "balanced", "strict", "gentle", "paranoid"}
_HOOK_DAEMON_FAILURE_STATUSES = frozenset({"unreachable", "error", "failed", "404"})
_HOOK_DAEMON_FAIL_MODES = frozenset({"strict", "permissive"})
_HOOK_DAEMON_UNREACHABLE_REASON_MARKER = "daemon was unreachable"
_HOOK_DAEMON_STRICT_REASON = (
    "HOL Guard fail safe: the local Guard daemon was unreachable, so this hook blocked the action."
)
_HOOK_DAEMON_PERMISSIVE_REASON = (
    "HOL Guard daemon was unreachable; permissive mode allowed this action and recorded the degraded state."
)
_HOOK_DAEMON_PRESERVED_DENY_REASON = (
    "HOL Guard daemon was unreachable; preserving the existing deny decision for this action."
)
_CODEX_PROMPT_APPROVAL_WAIT_MAX_SECONDS = 8
_GUARD_HELP_GROUPS = (
    "HOL Guard AI Antivirus command center:\n"
    "  start        First-run protection setup for one local AI harness\n"
    "  status       Home: current protection state, proof, and next action\n"
    "  dashboard    Open local Home, Protect, Inbox, Evidence, and Settings\n"
    "  apps         Protect: connect, test, repair, or disconnect AI tools\n"
    "  run          Enforce Guard before a harness launch\n"
    "  approvals    Inbox: approve, block, or scope requests needing judgment\n"
    "  receipts     Evidence: review local decisions and proof receipts\n"
    "\n"
    "Team and cloud coordination:\n"
    "  connect      Pair this machine to Guard Cloud\n"
    "  disconnect   Revoke local Guard Cloud auth and optionally revoke cloud grant state\n"
    "  login        Compatibility alias for browser pairing\n"
    "  sync         Send local decisions, receipts, and policy memory to Guard Cloud\n"
    "  service      Manage hosted-runtime Guard Cloud login and sync\n"
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
    "  abom         Export the local artifact bill of materials\n"
    "  aibom        Export the local AIBOM with trust and source metadata\n"
    "  explain      Show evidence for one artifact\n"
    "  policies     Inspect local Guard policy state\n"
    "  settings     Settings: show or update local Guard rules\n"
    "  exceptions   Inspect active exception windows\n"
    "  advisories   Inspect cached Guard Cloud advisories\n"
    "  events       Review Guard lifecycle events\n"
    "  doctor       Run local diagnostics\n"
    "  bootstrap    Detect, install, and launch the approval center\n"
    "  install      Enable Guard management for a harness\n"
    "  uninstall    Disable Guard management for a harness\n"
    "  update       Update hol-guard in the current environment\n"
    "\n"
    "Command selection:\n"
    "  Use status for Home posture and the next safe step\n"
    "  Use apps for Protect install, repair, status, and first protected action proof\n"
    "  Use approvals for Inbox decisions and receipts for Evidence\n"
    "  Use doctor for setup and runtime probes\n"
    "  Use diff for changed artifacts after a blocked launch\n"
    "  Use explain for detailed artifact evidence\n"
    "  Use events for the local timeline"
)


def _guard_risk_action_key(value: str) -> str:
    normalized = value.strip().lower().replace("-", "_")
    if normalized not in VALID_RISK_ACTION_KEYS:
        raise argparse.ArgumentTypeError(f"invalid risk class: {value}")
    return normalized


def _hook_command_text(payload: Mapping[str, object]) -> str | None:
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, Mapping):
        return None
    for key in ("command", "cmd", "shell_command", "shellCommand"):
        value = tool_input.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None
def add_guard_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register Guard as a nested command family."""

    program_name = Path(sys.argv[0]).name or "plugin-scanner"
    guard_parser = subparsers.add_parser(
        "guard",
        help="Run HOL Guard AI Antivirus workflows",
        description=(
            "HOL Guard is AI Antivirus for local harnesses. It keeps Home, Protect, "
            "Inbox, Evidence, and Settings aligned with this machine."
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

    parser.description = "HOL Guard AI Antivirus protects local harnesses before new or changed tools run."
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
            "{start,status,dashboard,init,apps,bootstrap,detect,install,update,uninstall,package-shims,run,protect,preflight,scan,diff,"
            "receipts,inventory,abom,aibom,approvals,explain,allow,deny,policies,exceptions,advisories,events,doctor,connect,"
            "remote-pair,disconnect,"
            "login,sync,device,bridge}"
        ),
    )

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

    policies_parser = guard_subparsers.add_parser("policies", help="List or clear stored Guard policy decisions")
    policies_parser.add_argument("policies_command", nargs="?", choices=("clear",))
    policies_parser.add_argument("--harness")
    policies_parser.add_argument("--source")
    policies_parser.add_argument("--scope", choices=("artifact", "workspace", "publisher", "harness", "global"))
    policies_parser.add_argument("--artifact-id")
    policies_parser.add_argument("--artifact-hash")
    policies_parser.add_argument("--policy-workspace", dest="policy_workspace")
    policies_parser.add_argument("--publisher")
    policies_parser.add_argument(
        "--all",
        action="store_true",
        help="Clear decisions across every harness; cannot be combined with --harness",
    )
    _add_guard_common_args(policies_parser)
    policies_parser.add_argument("--json", action="store_true")

    settings_parser = guard_subparsers.add_parser("settings", help="Show or update local Guard settings")
    _add_guard_common_args(settings_parser)
    settings_parser.add_argument("--json", action="store_true")
    settings_subparsers = settings_parser.add_subparsers(
        dest="settings_command",
        parser_class=FriendlyArgumentParser,
    )
    settings_set_parser = settings_subparsers.add_parser("set", help="Update local Guard settings")
    _add_guard_common_args(settings_set_parser)
    settings_set_parser.add_argument("--json", action="store_true")
    settings_set_subparsers = settings_set_parser.add_subparsers(
        dest="settings_set_command",
        required=True,
        parser_class=FriendlyArgumentParser,
    )
    settings_security_parser = settings_set_subparsers.add_parser("security-level", help="Set Guard security level")
    settings_security_parser.add_argument("security_level", choices=tuple(sorted(VALID_SECURITY_LEVELS)))
    _add_guard_common_args(settings_security_parser)
    settings_security_parser.add_argument("--json", action="store_true")
    settings_risk_parser = settings_set_subparsers.add_parser("risk", help="Set a granular risk action")
    settings_risk_parser.add_argument("risk_class", type=_guard_risk_action_key)
    settings_risk_parser.add_argument("action", choices=tuple(sorted(VALID_GUARD_ACTIONS)))
    settings_risk_parser.add_argument("--harness")
    _add_guard_common_args(settings_risk_parser)
    settings_risk_parser.add_argument("--json", action="store_true")
    settings_preset_parser = settings_set_subparsers.add_parser("preset", help="Apply a named security preset")
    settings_preset_parser.add_argument("preset", choices=tuple(sorted(VALID_SECURITY_LEVELS)))
    _add_guard_common_args(settings_preset_parser)
    settings_preset_parser.add_argument("--json", action="store_true")
    settings_secret_files_parser = settings_set_subparsers.add_parser(
        "secret-files", help="Set action for local secret file reads"
    )
    settings_secret_files_parser.add_argument("action", choices=("ask", "warn", "allow"))
    _add_guard_common_args(settings_secret_files_parser)
    settings_secret_files_parser.add_argument("--json", action="store_true")
    settings_network_parser = settings_set_subparsers.add_parser(
        "network", help="Set action for outbound network calls"
    )
    settings_network_parser.add_argument("action", choices=("warn", "ask", "block"))
    _add_guard_common_args(settings_network_parser)
    settings_network_parser.add_argument("--json", action="store_true")
    settings_mcp_parser = settings_set_subparsers.add_parser("mcp", help="Set MCP tool call approval policy")
    settings_mcp_parser.add_argument("policy", choices=("allow-known", "ask-new", "ask-dangerous", "ask-all"))
    _add_guard_common_args(settings_mcp_parser)
    settings_mcp_parser.add_argument("--json", action="store_true")
    settings_skills_parser = settings_set_subparsers.add_parser("skills", help="Set skill install approval policy")
    settings_skills_parser.add_argument("policy", choices=("allow-known", "ask-new", "ask-dangerous", "ask-all"))
    _add_guard_common_args(settings_skills_parser)
    settings_skills_parser.add_argument("--json", action="store_true")
    settings_packages_parser = settings_set_subparsers.add_parser(
        "packages", help="Set package install approval policy"
    )
    settings_packages_parser.add_argument("policy", choices=("warn", "ask-lifecycle", "ask-all"))
    _add_guard_common_args(settings_packages_parser)
    settings_packages_parser.add_argument("--json", action="store_true")
    settings_encoded_parser = settings_set_subparsers.add_parser(
        "encoded-payloads", help="Set encoded payload detection action"
    )
    settings_encoded_parser.add_argument("action", choices=("warn", "ask", "block"))
    _add_guard_common_args(settings_encoded_parser)
    settings_encoded_parser.add_argument("--json", action="store_true")
    settings_output_parser = settings_set_subparsers.add_parser("output-scanning", help="Set output scanning policy")
    settings_output_parser.add_argument("policy", choices=("off", "warn", "ask"))
    _add_guard_common_args(settings_output_parser)
    settings_output_parser.add_argument("--json", action="store_true")
    settings_explain_parser = settings_subparsers.add_parser(
        "explain", help="Explain current Guard settings in plain language"
    )
    _add_guard_common_args(settings_explain_parser)
    settings_explain_parser.add_argument("--json", action="store_true")
    settings_doctor_parser = settings_subparsers.add_parser("doctor", help="Diagnose Guard settings for common issues")
    _add_guard_common_args(settings_doctor_parser)
    settings_doctor_parser.add_argument("--json", action="store_true")
    approval_password_parser = settings_subparsers.add_parser(
        "approval-password",
        help="Manage local approval password gate state",
    )
    _add_guard_common_args(approval_password_parser)
    approval_password_parser.add_argument("--json", action="store_true")
    approval_password_subparsers = approval_password_parser.add_subparsers(
        dest="settings_approval_password_command",
        required=True,
        parser_class=FriendlyArgumentParser,
    )
    approval_password_status_parser = approval_password_subparsers.add_parser(
        "status",
        help="Show approval password gate status",
    )
    _add_guard_common_args(approval_password_status_parser)
    approval_password_status_parser.add_argument("--json", action="store_true")
    approval_password_enable_parser = approval_password_subparsers.add_parser(
        "enable",
        help="Enable the approval password gate",
    )
    approval_password_enable_parser.add_argument("--new-password", required=True)
    approval_password_enable_parser.add_argument("--confirm-password", required=True)
    approval_password_enable_parser.add_argument("--cooldown-seconds", type=int, choices=(0, 900, 3600))
    approval_password_enable_parser.add_argument("--strict-all-decisions", action="store_true")
    approval_password_enable_parser.add_argument("--current-password")
    approval_password_enable_parser.add_argument("--totp-code")
    _add_guard_common_args(approval_password_enable_parser)
    approval_password_enable_parser.add_argument("--json", action="store_true")
    approval_password_change_parser = approval_password_subparsers.add_parser(
        "change",
        help="Change the approval password",
    )
    approval_password_change_parser.add_argument("--current-password", required=True)
    approval_password_change_parser.add_argument("--new-password", required=True)
    approval_password_change_parser.add_argument("--confirm-password", required=True)
    approval_password_change_parser.add_argument("--totp-code")
    _add_guard_common_args(approval_password_change_parser)
    approval_password_change_parser.add_argument("--json", action="store_true")
    approval_password_disable_parser = approval_password_subparsers.add_parser(
        "disable",
        help="Disable the approval password gate",
    )
    approval_password_disable_parser.add_argument("--current-password", required=True)
    approval_password_disable_parser.add_argument("--totp-code")
    _add_guard_common_args(approval_password_disable_parser)
    approval_password_disable_parser.add_argument("--json", action="store_true")
    approval_totp_parser = settings_subparsers.add_parser(
        "approval-totp",
        help="Manage approval gate TOTP enrollment and enforcement",
    )
    _add_guard_common_args(approval_totp_parser)
    approval_totp_parser.add_argument("--json", action="store_true")
    approval_totp_subparsers = approval_totp_parser.add_subparsers(
        dest="settings_approval_totp_command",
        required=True,
        parser_class=FriendlyArgumentParser,
    )
    approval_totp_status_parser = approval_totp_subparsers.add_parser("status", help="Show TOTP enrollment status")
    _add_guard_common_args(approval_totp_status_parser)
    approval_totp_status_parser.add_argument("--json", action="store_true")
    approval_totp_enroll_parser = approval_totp_subparsers.add_parser(
        "enroll",
        help="Start TOTP enrollment and emit an otpauth provisioning URI",
    )
    approval_totp_enroll_parser.add_argument("--current-password", required=True)
    approval_totp_enroll_parser.add_argument("--device-label", default="local-device")
    _add_guard_common_args(approval_totp_enroll_parser)
    approval_totp_enroll_parser.add_argument("--json", action="store_true")
    approval_totp_verify_parser = approval_totp_subparsers.add_parser(
        "verify",
        help="Verify pending enrollment and enable TOTP",
    )
    approval_totp_verify_parser.add_argument("--current-password", required=True)
    approval_totp_verify_parser.add_argument("--code", required=True)
    _add_guard_common_args(approval_totp_verify_parser)
    approval_totp_verify_parser.add_argument("--json", action="store_true")
    approval_totp_disable_parser = approval_totp_subparsers.add_parser(
        "disable",
        help="Disable TOTP with a fresh password and code",
    )
    approval_totp_disable_parser.add_argument("--current-password", required=True)
    approval_totp_disable_parser.add_argument("--code", required=True)
    _add_guard_common_args(approval_totp_disable_parser)
    approval_totp_disable_parser.add_argument("--json", action="store_true")

    exceptions_parser = guard_subparsers.add_parser("exceptions", help="List active Guard exceptions with expiry")
    exceptions_parser.add_argument("--harness")
    _add_guard_common_args(exceptions_parser)
    exceptions_parser.add_argument("--json", action="store_true")

    advisories_parser = guard_subparsers.add_parser("advisories", help="List cached Guard advisories and verdicts")
    _add_guard_common_args(advisories_parser)
    advisories_parser.add_argument("--json", action="store_true")
    advisories_sub = advisories_parser.add_subparsers(dest="advisories_subcommand")

    _adv_list = advisories_sub.add_parser("list", help="List cached advisories")
    _adv_list.add_argument("--json", action="store_true")
    _adv_list.add_argument(
        "--severity",
        choices=["low", "medium", "high", "critical"],
        help="Filter by minimum severity",
    )

    _adv_sync = advisories_sub.add_parser("sync", help="Sync advisories from Guard Cloud")
    _adv_sync.add_argument("--json", action="store_true")

    _adv_explain = advisories_sub.add_parser("explain", help="Explain a specific advisory by ID")
    _adv_explain.add_argument("--json", action="store_true")
    _adv_explain.add_argument("advisory_id", help="Advisory ID to explain")

    events_parser = guard_subparsers.add_parser("events", help="List local Guard lifecycle events")
    _add_guard_common_args(events_parser)
    events_parser.add_argument("--name")
    events_parser.add_argument("--json", action="store_true")

    doctor_parser = guard_subparsers.add_parser("doctor", help="Emit Guard diagnostics for a harness")
    doctor_parser.add_argument("harness", nargs="?")
    _add_guard_common_args(doctor_parser)
    doctor_parser.add_argument("--json", action="store_true")
    doctor_parser.add_argument(
        "--harnesses",
        action="store_true",
        help="List all supported harnesses with their protection contract",
    )
    doctor_parser.add_argument("--perf", action="store_true", help="Include detector performance timings")
    doctor_parser.add_argument(
        "--notifications",
        action="store_true",
        help="Send a notification preview and open macOS notification settings when needed",
    )
    doctor_parser.add_argument(
        "--force-notification-settings",
        action="store_true",
        help="Open macOS notification settings even if Guard already prompted before",
    )

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
    connect_parser.add_argument("connect_command", nargs="?", choices=("status", "repair", "re-pair"))
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
    disconnect_parser.add_argument("--json", action="store_true")

    sync_parser = guard_subparsers.add_parser("sync", help="Sync receipts to the configured Guard endpoint")
    sync_parser.add_argument("--home")
    sync_parser.add_argument("--guard-home")
    sync_parser.add_argument("--json", action="store_true")

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
        choices=("allow", "warn", "review", "block", "sandbox-required", "require-reapproval"),
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


def _add_guard_common_args(
    parser: argparse.ArgumentParser,
    *,
    suppress_defaults: bool = False,
) -> None:
    default = argparse.SUPPRESS if suppress_defaults else None
    parser.add_argument("--home", default=default)
    parser.add_argument("--guard-home", default=default)
    parser.add_argument("--workspace", default=default)


def _add_aibom_cli_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--include-symlinks",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Include symlink source-of-truth metadata in AIBOM output (default: enabled).",
    )
    parser.add_argument(
        "--follow-unsafe-symlinks",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Follow symlink targets outside safe roots (default: disabled).",
    )


def _aibom_cli_options_from_args(args: argparse.Namespace) -> AibomCliOptions:
    return AibomCliOptions(
        include_symlinks=bool(getattr(args, "include_symlinks", True)),
        follow_unsafe_symlinks=bool(getattr(args, "follow_unsafe_symlinks", False)),
    )


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
