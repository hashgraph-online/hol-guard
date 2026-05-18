"""Guard CLI command handlers."""

# fmt: off

from __future__ import annotations

import argparse
import fnmatch
import hashlib
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
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import TextIO

from ...argparse_utils import FriendlyArgumentParser
from ...models import ScanOptions
from ..adapters import get_adapter
from ..adapters.base import HarnessContext
from ..approvals import (
    approval_center_hint,
    approval_delivery_payload,
    approval_prompt_flow,
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
from ..mcp_tool_calls import (
    allow_tool_call,
    block_tool_call,
    build_tool_call_artifact,
    build_tool_call_hash,
    evaluate_tool_call,
)
from ..models import SEVERITY_RANK, GuardArtifact, HarnessDetection, PolicyDecision
from ..policy.engine import SAFE_CHANGED_HASH_ACTION, VALID_GUARD_ACTIONS, build_decision_v2
from ..protect import build_protect_payload
from ..proxy import (
    CodexMcpGuardProxy,
    CopilotMcpGuardProxy,
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
)
from ..runtime.runner import (
    GuardSyncNotConfiguredError,
    extract_prompt_requests,
    guard_run,
    prompt_requests_to_artifacts,
    sync_receipts,
    sync_runtime_session,
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
from ..runtime.surface_server import GuardSurfaceRuntime
from ..store import GuardStore
from .approval_commands import (
    add_approval_parser,
    run_approval_command,
    run_approval_open_command,
    run_approval_retry_hint_command,
)
from .bootstrap import DEFAULT_ALIAS_NAME, build_guard_bootstrap_payload
from .connect_flow import (
    DEFAULT_GUARD_CONNECT_URL,
    DEFAULT_GUARD_SYNC_URL,
    build_connect_status_payload,
    run_guard_connect_command,
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
from .update_commands import run_guard_update

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
    "  abom         Export the local AI-BOM\n"
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


_CLAUDE_GUARD_APPROVAL_HEADER = "HOL Guard"
_CLAUDE_GUARD_APPROVAL_OPTIONS = (
    "Allow once",
    "Allow during this session",
    "Keep blocked",
)
_SETTINGS_POLICY_RISK_ACTIONS: dict[str, dict[str, dict[str, str]]] = {
    "mcp": {
        "allow-known": {"mcp_dangerous_tool": "warn"},
        "ask-new": {"mcp_dangerous_tool": "require-reapproval"},
        "ask-dangerous": {"mcp_dangerous_tool": "require-reapproval"},
        "ask-all": {"mcp_dangerous_tool": "require-reapproval"},
    },
    "skills": {
        "allow-known": {"malicious_skill": "warn"},
        "ask-new": {"malicious_skill": "require-reapproval"},
        "ask-dangerous": {"malicious_skill": "require-reapproval"},
        "ask-all": {"malicious_skill": "require-reapproval"},
    },
    "packages": {
        "warn": {"package_script": "warn"},
        "ask-lifecycle": {"package_script": "require-reapproval"},
        "ask-all": {"package_script": "require-reapproval"},
    },
    "output-scanning": {
        "off": {
            "encoded_execution": "allow",
            "encoded_exfiltration": "allow",
        },
        "warn": {
            "encoded_execution": "warn",
            "encoded_exfiltration": "warn",
        },
        "ask": {
            "encoded_execution": "require-reapproval",
            "encoded_exfiltration": "require-reapproval",
        },
    },
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


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
            "{start,status,dashboard,init,apps,bootstrap,detect,install,update,uninstall,run,protect,preflight,scan,diff,"
            "receipts,inventory,abom,approvals,explain,allow,deny,policies,exceptions,advisories,events,doctor,connect,"
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
    connect_parser.add_argument("--json", action="store_true")

    sync_parser = guard_subparsers.add_parser("sync", help="Sync receipts to the configured Guard endpoint")
    sync_parser.add_argument("--home")
    sync_parser.add_argument("--guard-home")
    sync_parser.add_argument("--json", action="store_true")

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
        help="Save a hosted-runtime Guard Cloud token and runtime profile",
    )
    _add_guard_common_args(service_login_parser)
    service_login_parser.add_argument("--runtime", choices=_SERVICE_RUNTIME_CHOICES, required=True)
    service_login_parser.add_argument("--label", required=True)
    service_login_parser.add_argument("--sync-url", required=True, type=_guard_http_url)
    service_login_parser.add_argument("--token", required=True)
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


def _build_init_plan(args: argparse.Namespace) -> list[dict[str, object]]:
    del args
    return [
        {
            "id": "dashboard",
            "title": "Open local Guard dashboard",
            "detail": (
                "Starts the local daemon and opens the dashboard so you can see what Guard will protect "
                "before anything is changed."
            ),
            "command": "hol-guard dashboard",
            "skip_flag": None,
        },
        {
            "id": "apps",
            "title": "Protect detected AI apps",
            "detail": (
                "Discovers supported harnesses and installs Guard-managed launch commands for each detected app. "
                "This is reversible with `hol-guard uninstall --all`."
            ),
            "command": "hol-guard install --all",
            "skip_flag": "skip_apps",
        },
        {
            "id": "cloud",
            "title": "Connect Guard Cloud",
            "detail": (
                "Opens the browser pairing flow only after you approve it, then syncs receipts and policy memory "
                "when Cloud is available."
            ),
            "command": "hol-guard connect",
            "skip_flag": "skip_cloud",
        },
        {
            "id": "notifications",
            "title": "Enable desktop notifications",
            "detail": (
                "Sends one preview notification and opens OS notification settings only after you approve it."
            ),
            "command": "hol-guard doctor --notifications --force-notification-settings",
            "skip_flag": "skip_notifications",
        },
    ]


def _print_init_plan_preview(plan: list[dict[str, object]]) -> None:
    print("HOL Guard init will ask before each setup action.", file=sys.stderr)
    for index, step in enumerate(plan, start=1):
        print(f"{index}. {step.get('title')}", file=sys.stderr)
        detail = step.get("detail")
        if isinstance(detail, str) and detail:
            print(f"   {detail}", file=sys.stderr)


def _prompt_init_step(step: dict[str, object]) -> str:
    title = str(step.get("title") or "Guard init step")
    detail = str(step.get("detail") or "")
    command = str(step.get("command") or "")
    print(f"\n{title}", file=sys.stderr)
    if detail:
        print(detail, file=sys.stderr)
    if command:
        print(f"Command: {command}", file=sys.stderr)
    sys.stderr.write("Run this step? [y/N] ")
    sys.stderr.flush()
    return sys.stdin.readline().strip().lower()


def _approve_init_step(
    args: argparse.Namespace,
    step: dict[str, object],
    *,
    interactive: bool,
) -> bool:
    skip_flag = step.get("skip_flag")
    if isinstance(skip_flag, str) and bool(getattr(args, skip_flag, False)):
        step["decision"] = "skipped"
        step["reason"] = skip_flag
        return False
    if bool(getattr(args, "yes", False)):
        step["decision"] = "approved"
        step["reason"] = "yes_flag"
        return True
    if not interactive:
        step["decision"] = "skipped"
        step["reason"] = "needs_approval"
        return False
    answer = _prompt_init_step(step)
    if answer in {"y", "yes"}:
        step["decision"] = "approved"
        step["reason"] = "user_approved"
        return True
    step["decision"] = "skipped"
    step["reason"] = "user_skipped"
    return False


def _skip_init_step_payload(step: dict[str, object]) -> dict[str, object]:
    return {"skipped": True, "reason": str(step.get("reason") or "skipped")}


def _print_init_step_complete(step: dict[str, object], payload: dict[str, object]) -> None:
    title = str(step.get("title") or step.get("id") or "Init step")
    if bool(payload.get("skipped")):
        reason = str(payload.get("reason") or "skipped").replace("_", " ")
        print(f"Skipped: {title} ({reason})", file=sys.stderr)
        return
    if payload.get("error"):
        print(f"Needs attention: {title} ({payload.get('error')})", file=sys.stderr)
        return
    print(f"Completed: {title}", file=sys.stderr)


def _run_init_command(
    args: argparse.Namespace,
    context: HarnessContext,
    store: GuardStore,
    config: GuardConfig,
    workspace: Path | None,
) -> int:
    init_plan = _build_init_plan(args)
    interactive = sys.stdin.isatty() and not bool(getattr(args, "json", False))
    if interactive and not bool(getattr(args, "yes", False)) and not bool(getattr(args, "json", False)):
        _print_init_plan_preview(init_plan)
    approved_any = False
    init_failed = False
    approval_center_url: str | None = None
    dashboard_payload: dict[str, object] | None = None
    apps_payload: dict[str, object] = {}
    cloud_payload: dict[str, object] = {}
    notification_payload: dict[str, object] = {}

    for step in init_plan:
        step_id = str(step.get("id") or "")
        if not _approve_init_step(args, step, interactive=interactive):
            step_payload = _skip_init_step_payload(step)
        else:
            approved_any = True
            if step_id == "dashboard":
                try:
                    approval_center_url = ensure_guard_daemon(context.guard_home)
                    open_result = _open_approval_center(
                        approval_center_url,
                        store=store,
                        config=config,
                        open_key="init",
                        force_open=True,
                    )
                    step_payload = {
                        "approval_center_url": approval_center_url,
                        "browser_url": open_result.get("browser_url"),
                        "opened": bool(open_result.get("opened")),
                        "reason": str(open_result.get("reason") or "unknown"),
                    }
                except RuntimeError as error:
                    init_failed = True
                    step_payload = {"opened": False, "error": str(error)}
            elif step_id == "apps":
                try:
                    step_payload = apply_managed_install(
                        "install",
                        None,
                        True,
                        context,
                        store,
                        str(workspace) if workspace else None,
                        _now(),
                    )
                    step_payload["skipped"] = False
                except ValueError as error:
                    init_failed = True
                    step_payload = {"skipped": False, "error": str(error), "managed_installs": []}
            elif step_id == "cloud":
                try:
                    step_payload = _run_guard_connect_flow(
                        guard_home=context.guard_home,
                        store=store,
                        sync_url=args.sync_url,
                        connect_url=args.connect_url,
                        wait_timeout_seconds=int(getattr(args, "wait_timeout_seconds", 0)),
                    )
                    step_payload["skipped"] = False
                except Exception as error:
                    init_failed = True
                    step_payload = {"skipped": False, "connected": False, "error": str(error)}
            elif step_id == "notifications":
                try:
                    approval_url = (
                        f"{approval_center_url.rstrip('/')}/approvals/notification-preview"
                        if isinstance(approval_center_url, str) and approval_center_url
                        else "hol-guard://notification-preview"
                    )
                    result = ensure_desktop_notification_setup(
                        context.guard_home,
                        approval_url=approval_url,
                        force=True,
                    )
                    step_payload = desktop_notification_setup_payload(
                        result,
                        guidance=macos_notification_guidance(result.notifier_path)
                        if result.platform == "Darwin"
                        else None,
                    )
                    step_payload["skipped"] = False
                except Exception as error:
                    init_failed = True
                    step_payload = {"skipped": False, "supported": True, "error": str(error)}
            else:
                init_failed = True
                step_payload = {"skipped": True, "reason": "unknown_step"}

        if step_id == "dashboard":
            dashboard_payload = step_payload
        elif step_id == "apps":
            apps_payload = step_payload
        elif step_id == "cloud":
            cloud_payload = step_payload
        elif step_id == "notifications":
            notification_payload = step_payload
        if interactive:
            _print_init_step_complete(step, step_payload)

    payload = {
        "generated_at": _now(),
        "status": "needs_attention" if init_failed else ("initialized" if approved_any else "approval_required"),
        "mode": "auto_approved" if bool(getattr(args, "yes", False)) else "progressive",
        "plan": init_plan,
        "dashboard": dashboard_payload,
        "apps": apps_payload,
        "cloud": cloud_payload,
        "desktop_notifications": notification_payload,
        "next_command": "hol-guard init --yes" if not approved_any else "hol-guard status",
        "next_steps": [
            {
                "title": "Open dashboard settings",
                "command": "hol-guard dashboard",
                "detail": "Use Settings for notification setup and protection tuning.",
            },
            {
                "title": "Check coverage",
                "command": "hol-guard status",
                "detail": "Confirm apps are protected and Cloud pairing is healthy.",
            },
        ],
    }
    _emit("init", payload, getattr(args, "json", False))
    return 1 if init_failed else 0


def _run_apps_command(
    args: argparse.Namespace,
    context: HarnessContext,
    store: GuardStore,
    workspace: str | None,
) -> int:
    apps_command = getattr(args, "apps_command", None)
    if apps_command is None:
        _emit(
            "apps",
            {
                "generated_at": _now(),
                "items": list_harness_setup_items(context, store),
            },
            getattr(args, "json", False),
        )
        return 0

    harness = str(getattr(args, "harness", "")).strip()
    if not harness:
        print("guard apps requires a harness.", file=sys.stderr)
        return 2
    if apps_command == "test":
        try:
            payload = build_harness_verification(harness, context, store)
        except ValueError as error:
            print(str(error), file=sys.stderr)
            return 2
        _emit("apps", payload, getattr(args, "json", False))
        return 0

    if apps_command in {"connect", "repair"} and bool(getattr(args, "dry_run", False)):
        try:
            payload = build_harness_setup_plan(apps_command, harness, context, dry_run=True)
        except ValueError as error:
            print(str(error), file=sys.stderr)
            return 2
        _emit("apps", payload, getattr(args, "json", False))
        return 0

    if apps_command == "disconnect":
        try:
            canonical_harness = get_adapter(harness).harness
        except ValueError as error:
            print(str(error), file=sys.stderr)
            return 2
        expected_confirmation = uninstall_confirmation_token(canonical_harness)
        if getattr(args, "confirm", None) != expected_confirmation:
            payload = {
                "error": "confirmation_required",
                "harness": canonical_harness,
                "confirmation_phrase": expected_confirmation,
                "confirm_command": f"hol-guard apps disconnect {canonical_harness} --confirm {expected_confirmation}",
            }
            _emit("apps", payload, getattr(args, "json", False))
            return 2

    install_command = "uninstall" if apps_command == "disconnect" else "install"
    try:
        payload = apply_managed_install(
            install_command,
            harness,
            False,
            context,
            store,
            workspace,
            _now(),
        )
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 2
    payload["action"] = apps_command
    _emit("apps", payload, getattr(args, "json", False))
    return 0


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
        if getattr(args, "deep", False):
            scan_type = str(args.target)
            if scan_type not in {"skills", "mcp"}:
                print("guard scan --deep supports 'skills' or 'mcp'.", file=sys.stderr)
                return 2
            home_override = getattr(args, "home", None)
            guard_home = resolve_guard_home(getattr(args, "guard_home", None) or home_override)
            workspace = Path(args.workspace).resolve() if getattr(args, "workspace", None) else Path.cwd().resolve()
            config = load_guard_config(guard_home, workspace=workspace)
            payload = build_cisco_deep_scan_payload(
                scan_type=scan_type,
                target=workspace,
                mode=args.cisco_mode,
                config=config,
            )
            payload["generated_at"] = _now()
            _emit("deep-scan", payload, getattr(args, "json", False))
            return 0
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
            unsafe_raw_output=bool(getattr(args, "unsafe_raw_output", False)),
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

    if args.guard_command == "init":
        return _run_init_command(args, context, store, config, workspace)

    if args.guard_command in {"dashboard", "admin"}:
        try:
            approval_center_url = ensure_guard_daemon(guard_home)
        except RuntimeError as error:
            if getattr(args, "json", False):
                _emit(
                    "dashboard",
                    {
                        "generated_at": _now(),
                        "opened": False,
                        "error": str(error),
                    },
                    True,
                )
            else:
                print(str(error), file=sys.stderr)
            return 1
        open_result = _open_approval_center(
            approval_center_url,
            store=store,
            config=config,
            open_key="dashboard",
            force_open=True,
        )
        _emit(
            "dashboard",
            {
                "generated_at": _now(),
                "approval_center_url": approval_center_url,
                "browser_url": open_result.get("browser_url"),
                "opened": bool(open_result.get("opened")),
                "reason": str(open_result.get("reason") or "unknown"),
            },
            getattr(args, "json", False),
        )
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

    if args.guard_command == "apps":
        return _run_apps_command(args, context, store, str(workspace) if workspace else None)

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
            server_id=args.server_id,
            server_env_keys=tuple(args.server_env_keys),
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
            server_id=args.server_id,
            server_env_keys=tuple(args.server_env_keys),
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
            server_id=args.server_id,
            server_env_keys=tuple(args.server_env_keys),
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

    if args.guard_command == "history":
        history_cmd = getattr(args, "history_command", None)
        if history_cmd == "explain":
            receipt_id: str = args.receipt_id
            match = store.get_receipt(receipt_id)
            if match is None:
                msg = f"No receipt found for ID {receipt_id!r}"
                _emit("history.explain", {"error": msg}, getattr(args, "json", False))
                return 1
            evidence = store.list_evidence(request_id=receipt_id, limit=10_000)
            payload: dict[str, object] = {
                "receipt_id": receipt_id,
                "receipt": match,
                "evidence": [
                    {
                        "evidence_id": e.get("evidence_id", ""),
                        "category": e.get("category", ""),
                        "severity": e.get("severity", ""),
                        "summary": e.get("summary", ""),
                        "action_identity": e.get("action_identity"),
                        "created_at": e.get("created_at", ""),
                    }
                    for e in evidence
                ],
            }
            _emit("history.explain", payload, getattr(args, "json", False))
            return 0
        _emit("history", {"error": "Use: hol-guard history explain <receipt_id>"}, getattr(args, "json", False))
        return 1

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
        if getattr(args, "policies_command", None) == "clear":
            harness = getattr(args, "harness", None)
            clear_all = bool(getattr(args, "all", False))
            if clear_all and harness is not None:
                _emit(
                    "policies",
                    {
                        "error": "Choose either --all or --harness <name> when clearing Guard policy decisions.",
                        "cleared": 0,
                        "harness": harness,
                        "source": getattr(args, "source", None),
                    },
                    getattr(args, "json", False),
                )
                return 2
            if not clear_all and harness is None:
                _emit(
                    "policies",
                    {
                        "error": "Choose --harness <name> or --all when clearing Guard policy decisions.",
                        "cleared": 0,
                    },
                    getattr(args, "json", False),
                )
                return 2
            scope = getattr(args, "scope", None)
            artifact_id = getattr(args, "artifact_id", None)
            policy_artifact_hash = getattr(args, "artifact_hash", None)
            workspace = getattr(args, "policy_workspace", None)
            publisher = getattr(args, "publisher", None)
            cleared = store.clear_policy_decisions(
                None if clear_all else harness,
                getattr(args, "source", None),
                scope=scope,
                artifact_id=artifact_id,
                artifact_hash=policy_artifact_hash,
                workspace=workspace,
                publisher=publisher,
            )
            _emit(
                "policies",
                {
                    "generated_at": _now(),
                    "cleared": cleared,
                    "harness": None if clear_all else harness,
                    "source": getattr(args, "source", None),
                    "scope": scope,
                    "artifact_id": artifact_id,
                    "artifact_hash": policy_artifact_hash,
                    "workspace": workspace,
                    "publisher": publisher,
                },
                getattr(args, "json", False),
            )
            return 0
        policy_items = store.list_policy_decisions(getattr(args, "harness", None))
        items = _filter_policy_items(policy_items, active_only=True)
        _emit("policies", {"generated_at": _now(), "items": items}, getattr(args, "json", False))
        return 0

    if args.guard_command == "settings":
        settings_sub = getattr(args, "settings_command", None)
        if settings_sub == "set":
            try:
                config = _update_guard_cli_settings(args=args, config=config, guard_home=guard_home)
            except ValueError as error:
                print(str(error), file=sys.stderr)
                return 2
        elif settings_sub == "explain":
            _emit("settings.explain", _guard_settings_explain_payload(config), getattr(args, "json", False))
            return 0
        elif settings_sub == "doctor":
            _emit("settings.doctor", _guard_settings_doctor_payload(config), getattr(args, "json", False))
            return 0
        _emit("settings", _guard_cli_settings_payload(config), getattr(args, "json", False))
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
        adv_sub = getattr(args, "advisories_subcommand", None)
        if adv_sub == "sync":
            credentials = store.get_sync_credentials()
            if credentials is None:
                _emit(
                    "advisories_sync",
                    {"generated_at": _now(), "status": "no_cloud_sync_configured"},
                    getattr(args, "json", False),
                )
            else:
                _emit(
                    "advisories_sync",
                    {"generated_at": _now(), "status": "advisory_sync_not_available", "synced": False},
                    getattr(args, "json", False),
                )
        elif adv_sub == "explain":
            target_id = getattr(args, "advisory_id", None)
            all_advs = store.list_cached_advisories(limit=None)
            match = next(
                (a for a in all_advs if a.get("advisory_id") == target_id or a.get("id") == target_id),
                None,
            )
            if match:
                _emit("advisory_explain", match, getattr(args, "json", False))
            else:
                _emit("advisory_explain", {"error": f"advisory {target_id!r} not found"}, getattr(args, "json", False))
        else:
            all_advs = store.list_cached_advisories()
            sev_filter = getattr(args, "severity", None)
            if sev_filter and sev_filter in SEVERITY_RANK:
                min_rank = SEVERITY_RANK[sev_filter]
                all_advs = [
                    a for a in all_advs if SEVERITY_RANK.get(str(a.get("severity", "")).lower(), -1) >= min_rank
                ]
            _emit(
                "advisories",
                {"generated_at": _now(), "items": all_advs},
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
        approvals_command = getattr(args, "approvals_command", None)
        if approvals_command == "open":
            payload, exit_code = run_approval_open_command(args, store=store)
            _emit("approvals", payload, getattr(args, "json", False))
            return exit_code
        if approvals_command == "retry-hint":
            payload, exit_code = run_approval_retry_hint_command(args, store=store)
            _emit("approvals", payload, getattr(args, "json", False))
            return exit_code
        payload = run_approval_command(args, store=store, workspace=workspace)
        _emit("approvals", payload, getattr(args, "json", False))
        return int(payload.get("exit_code", 0))

    if args.guard_command == "explain":
        if str(args.target).strip().lower() == "install-connect":
            payload = build_install_connect_docs_payload()
        else:
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
        if getattr(args, "notifications", False):
            approval_url = "hol-guard://notification-preview"
            if desktop_notification_setup_supported():
                try:
                    approval_center_url = ensure_guard_daemon(guard_home)
                    approval_url = f"{approval_center_url.rstrip('/')}/approvals/notification-preview"
                except Exception:
                    approval_url = "hol-guard://notification-preview"
            result = ensure_desktop_notification_setup(
                guard_home,
                approval_url=approval_url,
                force=bool(getattr(args, "force_notification_settings", False)),
            )
            guidance = macos_notification_guidance(result.notifier_path) if result.platform == "Darwin" else None
            _emit(
                "doctor",
                {"desktop_notifications": desktop_notification_setup_payload(result, guidance=guidance)},
                getattr(args, "json", False),
            )
            return 0
        if getattr(args, "harnesses", False):
            from ..adapters.contracts import HARNESS_CONTRACTS

            contracts_payload = [
                {
                    "harness": c.harness,
                    "install_aliases": list(c.install_aliases),
                    "config_paths": list(c.config_paths),
                    "event_surfaces": list(c.event_surfaces),
                    "native_approval": c.native_approval,
                    "browser_fallback": c.browser_fallback,
                    "resume_support": c.resume_support,
                    "known_blind_spots": c.known_blind_spots,
                    "smoke_command": c.smoke_command,
                }
                for c in HARNESS_CONTRACTS
            ]
            _emit("doctor", {"harnesses": contracts_payload}, getattr(args, "json", False))
            return 0
        if args.harness:
            adapter = get_adapter(args.harness)
            payload = adapter.diagnostics(context)
            payload["runtime_detector_registry"] = _runtime_detector_registry_payload(config)
        else:
            payload = {
                "tables": store.list_table_names(),
                "adapters": [detection.to_dict() for detection in detect_all(context)],
                "runtime_detector_registry": _runtime_detector_registry_payload(config),
            }
        if getattr(args, "perf", False):
            payload["detector_perf"] = _runtime_detector_perf_payload(config)
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
        connect_subcommand = getattr(args, "connect_command", None)
        if connect_subcommand in {"status", "repair", "re-pair"}:
            payload = build_connect_status_payload(
                store=store,
                sync_url=args.sync_url,
                connect_url=args.connect_url,
                action=str(connect_subcommand),
            )
            _emit("connect", payload, getattr(args, "json", False))
            return 0
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

    if args.guard_command == "service":
        service_command = getattr(args, "service_command", None)
        if service_command == "login":
            payload, exit_code = _guard_service_login_payload(args=args, store=store)
            _emit("service-login", payload, getattr(args, "json", False))
            return exit_code
        if service_command == "sync":
            try:
                payload = _guard_service_sync_payload(store)
            except (GuardSyncNotConfiguredError, RuntimeError) as error:
                message = (
                    _guard_service_sync_prerequisite_message()
                    if isinstance(error, GuardSyncNotConfiguredError)
                    else str(error)
                )
                if getattr(args, "json", False):
                    _emit("service-sync", {"synced": False, "error": message}, True)
                else:
                    print(message, file=sys.stderr)
                return 1
            _emit("service-sync", payload, getattr(args, "json", False))
            return 0
        if service_command == "status":
            payload = _guard_service_status_payload(store)
            _emit("service-status", payload, getattr(args, "json", False))
            return 0
        print("service subcommand is required", file=sys.stderr)
        return 2

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
        daemon_command = getattr(args, "daemon_command", None)
        if daemon_command == "status":
            return _handle_daemon_status(guard_home, getattr(args, "json", False))
        if daemon_command == "repair":
            return _handle_daemon_repair(guard_home, getattr(args, "json", False))
        if daemon_command == "stop":
            return _handle_daemon_stop(guard_home, getattr(args, "json", False))
        daemon = GuardDaemonServer(store, port=args.port or 0)
        if args.serve:
            daemon.serve()
            return 0
        _emit("doctor", {"daemon_url": f"http://127.0.0.1:{daemon.port}"}, getattr(args, "json", False))
        return 0

    if args.guard_command == "hook":
        payload = _load_hook_payload(getattr(args, "event_file", None), input_text=input_text)
        managed_install = _managed_install_for(store, args.harness)
        workspace_was_explicit = workspace is not None
        runtime_workspace = workspace
        if runtime_workspace is None and args.harness == "copilot":
            with suppress(OSError):
                current_workspace = Path.cwd().resolve()
                if current_workspace.is_dir():
                    runtime_workspace = current_workspace
        if args.harness == "copilot":
            runtime_workspace = _resolve_copilot_workspace_root(runtime_workspace)
        action_envelope = _hook_action_envelope(
            harness=args.harness,
            payload=payload,
            home_dir=context.home_dir,
            workspace=runtime_workspace,
        )
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
                    risk_categories=decision.risk_categories,
                    remember=False,
                )
                if _should_emit_copilot_hook_response(args):
                    _record_harness_usage_for_hook(
                        store=store,
                        action_envelope=action_envelope,
                        payload=payload,
                        policy_action=policy_action,
                    )
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
                        risk_categories=decision.risk_categories,
                    )
                if _should_emit_copilot_hook_response(args):
                    _record_harness_usage_for_hook(
                        store=store,
                        action_envelope=action_envelope,
                        payload=payload,
                        policy_action=policy_action,
                    )
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
                        "action_envelope_json": _action_envelope_json(action_envelope),
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
                    risk_categories=decision.risk_categories,
                    remember=False,
                )
                if _should_emit_copilot_hook_response(args):
                    _record_harness_usage_for_hook(
                        store=store,
                        action_envelope=action_envelope,
                        payload=payload,
                        policy_action=policy_action,
                    )
                    _emit_copilot_permission_request_response(behavior="allow", output_stream=output_stream)
                    return 0
                _record_harness_usage_for_hook(
                    store=store,
                    action_envelope=action_envelope,
                    payload=payload,
                    policy_action=policy_action,
                )
                _emit("hook", response_payload, getattr(args, "json", False))
                return 0
            block_tool_call(
                store=store,
                artifact=runtime_artifact,
                artifact_hash=runtime_artifact_hash,
                decision_source="permission-request-hook",
                now=now,
                signals=decision.signals,
                risk_categories=decision.risk_categories,
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
                        **codex_resume_metadata_from_hook_payload(payload),
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
            _record_harness_usage_for_hook(
                store=store,
                action_envelope=action_envelope,
                payload=payload,
                policy_action=policy_action,
            )
            if _should_emit_copilot_hook_response(args):
                review_context = _native_approval_center_context(response_payload, harness=args.harness)
                _emit_copilot_permission_request_response(
                    behavior="deny",
                    message=_copilot_hook_reason(
                        f"HOL Guard blocked {artifact_name}. {decision.summary}",
                        review_context,
                    ),
                    interrupt=True,
                    output_stream=output_stream,
                )
                return 0
            _emit("hook", response_payload, getattr(args, "json", False))
            return 1
        data_flow_signals = _runtime_action_data_flow_signals(action_envelope, workspace=runtime_workspace)
        runtime_artifact = _hook_runtime_artifact(
            harness=args.harness,
            payload=payload,
            action_envelope=action_envelope,
            data_flow_signals=data_flow_signals,
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
                policy_action="block",
                event_name="PermissionRequest",
                reason="HOL Guard is routing this approval through AskUserQuestion.",
                system_message=_claude_permission_prompt_system_message(payload=payload, notice=notice),
                additional_context=_claude_guard_approval_question_message(notice),
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
                reason="HOL Guard intercepted the tool request and is routing it through a HOL Guard approval prompt.",
                system_message=system_message,
                additional_context=additional_context,
                output_stream=output_stream,
            )
            return 0
        if _canonical_harness_name(args.harness) == "claude-code" and _hook_event_name(payload) == "Stop":
            discarded = _discard_claude_pending_permissions(store, payload)
            store.add_event(
                "claude/turn_stop",
                {
                    "session_id": payload.get("session_id"),
                    "discarded_pending_permissions": discarded,
                },
                _now(),
            )
            return 0
        if _canonical_harness_name(args.harness) == "claude-code" and _persist_claude_guard_question_decision(
            store, payload
        ):
            return 0
        if runtime_artifact is not None:
            event_name = _hook_event_name(payload) or "PreToolUse"
            runtime_artifact_hash = artifact_hash(runtime_artifact)
            artifact_id = runtime_artifact.artifact_id
            artifact_name = runtime_artifact.name
            policy_harness = _canonical_harness_name(args.harness)
            stored_policy_action = _runtime_stored_policy_action(
                store=store,
                harness=policy_harness,
                artifact=runtime_artifact,
                artifact_id=artifact_id,
                artifact_hash=runtime_artifact_hash,
                workspace=str(runtime_workspace) if runtime_workspace else None,
            )
            if stored_policy_action is None:
                legacy_artifact = _legacy_claude_alias_runtime_artifact(
                    artifact=runtime_artifact,
                    requested_harness=args.harness,
                    home_dir=context.home_dir,
                    workspace=runtime_workspace,
                )
                if legacy_artifact is not None:
                    stored_policy_action = _runtime_stored_policy_action(
                        store=store,
                        harness=args.harness,
                        artifact=legacy_artifact,
                        artifact_id=legacy_artifact.artifact_id,
                        artifact_hash=artifact_hash(legacy_artifact),
                        workspace=str(runtime_workspace) if runtime_workspace else None,
                    )
            requested_policy_action = _coalesce_string(
                getattr(args, "policy_action", None),
                stored_policy_action,
                payload.get("policy_action"),
            )
            policy_action = requested_policy_action
            if policy_action not in VALID_GUARD_ACTIONS:
                policy_action = _runtime_artifact_policy_action(config, runtime_artifact, args.harness)
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
                        approval_source="inline",
                    )
                    store.add_receipt(receipt)
                _record_harness_usage_for_hook(
                    store=store,
                    action_envelope=action_envelope,
                    payload=payload,
                    policy_action="allow",
                )
                return 0
            changed_capabilities = [runtime_artifact.artifact_type]
            scanner_evidence = (
                scan_action_for_cisco_evidence(action_envelope, workspace=runtime_workspace)
                if action_envelope is not None
                else ()
            )
            scanner_evidence_payload = [signal.to_dict() for signal in scanner_evidence]
            if data_flow_signals:
                data_flow_action = resolve_risk_action(
                    config,
                    "data_flow_exfiltration",
                    harness=policy_harness,
                )
                if _guard_action_severity(data_flow_action) > _guard_action_severity(policy_action):
                    policy_action = data_flow_action
            _pre_scanner_policy_action = policy_action
            if scanner_evidence and requested_policy_action not in VALID_GUARD_ACTIONS:
                scanner_action = policy_action_for_cisco_signals(
                    scanner_evidence,
                    config=config,
                    harness=policy_harness,
                )
                if _guard_action_severity(scanner_action) > _guard_action_severity(policy_action):
                    policy_action = scanner_action
            scanner_raised_to_block = (
                policy_action == "block" and _pre_scanner_policy_action != "block" and bool(scanner_evidence)
            )
            base_decision_signals = data_flow_signals or artifact_risk_signals_v2(runtime_artifact)
            scanner_decision_signals = tuple(cisco_risk_signal_v3_to_v2(signal) for signal in scanner_evidence)
            decision_signals = (*base_decision_signals, *scanner_decision_signals)
            scanner_risk_signals = [signal.plain_language_summary for signal in scanner_evidence]
            if data_flow_signals:
                risk_signals = [signal.plain_reason for signal in data_flow_signals]
                risk_summary = _runtime_data_flow_summary(data_flow_signals)
            else:
                risk_signals = list(artifact_risk_signals(runtime_artifact))
                risk_summary = artifact_risk_summary(runtime_artifact)
            if scanner_risk_signals:
                risk_signals.extend(scanner_risk_signals)
                if scanner_raised_to_block:
                    risk_summary = scanner_risk_signals[0]
            decision_v2 = build_decision_v2(policy_action, reason=policy_action, signals=decision_signals)
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
                scanner_evidence=scanner_evidence_payload,
                approval_source=(
                    "inline"
                    if _optional_string(payload.get("user_override")) is not None
                    else "approval_center"
                    if policy_action == "require-reapproval"
                    else "policy"
                ),
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
                "scanner_evidence": scanner_evidence_payload,
                "decision_v2_json": decision_v2.to_dict(),
                "artifact_label": incident["artifact_label"],
                "source_label": incident["source_label"],
                "trigger_summary": incident["trigger_summary"],
                "why_now": incident["why_now"],
                "launch_summary": incident["launch_summary"],
                "risk_headline": incident["risk_headline"],
                "path_summary": _runtime_requested_path(runtime_artifact),
            }
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
                    _record_harness_usage_for_hook(
                        store=store,
                        action_envelope=action_envelope,
                        payload=payload,
                        policy_action=policy_action,
                    )
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
                    _record_harness_usage_for_hook(
                        store=store,
                        action_envelope=action_envelope,
                        payload=payload,
                        policy_action=policy_action,
                    )
                    return 0
                if not _prompt_requires_hard_block(runtime_artifact):
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
                                "action_envelope_json": _action_envelope_json(action_envelope),
                                "decision_v2_json": decision_v2.to_dict(),
                                "scanner_evidence": scanner_evidence_payload,
                            }
                        ]
                    }
                    browser_approval_daemon_client = None
                    try:
                        browser_approval_daemon_client = load_guard_surface_daemon_client(guard_home)
                    except RuntimeError:
                        queued = queue_blocked_approvals(
                            detection=runtime_detection,
                            evaluation=evaluation_payload,
                            store=store,
                            approval_center_url=approval_center_url,
                            now=_now(),
                        )
                    else:
                        session = browser_approval_daemon_client.start_session(
                            harness=args.harness,
                            surface="harness-adapter",
                            workspace=str(workspace) if workspace else None,
                            client_name=f"{args.harness}-hook",
                            client_title=f"{args.harness} hook",
                            client_version="1.0.0",
                            capabilities=["approval-resolution", "receipt-view"],
                        )
                        response_payload["session_id"] = str(session["session_id"])
                        blocked_operation = browser_approval_daemon_client.queue_blocked_operation(
                            session_id=str(session["session_id"]),
                            operation_type="tool_call",
                            harness=args.harness,
                            metadata={
                                "tool_name": str(payload.get("tool_name", "")),
                                "event": str(payload.get("event", "")),
                                **codex_resume_metadata_from_hook_payload(payload),
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
                            blocked_operation["operation"]
                            if isinstance(blocked_operation.get("operation"), dict)
                            else {}
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
                _record_harness_usage_for_hook(
                    store=store,
                    action_envelope=action_envelope,
                    payload=payload,
                    policy_action=policy_action,
                )
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
            codex_browser_decision = _codex_browser_approval_decision(
                args=args,
                event_name=event_name,
                policy_action=policy_action,
                response_payload=response_payload,
                store=store,
                config=config,
                daemon_client=locals().get("browser_approval_daemon_client"),
            )
            if codex_browser_decision == "allow":
                if event_name != "PreToolUse":
                    _emit_native_hook_response(
                        harness=args.harness,
                        policy_action="allow",
                        event_name=event_name,
                        reason="",
                        output_stream=output_stream,
                    )
                _record_harness_usage_for_hook(
                    store=store,
                    action_envelope=action_envelope,
                    payload=payload,
                    policy_action="allow",
                )
                return 0
            if codex_browser_decision == "block":
                policy_action = "block"
            if _should_emit_native_hook_exit_block(args, event_name=event_name, policy_action=policy_action):
                _emit_native_hook_block_stderr(
                    _native_hook_reason_for_harness(
                        args.harness,
                        _runtime_artifact_native_reason(runtime_artifact, response_payload),
                        _native_approval_center_context(response_payload, harness=args.harness),
                    )
                )
                _record_harness_usage_for_hook(
                    store=store,
                    action_envelope=action_envelope,
                    payload=payload,
                    policy_action=policy_action,
                )
                return 2
            raw_runtime_reason = _runtime_artifact_native_reason(runtime_artifact, response_payload)
            if _canonical_harness_name(args.harness) == "codex" and event_name == "UserPromptSubmit":
                runtime_reason = _native_hook_reason(
                    raw_runtime_reason,
                    _native_approval_center_context(response_payload, harness=args.harness),
                )
            else:
                runtime_reason = _native_hook_reason_for_harness(
                    args.harness,
                    raw_runtime_reason,
                    _native_approval_center_context(response_payload, harness=args.harness),
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
                canonical_harness = _canonical_harness_name(args.harness)
                if canonical_harness == "claude-code":
                    system_message = _claude_prompt_system_message(
                        event_name=event_name,
                        policy_action=policy_action,
                        artifact=runtime_artifact,
                        native_reason=runtime_reason,
                    )
                elif canonical_harness == "codex" and event_name == "UserPromptSubmit":
                    system_message = _codex_prompt_block_system_message(
                        policy_action=policy_action,
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
                _record_harness_usage_for_hook(
                    store=store,
                    action_envelope=action_envelope,
                    payload=payload,
                    policy_action=policy_action,
                )
                return 0
            _emit("hook", response_payload, getattr(args, "json", False))
            _record_harness_usage_for_hook(
                store=store,
                action_envelope=action_envelope,
                payload=payload,
                policy_action=policy_action,
            )
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
        incoming_policy_action = _optional_string(payload.get("policy_action"))
        policy_action = _coalesce_string(
            getattr(args, "policy_action", None),
            stored_policy_action,
            incoming_policy_action,
            config.default_action,
        )
        if (
            _canonical_harness_name(args.harness) == "copilot"
            and _copilot_hook_stage(payload) == "pretooluse"
            and runtime_artifact is None
            and stored_policy_action is None
            and not isinstance(getattr(args, "policy_action", None), str)
            and incoming_policy_action in VALID_GUARD_ACTIONS
            and is_explicitly_benign_tool_action_request(
                payload.get("tool_name"),
                payload.get("tool_input", payload.get("arguments")),
            )
        ):
            policy_action = "allow"
        if (
            stored_policy_action is None
            and not isinstance(getattr(args, "policy_action", None), str)
            and not isinstance(payload.get("policy_action"), str)
            and runtime_artifact is not None
            and runtime_artifact.artifact_type == "tool_action_request"
        ):
            policy_action = SAFE_CHANGED_HASH_ACTION
        if policy_action not in VALID_GUARD_ACTIONS:
            policy_action = SAFE_CHANGED_HASH_ACTION
        daemon_status = _optional_string(payload.get("daemon_status"))
        fail_mode = _optional_string(payload.get("fail_mode"))
        daemon_failure_reason: str | None = None
        if daemon_status in _HOOK_DAEMON_FAILURE_STATUSES and fail_mode in _HOOK_DAEMON_FAIL_MODES:
            if fail_mode == "strict":
                policy_action = "block"
                daemon_failure_reason = _HOOK_DAEMON_STRICT_REASON
                payload["permission_decision_reason"] = daemon_failure_reason
            else:
                if policy_action in {"block", "sandbox-required", "require-reapproval"}:
                    daemon_failure_reason = _coalesce_string(
                        payload.get("permission_decision_reason"),
                        _HOOK_DAEMON_PRESERVED_DENY_REASON,
                    )
                    payload["permission_decision_reason"] = daemon_failure_reason
                else:
                    policy_action = "allow"
                    daemon_failure_reason = _HOOK_DAEMON_PERMISSIVE_REASON
                    payload["permission_decision_reason"] = daemon_failure_reason
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
                approval_source=("inline" if _optional_string(payload.get("user_override")) is not None else "policy"),
            )
            store.add_receipt(receipt)
        _record_harness_usage_for_hook(
            store=store,
            action_envelope=action_envelope,
            payload=payload,
            policy_action=policy_action,
        )
        if _should_emit_copilot_hook_response(args):
            _emit_copilot_hook_response(
                policy_action=policy_action,
                reason=_copilot_hook_reason(payload.get("permission_decision_reason")),
                output_stream=output_stream,
            )
            return 0
        incoming_reason = (
            daemon_failure_reason
            or _decision_v2_harness_message(payload)
            or payload.get("permission_decision_reason")
        )
        if _should_emit_native_hook_exit_block(args, event_name=hook_event_name, policy_action=policy_action):
            _emit_native_hook_block_stderr(_native_hook_reason_for_harness(args.harness, incoming_reason))
            return 2
        reason = _native_hook_reason_for_harness(args.harness, incoming_reason)
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


def _record_harness_usage_for_hook(
    *,
    store: GuardStore,
    action_envelope: GuardActionEnvelope | None,
    payload: Mapping[str, object],
    policy_action: str | None,
) -> None:
    usage_payload = dict(payload)
    if isinstance(policy_action, str) and policy_action:
        usage_payload["policy_action"] = policy_action
    record_harness_usage_events(
        store=store,
        action=action_envelope,
        raw_payload=usage_payload,
        occurred_at=_now(),
    )


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
    return (
        args.harness == "codex"
        and event_name == "PreToolUse"
        and policy_action in {"block", "sandbox-required", "require-reapproval"}
        and not getattr(args, "json", False)
        and _is_codex_native_runtime()
    )


def _is_codex_native_runtime() -> bool:
    return bool(os.environ.get("CODEX_HOME", "").strip() or os.environ.get("CODEX_MANAGED_BY_BUN", "").strip())


def _codex_browser_approval_decision(
    *,
    args: argparse.Namespace,
    event_name: str,
    policy_action: str,
    response_payload: dict[str, object],
    store: GuardStore,
    config: GuardConfig,
    daemon_client: object | None = None,
) -> str | None:
    if _canonical_harness_name(args.harness) != "codex":
        return None
    if getattr(args, "json", False):
        return None
    if event_name not in {"PreToolUse", "PostToolUse", "UserPromptSubmit"}:
        return None
    if policy_action not in {"block", "sandbox-required", "require-reapproval"}:
        return None
    if event_name == "PreToolUse" and not _is_codex_native_runtime():
        return None
    approval_requests = response_payload.get("approval_requests")
    if not isinstance(approval_requests, list):
        return None
    request_ids = [
        item["request_id"]
        for item in approval_requests
        if isinstance(item, dict) and isinstance(item.get("request_id"), str)
    ]
    if not request_ids:
        return None
    has_daemon_operation = isinstance(response_payload.get("operation_id"), str)
    wait_timeout_seconds = min(config.approval_wait_timeout_seconds, 25 if has_daemon_operation else 5)
    wait_result = wait_for_approval_requests(
        store=store,
        request_ids=request_ids,
        timeout_seconds=wait_timeout_seconds,
    )
    response_payload["approval_wait"] = wait_result
    if not bool(wait_result.get("resolved")):
        response_payload["review_hint"] = (
            "Approval is still pending in HOL Guard. Approve it in the browser, then retry the same Codex action."
        )
        return None
    resolved_items = [item for item in wait_result.get("items", []) if isinstance(item, dict)]
    if any(str(item.get("resolution_action")) == "block" for item in resolved_items):
        _update_codex_browser_operation_status(response_payload, daemon_client, "blocked")
        response_payload["review_hint"] = "Browser decision saved. HOL Guard kept this Codex action blocked."
        return "block"
    _update_codex_browser_operation_status(response_payload, daemon_client, "completed")
    response_payload["review_hint"] = "Approval received in HOL Guard. Codex is resuming this action."
    return "allow"


def _update_codex_browser_operation_status(
    response_payload: dict[str, object],
    daemon_client: object | None,
    status: str,
) -> None:
    operation_id = response_payload.get("operation_id")
    if daemon_client is None or not isinstance(operation_id, str) or not operation_id:
        return
    update_operation_status = getattr(daemon_client, "update_operation_status", None)
    if not callable(update_operation_status):
        return
    with suppress(Exception):
        update_operation_status(operation_id=operation_id, status=status)


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


def _claude_guard_approval_question_text(approval_code: str) -> str:
    return f"HOL Guard intercepted this sensitive action (approval code: {approval_code}). What should Claude do?"


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
    saved_at = _now()
    tool_name = _optional_string(payload.get("tool_name"))
    approval_code = secrets.token_hex(6)
    approval_question = _claude_guard_approval_question_text(approval_code)
    notice_payload: dict[str, object] = {
        "saved_at": saved_at,
        "reason": reason,
        "artifact_id": artifact.artifact_id,
        "artifact_hash": artifact_hash,
        "artifact_name": artifact.name,
        "artifact_type": artifact.artifact_type,
        "config_path": artifact.config_path,
        "source_scope": artifact.source_scope,
        "approval_header": _CLAUDE_GUARD_APPROVAL_HEADER,
        "approval_question": approval_question,
        "approval_options": list(_CLAUDE_GUARD_APPROVAL_OPTIONS),
        "approval_code": approval_code,
    }
    if tool_name is not None:
        notice_payload["tool_name"] = tool_name
    try:
        store.set_sync_payload(_claude_permission_notice_state_key(session_id, tool_name), notice_payload, saved_at)
        pending_key = _claude_pending_permission_state_key(session_id, artifact.artifact_id)
        store.set_sync_payload(pending_key, notice_payload, saved_at)
        _append_claude_pending_permission_key(store, session_id=session_id, pending_key=pending_key, now=saved_at)
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
        if isinstance(persisted, dict):
            artifact_id = _optional_string(persisted.get("artifact_id"))
            if artifact_id is not None:
                pending_key = _claude_pending_permission_state_key(session_id, artifact_id)
                pending = store.get_sync_payload(pending_key)
                if not isinstance(pending, dict):
                    store.delete_sync_payload(selected_key)
                    persisted = None
            else:
                store.delete_sync_payload(selected_key)
                persisted = None
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


def _load_single_claude_pending_permission(
    store: GuardStore,
    payload: dict[str, object],
) -> tuple[str, dict[str, object]] | None:
    session_id = _optional_string(payload.get("session_id"))
    if session_id is None:
        return None
    try:
        index_payload = store.get_sync_payload(_claude_pending_permission_index_key(session_id))
    except (OSError, sqlite3.Error):
        return None
    if not isinstance(index_payload, list):
        return None
    pending_keys = [str(item) for item in index_payload]
    pending_items: list[tuple[str, dict[str, object]]] = []
    for pending_key in pending_keys:
        try:
            pending = store.get_sync_payload(pending_key)
        except (OSError, sqlite3.Error):
            continue
        if isinstance(pending, dict):
            pending_items.append((pending_key, pending))
    prompt_seen_items = [item for item in pending_items if item[1].get("permission_prompt_seen") is True]
    if len(prompt_seen_items) == 1:
        return prompt_seen_items[0]
    if len(pending_items) != 1:
        return None
    try:
        pending = store.get_sync_payload(pending_items[0][0])
    except (OSError, sqlite3.Error):
        return None
    if not isinstance(pending, dict):
        return None
    return pending_items[0][0], pending


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
    source: str = "claude-native-approval",
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
                source=source,
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


def _discard_claude_pending_permissions(store: GuardStore, payload: dict[str, object]) -> int:
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
    if not pending_keys:
        return 0
    try:
        store.delete_sync_payloads([*pending_keys, index_key])
    except (OSError, sqlite3.Error):
        return 0
    return len(pending_keys)


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


def _claude_guard_approval_question_message(notice: dict[str, object] | None) -> str:
    tool_name = _optional_string((notice or {}).get("tool_name")) or "this tool"
    reason = _optional_string((notice or {}).get("reason"))
    header = _optional_string((notice or {}).get("approval_header")) or _CLAUDE_GUARD_APPROVAL_HEADER
    question = _optional_string((notice or {}).get("approval_question")) or (
        "HOL Guard intercepted this sensitive action. What should Claude do?"
    )
    options = _claude_guard_approval_options_from_value((notice or {}).get("approval_options"))
    if not options:
        options = _CLAUDE_GUARD_APPROVAL_OPTIONS
    options_text = "', '".join(options)
    reason_text = f" HOL Guard reason: {_ensure_terminal_punctuation(reason)}" if reason is not None else ""
    return (
        f"HOL Guard needs the user's explicit decision before {tool_name} can run.{reason_text} "
        "The native Claude permission prompt is not the final decision surface for this request. Call "
        "AskUserQuestion now with one HOL Guard approval question before retrying the tool. Use header "
        f"'{header}', question '{question}', and exactly these options: '{options_text}'. If the user chooses an "
        "allow option, retry the same tool once. If the user chooses Keep blocked, do not retry the sensitive action."
    )


def _normalize_claude_guard_approval_text(value: str) -> str:
    return " ".join(value.strip().lower().split())


def _claude_guard_approval_options_from_value(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    labels: list[str] = []
    for item in value:
        label: str | None
        if isinstance(item, dict):
            label = _optional_string(item.get("label"))
        elif isinstance(item, str):
            label = item.strip()
        else:
            label = None
        if label is None:
            return ()
        labels.append(label)
    return tuple(labels)


def _claude_guard_prompt_contract_from_pending(
    pending: dict[str, object],
) -> tuple[str, str, tuple[str, ...]] | None:
    header = _optional_string(pending.get("approval_header"))
    question = _optional_string(pending.get("approval_question"))
    approval_code = _optional_string(pending.get("approval_code"))
    options = _claude_guard_approval_options_from_value(pending.get("approval_options"))
    if approval_code is None:
        if header is None and question is None and not options:
            return (
                _CLAUDE_GUARD_APPROVAL_HEADER,
                "HOL Guard intercepted this sensitive action. What should Claude do?",
                _CLAUDE_GUARD_APPROVAL_OPTIONS,
            )
        if header is None or question is None or not options:
            return None
        expected_question = "HOL Guard intercepted this sensitive action. What should Claude do?"
    else:
        if header is None or question is None or not options:
            return None
        expected_question = _claude_guard_approval_question_text(approval_code)
    normalized_expected_options = tuple(
        _normalize_claude_guard_approval_text(option) for option in _CLAUDE_GUARD_APPROVAL_OPTIONS
    )
    normalized_pending_options = tuple(_normalize_claude_guard_approval_text(option) for option in options)
    if _normalize_claude_guard_approval_text(question) != _normalize_claude_guard_approval_text(expected_question):
        return None
    if normalized_pending_options != normalized_expected_options:
        return None
    return header, question, options


def _claude_guard_prompt_contract_from_question_list(
    payload_section: object,
) -> tuple[str, str, tuple[str, ...]] | None:
    if not isinstance(payload_section, dict):
        return None
    questions = payload_section.get("questions")
    if not isinstance(questions, list) or len(questions) != 1:
        return None
    first_question = questions[0]
    if not isinstance(first_question, dict):
        return None
    header = _optional_string(first_question.get("header"))
    question = _optional_string(first_question.get("question"))
    options = _claude_guard_approval_options_from_value(first_question.get("options"))
    if header is None or question is None or not options:
        return None
    return header, question, options


def _claude_guard_prompt_contract_matches(
    expected_contract: tuple[str, str, tuple[str, ...]],
    actual_contract: tuple[str, str, tuple[str, ...]],
) -> bool:
    expected_header, expected_question, expected_options = expected_contract
    actual_header, actual_question, actual_options = actual_contract
    if _normalize_claude_guard_approval_text(actual_header) != _normalize_claude_guard_approval_text(expected_header):
        return False
    if _normalize_claude_guard_approval_text(actual_question) != _normalize_claude_guard_approval_text(
        expected_question
    ):
        return False
    expected_labels = tuple(_normalize_claude_guard_approval_text(option) for option in expected_options)
    actual_labels = tuple(_normalize_claude_guard_approval_text(option) for option in actual_options)
    return actual_labels == expected_labels


def _is_claude_guard_approval_question(
    payload: dict[str, object],
    pending: dict[str, object],
) -> bool:
    if _hook_event_name(payload) != "PostToolUse":
        return False
    tool_name = _optional_string(payload.get("tool_name"))
    if tool_name is None or tool_name.lower() != "askuserquestion":
        return False
    expected_contract = _claude_guard_prompt_contract_from_pending(pending)
    if expected_contract is None:
        return False
    tool_input_contract = _claude_guard_prompt_contract_from_question_list(payload.get("tool_input"))
    if tool_input_contract is None:
        return False
    if not _claude_guard_prompt_contract_matches(expected_contract, tool_input_contract):
        return False
    response_contract = _claude_guard_prompt_contract_from_question_list(payload.get("tool_response"))
    return response_contract is None or _claude_guard_prompt_contract_matches(expected_contract, response_contract)


def _claude_guard_approval_action_for_answer(answer_text: str) -> str | None:
    normalized_answer = _normalize_claude_guard_approval_text(answer_text)
    if normalized_answer == _normalize_claude_guard_approval_text("Keep blocked"):
        return "block"
    if normalized_answer in {
        _normalize_claude_guard_approval_text("Allow once"),
        _normalize_claude_guard_approval_text("Allow during this session"),
    }:
        return "allow"
    return None


def _claude_guard_answer_text_from_value(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value
    if isinstance(value, dict):
        label = _optional_string(value.get("label"))
        if label is not None:
            return label
    return None


def _claude_guard_approval_answer(payload: dict[str, object], *, expected_question: str | None = None) -> str | None:
    response = payload.get("tool_response")
    answer_text: str | None = None
    if isinstance(response, dict):
        answers = response.get("answers")
        if isinstance(answers, dict):
            normalized_expected_question = (
                _normalize_claude_guard_approval_text(expected_question) if isinstance(expected_question, str) else None
            )
            if normalized_expected_question is not None:
                for question, answer in answers.items():
                    if not isinstance(question, str):
                        continue
                    if _normalize_claude_guard_approval_text(question) != normalized_expected_question:
                        continue
                    parsed_answer_text = _claude_guard_answer_text_from_value(answer)
                    if parsed_answer_text is not None:
                        answer_text = parsed_answer_text
                        break
            if answer_text is None and len(answers) == 1:
                only_answer = next(iter(answers.values()))
                answer_text = _claude_guard_answer_text_from_value(only_answer)
        if answer_text is None:
            for key in ("answer", "selected_answer", "selected", "choice", "value", "label"):
                value = response.get(key)
                parsed_answer_text = _claude_guard_answer_text_from_value(value)
                if parsed_answer_text is not None:
                    answer_text = parsed_answer_text
                    break
        if answer_text is None and "questions" not in response and "options" not in response:
            content = response.get("content")
            if isinstance(content, str) and content.strip():
                answer_text = content
    elif isinstance(response, str) and response.strip():
        answer_text = response
    if answer_text is None:
        return None
    return _claude_guard_approval_action_for_answer(answer_text)


def _persist_claude_guard_question_decision(store: GuardStore, payload: dict[str, object]) -> bool:
    pending_pair = _load_single_claude_pending_permission(store, payload)
    if pending_pair is None:
        return False
    pending_key, pending = pending_pair
    approval_code = _optional_string(pending.get("approval_code"))
    if approval_code is None and pending.get("permission_prompt_seen") is not True:
        return False
    if not _is_claude_guard_approval_question(payload, pending):
        return False
    action = _claude_guard_approval_answer(
        payload,
        expected_question=_optional_string(pending.get("approval_question")),
    )
    if action is None:
        return False
    artifact_id = _optional_string(pending.get("artifact_id"))
    artifact_hash_value = _optional_string(pending.get("artifact_hash"))
    if artifact_id is None or artifact_hash_value is None:
        return False
    saved = _persist_claude_native_permission_policy(
        store=store,
        artifact_id=artifact_id,
        artifact_hash=artifact_hash_value,
        action=action,
        reason=(
            "Allowed through HOL Guard AskUserQuestion approval."
            if action == "allow"
            else "Blocked through HOL Guard AskUserQuestion approval."
        ),
        now=_now(),
        source="claude-ask-user-question",
    )
    if not saved:
        return False
    session_id = _optional_string(payload.get("session_id"))
    if session_id is not None:
        _remove_claude_pending_permission(store, session_id=session_id, pending_key=pending_key)
    return True


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
    intro = "HOL Guard intercepted a sensitive request and is routing it to a HOL Guard approval question."
    if tool_name is not None:
        intro = (
            f"HOL Guard intercepted Claude's attempt to use {tool_name} and is routing it to a HOL Guard approval "
            "question."
        )
    if reason is not None:
        return (
            f"{intro} This approval flow came from HOL Guard, not from Claude alone. "
            f"{_ensure_terminal_punctuation(reason)} "
            "HOL Guard will ask the user to choose Allow once, Allow during this session, or Keep blocked before "
            "Claude retries the action."
        )
    return (
        f"{intro} This approval flow came from HOL Guard, not from Claude alone. "
        "HOL Guard will ask the user to choose Allow once, Allow during this session, or Keep blocked before Claude "
        "retries the action."
    )


def _claude_permission_prompt_additional_context(notice: dict[str, object] | None) -> str:
    if notice is not None:
        return _claude_guard_approval_question_message(notice)
    reason = _optional_string(notice.get("reason")) if notice is not None else None
    if reason is not None:
        return (
            "HOL Guard intercepted the sensitive request and is routing it into a HOL Guard approval question. "
            "This approval flow came from HOL Guard, not from Claude alone. "
            f"{_ensure_terminal_punctuation(reason)} Ask the user with AskUserQuestion and the options Allow once, "
            "Allow during this session, and Keep blocked. If the user chooses Keep blocked, do not retry the same "
            "sensitive access."
        )
    return (
        "HOL Guard intercepted the sensitive request and is routing it into a HOL Guard approval question. "
        "This approval flow came from HOL Guard, not from Claude alone. Ask the user with AskUserQuestion and the "
        "options Allow once, Allow during this session, and Keep blocked. If the user chooses Keep blocked, do not "
        "retry the same action."
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
            f"HOL Guard is routing this Claude approval request for {tool_name} into a HOL Guard decision prompt. "
            f"{_ensure_terminal_punctuation(reason)} "
            "Choose Allow once, Allow during this session, or Keep blocked in the HOL Guard prompt."
        )
    if tool_name is not None:
        return (
            f"HOL Guard is routing this Claude approval request for {tool_name} into a HOL Guard decision prompt. "
            "Choose Allow once, Allow during this session, or Keep blocked in the HOL Guard prompt."
        )
    return (
        "HOL Guard is routing this Claude approval request into a HOL Guard decision prompt to protect a sensitive "
        "action. Choose Allow once, Allow during this session, or Keep blocked in the HOL Guard prompt."
    )


def _claude_native_pretooluse_terminal_notice(*, payload: dict[str, object], reason: str) -> str:
    tool_name = _claude_notification_tool_name(payload)
    if tool_name is not None:
        return (
            f"HOL Guard intercepted Claude's attempt to use {tool_name}. {_ensure_terminal_punctuation(reason)} "
            "Guard will route the next approval through a HOL Guard prompt if Claude asks to continue."
        )
    return (
        "HOL Guard intercepted a sensitive Claude action. "
        f"{_ensure_terminal_punctuation(reason)} Guard will route the next approval through a HOL Guard prompt if "
        "Claude asks to continue."
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
    if _HOOK_DAEMON_UNREACHABLE_REASON_MARKER in reason.lower():
        return f"{reason} Restart HOL Guard, then retry."
    return f"{reason} Approve it in HOL Guard, then retry."


def _native_approval_center_context(response_payload: dict[str, object], *, harness: str) -> str | None:
    approval_center_url = response_payload.get("approval_center_url")
    if not isinstance(approval_center_url, str) or not approval_center_url.strip():
        return None
    queued = response_payload.get("approval_requests")
    review_url = first_approval_url(queued) if isinstance(queued, list) else None
    review_url = review_url or approval_center_url.strip()
    harness_label = {
        "claude-code": "Claude Code",
        "codex": "Codex",
        "copilot": "Copilot",
        "opencode": "OpenCode",
    }.get(_canonical_harness_name(harness), "the harness")
    return (
        f"Open HOL Guard to approve or keep this blocked: {review_url}. "
        f"After you choose, retry the same {harness_label} action."
    )


def _runtime_stored_policy_action(
    *,
    store: GuardStore,
    harness: str,
    artifact: GuardArtifact,
    artifact_id: str,
    artifact_hash: str,
    workspace: str | None,
) -> str | None:
    decision = store.resolve_policy_decision(
        harness,
        artifact_id,
        artifact_hash,
        workspace,
        artifact.publisher,
    )
    if decision is None:
        return None
    action = _optional_string(decision.get("action"))
    if action is None:
        return None
    scope = _optional_string(decision.get("scope"))
    if (
        action in {"allow", "warn", "review"}
        and scope in {"workspace", "publisher", "harness", "global"}
        and _runtime_artifact_risk_classes(artifact)
    ):
        if scope == "workspace":
            decision_artifact_id = _optional_string(decision.get("artifact_id"))
            decision_artifact_hash = _optional_string(decision.get("artifact_hash"))
            if decision_artifact_id == artifact_id and (
                decision_artifact_hash is None or decision_artifact_hash == artifact_hash
            ):
                return action
        return None
    return action


def _runtime_artifact_policy_action(config: GuardConfig, artifact: GuardArtifact, harness: str) -> str:
    if _prompt_requires_hard_block(artifact):
        return "block"
    canonical_harness = _canonical_harness_name(harness)
    risk_classes = _runtime_artifact_risk_classes(artifact)
    has_configured_risk_action = any(
        _resolve_configured_risk_action(config, risk_class, harness=canonical_harness) for risk_class in risk_classes
    )
    if has_configured_risk_action:
        risk_actions = [
            _resolve_configured_risk_action(config, risk_class, harness=canonical_harness)
            or resolve_risk_action(config, risk_class, harness=canonical_harness)
            for risk_class in risk_classes
        ]
        resolved_actions = [action for action in risk_actions if action in VALID_GUARD_ACTIONS]
        if resolved_actions:
            return max(resolved_actions, key=_guard_action_severity)
    guard_default_action = _runtime_artifact_guard_default_action(artifact)
    risk_actions = [resolve_risk_action(config, risk_class, harness=canonical_harness) for risk_class in risk_classes]
    resolved_actions = [action for action in risk_actions if action in VALID_GUARD_ACTIONS]
    if resolved_actions:
        resolved = max(resolved_actions, key=_guard_action_severity)
        if guard_default_action is not None and _guard_action_severity(guard_default_action) > _guard_action_severity(
            resolved
        ):
            return guard_default_action
        return resolved
    if guard_default_action is not None:
        return guard_default_action
    return SAFE_CHANGED_HASH_ACTION


def _resolve_configured_risk_action(config: GuardConfig, risk_class: str, *, harness: str) -> str | None:
    if config.harness_risk_actions is not None:
        harness_actions = config.harness_risk_actions.get(harness)
        if harness_actions is not None and risk_class in harness_actions:
            return harness_actions[risk_class]
    if config.risk_actions is not None and risk_class in config.risk_actions:
        return config.risk_actions[risk_class]
    return None


def _runtime_artifact_guard_default_action(artifact: GuardArtifact) -> str | None:
    value = artifact.metadata.get("guard_default_action")
    if value in VALID_GUARD_ACTIONS:
        return str(value)
    return None


def _runtime_action_data_flow_signals(
    action_envelope: GuardActionEnvelope | None,
    *,
    workspace: Path | None,
) -> tuple[RiskSignalV2, ...]:
    if action_envelope is None:
        return ()
    return detect_data_flow_exfiltration(action_envelope, workspace=workspace)


def _runtime_data_flow_summary(signals: tuple[RiskSignalV2, ...]) -> str:
    sink_type = _runtime_data_flow_sink_type(signals)
    if signals:
        return f"This command sends local secret to {sink_type}. Guard kept raw secret contents out of the evidence."
    return f"This command sends local secret to {sink_type}."


def _runtime_data_flow_sink_type(signals: tuple[RiskSignalV2, ...]) -> str:
    signal_ids = {signal.signal_id for signal in signals}
    if any(signal.category == "network" for signal in signals):
        return "network host"
    if "data-flow:clipboard-secret" in signal_ids:
        return "clipboard"
    if "data-flow:world-readable-temp-secret" in signal_ids:
        return "world-readable temp file"
    if "data-flow:git-remote-token" in signal_ids:
        return "git remote configuration"
    return "external sink"


def _guard_action_severity(action: str) -> int:
    return {
        "allow": 0,
        "warn": 1,
        "review": 2,
        "require-reapproval": 3,
        "sandbox-required": 4,
        "block": 5,
    }.get(action, -1)


def _runtime_artifact_risk_classes(artifact: GuardArtifact) -> list[str]:
    if artifact.artifact_type == "file_read_request":
        return ["local_secret_read"]
    if artifact.artifact_type == "prompt_request":
        prompt_classes = _prompt_request_classes(artifact)
        risk_classes: list[str] = []
        if "secret_read" in prompt_classes:
            risk_classes.append("local_secret_read")
        if "exfil_intent" in prompt_classes:
            risk_classes.append("credential_exfiltration")
        if "destructive_intent" in prompt_classes:
            risk_classes.append("destructive_shell")
        if "subprocess_intent" in prompt_classes:
            risk_classes.append("destructive_shell")
        if "prompt_injection_intent" in prompt_classes:
            risk_classes.append("destructive_shell")
        return risk_classes
    if artifact.artifact_type != "tool_action_request":
        return []
    action_class = artifact.metadata.get("action_class")
    if not isinstance(action_class, str):
        return []
    action_risk_classes = {
        "credential exfiltration shell command": [
            "data_flow_exfiltration",
            "credential_exfiltration",
            "network_egress",
        ],
        "docker-sensitive command": ["network_egress", "destructive_shell"],
        "docker client config access": ["local_secret_read"],
        "encoded or encrypted shell command": ["encoded_execution"],
        "shell file upload command": ["credential_exfiltration", "network_egress"],
        "destructive shell command": ["destructive_shell"],
    }
    return action_risk_classes.get(action_class.strip().lower(), [])


def _guard_settings_payload(config: GuardConfig) -> dict[str, object]:
    return {
        "generated_at": _now(),
        "guard_home": str(config.guard_home),
        "config_path": str(config.guard_home / "config.toml"),
        "settings": editable_guard_settings(config),
    }


_PRESET_DESCRIPTIONS: dict[str, str] = {
    "gentle": (
        "Warn-only mode. All risky actions surface as warnings so you stay informed "
        "without blocking any agent workflows."
    ),
    "balanced": (
        "Default preset. High-severity actions (secret reads, exfiltration) require "
        "re-approval; network egress is warned."
    ),
    "strict": (
        "Elevated protection. Data-flow exfiltration is blocked; all other high-risk "
        "actions require explicit re-approval."
    ),
    "paranoid": (
        "Maximum protection. Every risk class is blocked outright. "
        "Recommended for high-security or air-gapped environments."
    ),
    "custom": "Fully custom action map. Each risk class uses the action you configured explicitly.",
}


def _guard_settings_explain_payload(config: GuardConfig) -> dict[str, object]:
    preset = config.security_level
    description = _PRESET_DESCRIPTIONS.get(preset, f"Unknown preset '{preset}'.")
    effective = editable_guard_settings(config).get("risk_actions") or {}
    return {
        "generated_at": _now(),
        "preset": preset,
        "description": description,
        "effective_risk_actions": effective,
    }


def _guard_settings_doctor_payload(config: GuardConfig) -> dict[str, object]:
    issues: list[dict[str, str]] = []
    if config.mode == "observe":
        issues.append(
            {
                "severity": "warning",
                "message": "Guard is in observe mode. No actions will be blocked or reviewed.",
            }
        )
    if config.security_level not in VALID_SECURITY_LEVELS:
        fallback = DEFAULT_SECURITY_LEVEL
        issues.append(
            {
                "severity": "error",
                "message": f"Unknown security level '{config.security_level}'. Falling back to '{fallback}'.",
            }
        )
    if config.approval_wait_timeout_seconds < 10:
        issues.append(
            {
                "severity": "warning",
                "message": (
                    f"approval_wait_timeout_seconds={config.approval_wait_timeout_seconds} is very low. "
                    "Approvals may time out before you can respond."
                ),
            }
        )
    return {
        "generated_at": _now(),
        "issues": issues,
        "healthy": len(issues) == 0,
    }


def _guard_cli_settings_payload(config: GuardConfig) -> dict[str, object]:
    payload = _guard_settings_payload(config)
    settings = payload.get("settings")
    if not isinstance(settings, dict):
        return payload
    cli_settings = dict(settings)
    cli_settings.pop("billing", None)
    return {
        **payload,
        "settings": cli_settings,
    }


def _runtime_detector_registry_payload(config: GuardConfig) -> dict[str, object]:
    return {
        "enabled": config.runtime_detector_registry,
        "debug_trace": config.runtime_detector_debug_trace,
        "timeout_ms": config.runtime_detector_timeout_ms,
        "disabled_detector_ids": list(config.runtime_detector_disabled_ids),
    }


def _runtime_detector_perf_payload(config: GuardConfig) -> list[dict[str, object]]:
    from ..runtime.actions import GuardActionEnvelope
    from ..runtime.detectors import (
        _SLOW_DETECTOR_THRESHOLD_MS,
        DetectorContext,
    )
    from ..runtime.runner import _get_default_detector_registry

    probe_action = GuardActionEnvelope(
        schema_version=1,
        action_id="perf-probe",
        harness="doctor",
        event_name="HarnessStart",
        action_type="harness_start",
        workspace=None,
        workspace_hash=None,
        tool_name=None,
        command=None,
        prompt_excerpt=None,
        prompt_text=None,
        target_paths=(),
        network_hosts=(),
        mcp_server=None,
        mcp_tool=None,
        package_manager=None,
        package_name=None,
        script_name=None,
        raw_payload_redacted={},
    )
    probe_context = DetectorContext(
        config=config,
        workspace=None,
        prior_decisions={},
        threat_intel={},
        redaction_settings={},
    )
    result = _get_default_detector_registry().run(
        probe_action,
        probe_context,
        timeout_ms=config.runtime_detector_timeout_ms,
        disabled_detector_ids=config.runtime_detector_disabled_ids,
    )
    return [
        {
            **t.to_dict(),
            "slow": t.elapsed_ms >= _SLOW_DETECTOR_THRESHOLD_MS,
        }
        for t in result.telemetry
    ]


def _update_guard_cli_settings(*, args: argparse.Namespace, config: GuardConfig, guard_home: Path) -> GuardConfig:
    settings_command = getattr(args, "settings_set_command", None)
    if settings_command == "security-level":
        payload: dict[str, object] = {"security_level": args.security_level}
        if args.security_level in _NAMED_SECURITY_LEVELS:
            payload["risk_actions"] = {}
            payload["harness_risk_actions"] = {}
        elif args.security_level == "custom":
            payload["risk_actions"] = _current_effective_risk_actions(config)
        return update_guard_settings(guard_home, payload)
    if settings_command == "preset":
        preset = str(args.preset)
        payload_preset: dict[str, object] = {"security_level": preset}
        if preset in _NAMED_SECURITY_LEVELS:
            payload_preset["risk_actions"] = {}
            payload_preset["harness_risk_actions"] = {}
        elif preset == "custom":
            payload_preset["risk_actions"] = _current_effective_risk_actions(config)
        return update_guard_settings(guard_home, payload_preset)
    if settings_command == "secret-files":
        action_map = {"ask": "require-reapproval", "warn": "warn", "allow": "allow"}
        mapped = action_map.get(str(args.action), "warn")
        risk_actions = dict(config.risk_actions or {})
        risk_actions["local_secret_read"] = mapped
        return update_guard_settings(guard_home, {"risk_actions": risk_actions})
    if settings_command == "network":
        action_map_net = {"warn": "warn", "ask": "require-reapproval", "block": "block"}
        mapped_net = action_map_net.get(str(args.action), "warn")
        risk_actions_net = dict(config.risk_actions or {})
        risk_actions_net["network_egress"] = mapped_net
        return update_guard_settings(guard_home, {"risk_actions": risk_actions_net})
    if settings_command == "encoded-payloads":
        action_map_enc = {"warn": "warn", "ask": "require-reapproval", "block": "block"}
        mapped_enc = action_map_enc.get(str(args.action), "warn")
        risk_actions_enc = dict(config.risk_actions or {})
        risk_actions_enc["encoded_execution"] = mapped_enc
        risk_actions_enc["encoded_exfiltration"] = mapped_enc
        return update_guard_settings(guard_home, {"risk_actions": risk_actions_enc})
    if settings_command in _SETTINGS_POLICY_RISK_ACTIONS:
        policy = str(getattr(args, "policy", "")).strip().lower()
        mapped_actions = _SETTINGS_POLICY_RISK_ACTIONS[settings_command].get(policy)
        if mapped_actions is None:
            raise ValueError(f"Unsupported Guard settings policy '{policy}' for {settings_command}.")
        risk_actions = dict(config.risk_actions or {})
        risk_actions.update(mapped_actions)
        return update_guard_settings(guard_home, {"risk_actions": risk_actions})
    if settings_command == "risk":
        risk_class = _guard_risk_action_key(str(args.risk_class))
        action = str(args.action)
        harness = getattr(args, "harness", None)
        if isinstance(harness, str) and harness.strip():
            harness_key = _canonical_harness_name(harness.strip().lower())
            harness_actions = {
                name: dict(values)
                for name, values in (config.harness_risk_actions or {}).items()
                if isinstance(values, dict)
            }
            harness_actions.setdefault(harness_key, {})[risk_class] = action
            return update_guard_settings(
                guard_home,
                {
                    "harness_risk_actions": harness_actions,
                },
            )
        risk_actions = dict(config.risk_actions or {})
        risk_actions[risk_class] = action
        return update_guard_settings(
            guard_home,
            {
                "risk_actions": risk_actions,
            },
        )
    raise ValueError("Unsupported Guard settings command.")


def _current_effective_risk_actions(config: GuardConfig) -> dict[str, str]:
    risk_actions = editable_guard_settings(config).get("risk_actions")
    if isinstance(risk_actions, dict):
        return {
            key: value
            for key, value in risk_actions.items()
            if isinstance(key, str) and isinstance(value, str) and value in VALID_GUARD_ACTIONS
        }
    return {}


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
    decision_message = _decision_v2_harness_message(response_payload)
    if decision_message is not None and _should_use_decision_v2_harness_message(response_payload, decision_message):
        return decision_message
    if artifact.artifact_type == "prompt_request":
        harness = response_payload.get("harness")
        prompt_classes = _prompt_request_classes(artifact)
        if harness == "codex" and "secret_read" in prompt_classes:
            prompt_summary = artifact.metadata.get("prompt_summary")
            if isinstance(prompt_summary, str) and "credential-looking local file" in prompt_summary:
                return (
                    "HOL Guard stopped this Codex prompt before Codex could open a credential-looking local file. "
                    "Codex does not expose native approval prompts for Read-tool file reads, so Guard blocks this "
                    "request at prompt time."
                )
            return (
                "HOL Guard stopped this Codex prompt before Codex could open a sensitive local file. Codex does not "
                "expose native approval prompts for Read-tool file reads, so Guard blocks this request at prompt time."
            )
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
                "secrets. The approval flow came from HOL Guard, not from Claude alone. HOL Guard will ask you to "
                "choose Allow once, Allow during this session, or Keep blocked before Claude retries this action."
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
        action_class = artifact.metadata.get("action_class")
        if (
            action_class == "credential exfiltration shell command"
            and "credential-looking output" not in trimmed_summary.lower()
        ):
            trimmed_summary = f"{trimmed_summary} Guard also detected credential-looking output."
        return f"HOL Guard flagged this request: {trimmed_summary}"
    return "HOL Guard flagged this request for review."


def _decision_v2_harness_message(response_payload: dict[str, object]) -> str | None:
    decision_v2 = response_payload.get("decision_v2_json")
    if not isinstance(decision_v2, Mapping):
        return None
    message = decision_v2.get("harness_message")
    if isinstance(message, str) and message.strip():
        return message.strip()
    return None


def _decision_v2_has_data_flow_signal(response_payload: dict[str, object]) -> bool:
    decision_v2 = response_payload.get("decision_v2_json")
    if not isinstance(decision_v2, Mapping):
        return False
    signals = decision_v2.get("signals")
    if not isinstance(signals, list):
        return False
    for item in signals:
        if not isinstance(item, Mapping):
            continue
        detector = item.get("detector")
        signal_id = item.get("signal_id")
        if detector == "data_flow.exfiltration":
            return True
        if isinstance(signal_id, str) and signal_id.startswith("data-flow:"):
            return True
    return False


def _should_use_decision_v2_harness_message(response_payload: dict[str, object], message: str) -> bool:
    if _decision_v2_has_data_flow_signal(response_payload):
        return True
    generic_messages = {
        "HOL Guard blocked this action.",
        "HOL Guard wants this action reviewed and run in a sandboxed path.",
    }
    if message in generic_messages:
        return False
    return not message.startswith("HOL Guard needs a fresh approval because this action changed.")


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
    briefing_sentence = "HOL Guard will intercept Claude's next sensitive action and open a branded approval question."
    if "secret_read" in _prompt_request_classes(artifact):
        briefing_sentence = (
            "HOL Guard will intercept Claude's next attempt to access local secrets and open a branded approval "
            "question to protect you."
        )
    return (
        f"{_ensure_terminal_punctuation(native_reason)} "
        "Do not ask for approval at the prompt stage. Attempt the intended sensitive tool once so HOL Guard can "
        "evaluate the exact tool, path, and arguments, then route that concrete action into a HOL Guard approval "
        "question with Allow once, Allow during this session, and Keep blocked. First tell the user exactly: "
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
                    "If Claude asks to continue, HOL Guard will route the decision through a branded approval prompt."
                )
            return (
                "HOL Guard intercepted this prompt because it leads to a sensitive action. "
                "If Claude asks to continue, HOL Guard will route the decision through a branded approval prompt."
            )
        if policy_action in {"block", "sandbox-required"}:
            return _ensure_terminal_punctuation(native_reason)
        return None
    if event_name == "PreToolUse" and policy_action in {"require-reapproval", "block", "sandbox-required"}:
        return _ensure_terminal_punctuation(native_reason)
    return None


def _codex_prompt_block_system_message(*, policy_action: str, native_reason: str) -> str | None:
    if policy_action not in {"block", "sandbox-required", "require-reapproval"}:
        return None
    if "open hol guard" not in native_reason.lower():
        return None
    return f"HOL Guard paused your Codex prompt. {native_reason}"


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
        elif _canonical_harness_name(harness) in {"claude-code", "codex"}:
            payload["hookSpecificOutput"] = {"hookEventName": event_name}
        if payload:
            _write_json_line(payload, output_stream=output_stream)
        return
    if event_name in {"Notification", "PermissionRequest"}:
        if event_name == "PermissionRequest" and policy_action in {"block", "sandbox-required"}:
            decision: dict[str, object] = {
                "behavior": "deny",
                "message": additional_context or reason,
            }
            if _canonical_harness_name(harness) != "codex":
                decision["interrupt"] = False
            payload["hookSpecificOutput"] = {
                "hookEventName": event_name,
                "decision": decision,
            }
            _write_json_line(payload, output_stream=output_stream)
            return
        if event_name == "PermissionRequest" and _canonical_harness_name(harness) == "codex":
            if policy_action == "require-reapproval":
                payload["systemMessage"] = (
                    "HOL Guard is reviewing this Codex approval request. Codex will show its normal approval prompt; "
                    "choose allow only if you trust the exact tool action."
                )
            if payload:
                _write_json_line(payload, output_stream=output_stream)
            return
        if additional_context:
            payload["hookSpecificOutput"] = {
                "hookEventName": event_name,
                "additionalContext": additional_context,
            }
        if payload:
            _write_json_line(payload, output_stream=output_stream)
        return
    if event_name == "PostToolUse" and policy_action in {"block", "sandbox-required", "require-reapproval"}:
        payload["decision"] = "block"
        payload["reason"] = reason
        payload["continue"] = False
        payload["stopReason"] = reason
        _write_json_line(payload, output_stream=output_stream)
        return
    permission_decision = _native_hook_permission_decision(policy_action, harness=harness)
    if harness == "codex" and event_name == "PreToolUse" and permission_decision is None:
        return
    hook_specific_output: dict[str, object] = {"hookEventName": event_name}
    if permission_decision is not None:
        hook_specific_output["permissionDecision"] = permission_decision
        if permission_decision != "allow" or _HOOK_DAEMON_UNREACHABLE_REASON_MARKER in reason.lower():
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


def _open_approval_center(
    approval_center_url: str,
    *,
    store: GuardStore,
    config: GuardConfig,
    open_key: str | None = None,
    force_open: bool = False,
) -> dict[str, object]:
    surface_runtime = GuardSurfaceRuntime(store)
    auth_token = load_guard_daemon_auth_token(store.guard_home)
    browser_url = _approval_center_browser_url(approval_center_url, auth_token)
    open_result = surface_runtime.ensure_surface(
        surface="approval-center",
        approval_center_url=approval_center_url,
        browser_url=browser_url,
        approval_surface_policy=config.approval_surface_policy,
        open_key=open_key or approval_center_url,
        force_open=force_open,
        opener=webbrowser.open,
    )
    open_result["browser_url"] = _public_approval_center_url(browser_url) or approval_center_url
    return open_result


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


def _public_approval_center_url(browser_url: str | None) -> str | None:
    if browser_url is None:
        return None
    parsed = urllib.parse.urlparse(browser_url)
    fragment_pairs = [
        (key, value)
        for key, value in urllib.parse.parse_qsl(parsed.fragment, keep_blank_values=True)
        if key != "guard-token"
    ]
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


_ACTION_ENVELOPE_HARNESSES = frozenset({"codex", "claude-code", "opencode", "copilot", "gemini"})


def _hook_action_envelope(
    *,
    harness: str,
    payload: dict[str, object],
    home_dir: Path,
    workspace: Path | None,
) -> GuardActionEnvelope | None:
    canonical_harness = _canonical_harness_name(harness)
    if canonical_harness not in _ACTION_ENVELOPE_HARNESSES:
        return None
    return normalize_harness_payload(
        canonical_harness,
        _hook_event_name(payload) or "PreToolUse",
        payload,
        workspace=workspace,
        home_dir=home_dir,
    )


def _action_envelope_json(envelope: GuardActionEnvelope | None) -> dict[str, object] | None:
    return envelope.to_dict() if envelope is not None else None


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


_HOOK_EVENT_NAME_MAP = {
    "userpromptsubmitted": "UserPromptSubmit",
    "pretooluse": "PreToolUse",
    "posttooluse": "PostToolUse",
    "permissionrequest": "PermissionRequest",
}


def _hook_event_name(payload: dict[str, object]) -> str | None:
    for key in ("event", "hook_event_name", "hookEventName", "hook_name"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            normalized = value.strip()
            return _HOOK_EVENT_NAME_MAP.get(normalized.lower(), normalized)
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
    prompt_display_texts: list[str] = []
    request_identity = "|".join(sorted(artifact.artifact_id for artifact in artifacts))
    for artifact in artifacts:
        metadata = artifact.metadata
        prompt_signals.extend(_string_list(metadata.get("prompt_signals")))
        matched_text = metadata.get("prompt_matched_text")
        if isinstance(matched_text, str) and matched_text.strip():
            prompt_matched_texts.append(matched_text.strip())
        display_text = metadata.get("prompt_display_text")
        if isinstance(display_text, str) and display_text.strip():
            prompt_display_texts.append(display_text.strip())
        request_class = metadata.get("prompt_request_class")
        if isinstance(request_class, str) and request_class.strip():
            prompt_request_classes.append(request_class.strip())
    deduped_signals = list(dict.fromkeys(prompt_signals))
    deduped_matches = list(dict.fromkeys(prompt_matched_texts))
    deduped_classes = list(dict.fromkeys(prompt_request_classes))
    deduped_display = list(dict.fromkeys(prompt_display_texts))
    request_summary = (
        deduped_display[0] if len(deduped_display) == 1 else "Prompt matches multiple guarded request classes."
    )
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
            "prompt_display_text": request_summary,
            "prompt_request_classes": deduped_classes,
            "request_summary": request_summary,
            "runtime_request_summary": request_summary,
        },
    )


def _hook_runtime_artifact(
    *,
    harness: str,
    payload: dict[str, object],
    action_envelope: GuardActionEnvelope | None,
    data_flow_signals: tuple[RiskSignalV2, ...] = (),
    home_dir: Path,
    guard_home: Path,
    workspace: Path | None,
) -> GuardArtifact | None:
    harness = _canonical_harness_name(harness)
    event_name = _hook_event_name(payload)
    if harness == "codex" and event_name == "PostToolUse":
        output_artifact = _codex_post_tool_output_artifact(
            payload=payload,
            config_path=str(_runtime_policy_path(harness, home_dir, workspace)),
            source_scope=_coalesce_string(payload.get("source_scope"), "project"),
            cwd=workspace,
        )
        if output_artifact is not None:
            return output_artifact
        if _codex_post_tool_command_is_read_only_source_inspection(payload=payload, cwd=workspace):
            return None
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
                    if harness == "codex":
                        prompt_artifacts = [
                            _with_codex_prompt_display_metadata(artifact, prompt_text=prompt_text)
                            for artifact in prompt_artifacts
                        ]
                    return _merged_prompt_runtime_artifact(harness, prompt_artifacts)
            prompt_file_artifact = _codex_prompt_credential_file_artifact(
                prompt_text=prompt_text,
                cwd=workspace,
                config_path=config_path,
            )
            if prompt_file_artifact is not None:
                return prompt_file_artifact
    request = extract_sensitive_file_read_request(
        payload.get("tool_name"),
        payload.get("tool_input", payload.get("arguments")),
        cwd=workspace,
        home_dir=home_dir,
    )
    if request is None:
        request = (
            extract_sensitive_file_read_request_from_action(action_envelope, cwd=workspace, home_dir=home_dir)
            if action_envelope is not None
            else None
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
        if action_envelope is None or not data_flow_signals:
            return None
        return _runtime_data_flow_artifact(
            harness=harness,
            action_envelope=action_envelope,
            data_flow_signals=data_flow_signals,
            config_path=config_path,
            source_scope=source_scope,
        )
    return build_tool_action_request_artifact(
        harness=harness,
        request=tool_request,
        config_path=config_path,
        source_scope=source_scope,
    )


def _runtime_data_flow_artifact(
    *,
    harness: str,
    action_envelope: GuardActionEnvelope,
    data_flow_signals: tuple[RiskSignalV2, ...],
    config_path: str,
    source_scope: str,
) -> GuardArtifact:
    command_text = action_envelope.command or action_envelope.tool_name or action_envelope.action_type
    signal_ids = tuple(signal.signal_id for signal in data_flow_signals)
    fingerprint = hashlib.sha256(
        json.dumps(
            {
                "command_text": command_text,
                "signal_ids": signal_ids,
                "source_scope": source_scope,
            },
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    return GuardArtifact(
        artifact_id=f"{harness}:{source_scope}:data-flow:{fingerprint}",
        name=f"{action_envelope.tool_name or 'runtime'} data-flow exfiltration",
        harness=harness,
        artifact_type="tool_action_request",
        source_scope=source_scope,
        config_path=config_path,
        metadata={
            "action_class": "credential exfiltration shell command",
            "command_text": command_text,
            "guard_default_action": "require-reapproval",
            "request_summary": _runtime_data_flow_summary(data_flow_signals),
            "runtime_request_signals": [signal.plain_reason for signal in data_flow_signals],
            "runtime_request_summary": _runtime_data_flow_summary(data_flow_signals),
            "runtime_request_reason": (
                "Guard detected local-secret data flow in the runtime action before the command could send it away."
            ),
        },
    )


_CODEX_PROMPT_SECRET_KEY_MARKERS = ("TOKEN", "SECRET", "PASSWORD", "PASS", "API_KEY", "API-KEY", "AUTH", "CREDENTIAL")
_CODEX_TOOL_RESPONSE_MAX_DEPTH = 5
_CODEX_TOOL_RESPONSE_TEXT_LIMIT = 20000
_CODEX_PROMPT_FILE_FINGERPRINT_LENGTH = 24


def _codex_post_tool_output_artifact(
    *,
    payload: dict[str, object],
    config_path: str,
    source_scope: str,
    cwd: Path | None,
) -> GuardArtifact | None:
    response_text = _collect_codex_tool_response_text(payload.get("tool_response"))
    tool_name = _coalesce_string(payload.get("tool_name"), "Bash")
    command_text = _codex_post_tool_command_text(payload)
    if not command_text:
        command_text = tool_name
    local_source_matches = _codex_sensitive_local_source_matches(command_text, cwd=cwd)
    references_local_content = bool(local_source_matches) or _codex_command_may_read_local_content(
        command_text, cwd=cwd
    )
    content_matches = classify_secret_content(response_text)
    if not content_matches and references_local_content:
        content_matches = classify_secret_content(response_text, suppress_samples=False)
    if not content_matches:
        return None
    if _codex_source_inspection_can_skip_secret_output(
        command_text=command_text,
        response_text=response_text,
        content_matches=content_matches,
        cwd=cwd,
    ):
        return None
    fingerprint = hashlib.sha256(
        json.dumps(
            {
                "tool_name": tool_name,
                "command_text": command_text,
                "output_class": "credential-looking output",
            },
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    local_secret_source = _codex_local_secret_source_label(
        local_source_matches,
        command_text=command_text,
    )
    runtime_default_action = "require-reapproval" if references_local_content else "warn"
    runtime_request_signals = ["tool output contains credential-looking material"]
    if references_local_content:
        source_signal = "command references local secrets"
        if local_secret_source is not None:
            source_signal = f"command references local secrets from {local_secret_source}"
        runtime_request_signals.append(source_signal)
    request_summary = _codex_tool_output_request_summary(
        tool_name=tool_name,
        command_text=command_text,
        local_secret_source=local_secret_source,
    )
    runtime_request_summary = _codex_tool_output_runtime_summary(local_secret_source)
    metadata: dict[str, object] = {
        "tool_name": tool_name,
        "command_text": command_text,
        "action_class": (
            "credential exfiltration shell command"
            if references_local_content
            else "credential-looking tool output"
        ),
        "guard_default_action": runtime_default_action,
        "request_summary": request_summary,
        "runtime_request_signals": runtime_request_signals,
        "runtime_request_summary": runtime_request_summary,
        "runtime_request_reason": (
            "Guard inspects supported Codex tool output before Codex uses it, so accidental secret reads can be "
            "stopped even when the filename was not obviously sensitive."
        ),
    }
    if local_secret_source is not None:
        metadata["secret_source_family"] = local_secret_source
    return GuardArtifact(
        artifact_id=f"codex:{source_scope}:tool-output:{fingerprint}",
        name=f"{tool_name} credential-looking output",
        harness="codex",
        artifact_type="tool_action_request",
        source_scope=source_scope,
        config_path=config_path,
        metadata=metadata,
    )


def _codex_command_references_sensitive_local_source(command_text: str, *, cwd: Path | None) -> bool:
    return bool(_codex_sensitive_local_source_matches(command_text, cwd=cwd))


def _codex_sensitive_local_source_matches(command_text: str, *, cwd: Path | None) -> list[SecretPathMatch]:
    matches = _codex_sensitive_path_matches_in_text(command_text, cwd=cwd)
    try:
        parts = shlex.split(command_text)
    except ValueError:
        return matches
    for part in parts:
        stripped = part.strip()
        if not stripped or stripped.startswith("-"):
            continue
        if _codex_token_is_url(stripped):
            local_match = _codex_existing_local_path_match(stripped, cwd=cwd)
            if local_match is not None:
                matches.append(local_match)
            continue
        path_match = classify_secret_path(stripped, cwd=cwd)
        if path_match is not None:
            matches.append(path_match)
    return _dedupe_codex_secret_path_matches(matches)


def _dedupe_codex_secret_path_matches(matches: list[SecretPathMatch]) -> list[SecretPathMatch]:
    deduped: list[SecretPathMatch] = []
    seen: set[tuple[str, str]] = set()
    for match in matches:
        key = (match.family, match.requested_path or match.path)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(match)
    return deduped


def _codex_token_is_url(token: str) -> bool:
    parsed = urllib.parse.urlparse(token)
    return bool(parsed.scheme and parsed.netloc)


def _codex_text_contains_sensitive_path_token(text: str, *, cwd: Path | None) -> bool:
    return bool(_codex_sensitive_path_matches_in_text(text, cwd=cwd))


def _codex_sensitive_path_matches_in_text(text: str, *, cwd: Path | None) -> list[SecretPathMatch]:
    matches: list[SecretPathMatch] = []
    for match in _PROMPT_PATH_TOKEN_PATTERN.finditer(text):
        token = match.group(0)
        if _codex_path_token_is_url_path(text, match.start()):
            local_match = _codex_existing_local_path_match(token, cwd=cwd)
            if local_match is not None:
                matches.append(local_match)
            continue
        path_match = classify_secret_path(token, cwd=cwd)
        if path_match is not None:
            matches.append(path_match)
    for token in _codex_url_like_local_path_tokens(text):
        local_match = _codex_existing_local_path_match(token, cwd=cwd)
        if local_match is not None:
            matches.append(local_match)
    return matches


def _codex_url_like_local_path_tokens(text: str) -> tuple[str, ...]:
    separators = frozenset(" \t\r\n'\"`<>|;(){}[]")
    tokens: list[str] = []
    start = 0
    for index, char in enumerate(f"{text} "):
        if char not in separators:
            continue
        token = text[start:index]
        start = index + 1
        if 0 < len(token) <= 255 and _codex_token_is_url(token):
            tokens.append(token)
    return tuple(tokens)


def _codex_existing_local_path_match(token: str, *, cwd: Path | None) -> SecretPathMatch | None:
    if cwd is None:
        return None
    base_dir = cwd.resolve()
    parsed = urllib.parse.urlparse(token)
    if not parsed.scheme or not parsed.netloc:
        return None
    relative_parts = [f"{parsed.scheme}:", parsed.netloc]
    for part in PurePosixPath(parsed.path).parts:
        if part in {"", "/", ".", ".."}:
            continue
        relative_parts.append(part)
    if len(relative_parts) <= 2 and not parsed.path.strip("/"):
        return None
    candidate = base_dir.joinpath(*relative_parts)
    if not candidate.exists():
        return None
    relative_candidate = candidate.relative_to(base_dir)
    return classify_secret_path(str(relative_candidate), cwd=cwd)


def _codex_path_token_is_url_path(text: str, start: int) -> bool:
    prefix = text[:start].lower()
    last_separator = max(prefix.rfind(separator) for separator in " \t\r\n'\"`<>|;(){}[]")
    token_prefix = prefix[last_separator + 1 :]
    if "://" in token_prefix:
        return True
    scheme = ""
    if token_prefix.endswith(":/"):
        scheme = token_prefix[:-2]
    elif token_prefix.endswith(":"):
        scheme = token_prefix[:-1]
    return _codex_token_prefix_is_url_scheme(scheme)


def _codex_token_prefix_is_url_scheme(scheme: str) -> bool:
    return bool(scheme) and scheme[0].isalpha() and all(char.isalnum() or char in "+.-" for char in scheme)


def _codex_command_may_read_local_content(command_text: str, *, cwd: Path | None) -> bool:
    if _codex_command_references_sensitive_local_source(command_text, cwd=cwd):
        return True
    if _codex_command_reads_environment_pipeline(command_text):
        return True
    if any(marker in command_text for marker in ("$(", "${", "`")):
        return True
    pipeline_segments = _split_codex_safe_read_only_pipeline(command_text)
    if pipeline_segments is not None:
        return any(
            _codex_pipeline_segment_may_read_local_content(segment, index=index, cwd=cwd)
            for index, segment in enumerate(pipeline_segments)
        )
    try:
        parts = _codex_shell_split(command_text)
    except ValueError:
        return True
    return _codex_command_parts_may_read_local_content(parts, cwd=cwd)


def _codex_pipeline_segment_may_read_local_content(segment: str, *, index: int, cwd: Path | None) -> bool:
    try:
        parts = _codex_shell_split(segment)
    except ValueError:
        return True
    if not parts:
        return False
    if index == 0:
        return _codex_command_parts_are_environment_dump(parts) or _codex_command_parts_may_read_local_content(
            parts,
            cwd=cwd,
        )
    return _codex_command_is_read_only_source_search(segment, cwd=cwd) or _codex_command_is_read_only_source_view(
        segment, cwd=cwd
    )


def _codex_command_parts_may_read_local_content(parts: list[str], *, cwd: Path | None) -> bool:
    for start in _codex_command_start_indexes(parts):
        previous_token = parts[start - 1] if start > 0 else None
        segment_parts = _codex_command_segment_parts(parts, start)
        if previous_token == "|":
            if _codex_command_sequence_is_read_only_source_inspection(segment_parts, cwd=cwd):
                return True
            continue
        if _codex_command_sequence_starts_with_local_reader(segment_parts, cwd=cwd):
            return True
    return False


def _codex_command_start_indexes(parts: list[str]) -> list[int]:
    starts = [0] if parts else []
    for index, part in enumerate(parts[:-1]):
        if part in {"&&", "||", ";", "&", "|", "|&"}:
            starts.append(index + 1)
    return starts


def _codex_command_segment_parts(parts: list[str], start: int) -> list[str]:
    end = start
    while end < len(parts) and parts[end] not in {"&&", "||", ";", "&", "|", "|&"}:
        end += 1
    return parts[start:end]


def _codex_command_sequence_is_read_only_source_inspection(parts: list[str], *, cwd: Path | None) -> bool:
    command_parts = _codex_unwrapped_command_parts(parts)
    if not command_parts:
        return False
    segment = shlex.join(command_parts)
    return _codex_command_is_read_only_source_search(segment, cwd=cwd) or _codex_command_is_read_only_source_view(
        segment, cwd=cwd
    )


def _codex_command_sequence_starts_with_local_reader(parts: list[str], *, cwd: Path | None) -> bool:
    command_parts = _codex_unwrapped_command_parts(parts)
    if not command_parts:
        return False
    if _codex_command_parts_are_git_grep(command_parts):
        return True
    return _codex_command_part_is_local_reader(command_parts, 0, cwd=cwd)


def _codex_command_parts_are_git_grep(parts: list[str]) -> bool:
    return bool(parts) and Path(parts[0]).name.lower() == "git" and _git_grep_search_args(parts[1:]) is not None


def _codex_command_reads_environment_pipeline(command_text: str) -> bool:
    try:
        parts = _codex_shell_split(command_text)
    except ValueError:
        return False
    if not parts:
        return False
    segment_starts = _codex_command_start_indexes(parts)
    if not segment_starts:
        return False
    first_segment = _codex_command_segment_parts(parts, segment_starts[0])
    if not _codex_command_parts_are_environment_dump(first_segment):
        return False
    saw_pipeline = False
    for start in segment_starts[1:]:
        separator = parts[start - 1]
        if separator != "|":
            return False
        saw_pipeline = True
    return saw_pipeline


def _codex_command_parts_are_environment_dump(parts: list[str]) -> bool:
    if not parts:
        return False
    executable = Path(parts[0]).name.lower()
    if executable == "printenv":
        return True
    if executable != "env":
        return False
    if _codex_env_args_clear_environment(parts[1:]):
        return False
    return not _codex_strip_env_wrapper(parts[1:])


def _codex_local_secret_source_label(
    matches: list[SecretPathMatch],
    *,
    command_text: str,
) -> str | None:
    families: list[str] = []
    for match in matches:
        if match.family not in families:
            families.append(match.family)
    if families:
        if len(families) == 1:
            return families[0]
        return f"{families[0]} and other local secret files"
    if _codex_command_reads_environment_pipeline(command_text):
        return "environment variables"
    return None


def _codex_tool_output_request_summary(
    *,
    tool_name: str,
    command_text: str,
    local_secret_source: str | None,
) -> str:
    if local_secret_source is not None:
        return f"Codex tool `{tool_name}` read local secrets from {local_secret_source} while running `{command_text}`."
    return f"Codex tool `{tool_name}` produced credential-looking output while running `{command_text}`."


def _codex_tool_output_runtime_summary(local_secret_source: str | None) -> str:
    if local_secret_source is not None:
        return f"Local secrets from {local_secret_source} reached Codex tool output."
    return "Requests a sensitive native tool action: credential-looking output reached Codex."


def _codex_unwrapped_command_parts(parts: list[str]) -> list[str]:
    remaining = parts
    while remaining:
        executable = Path(remaining[0]).name.lower()
        if executable == "command":
            remaining = _codex_strip_command_wrapper(remaining[1:])
            continue
        if executable == "env":
            remaining = _codex_strip_env_wrapper(remaining[1:])
            continue
        return remaining
    return []


def _codex_strip_command_wrapper(parts: list[str]) -> list[str]:
    index = 0
    while index < len(parts) and parts[index] in {"-p", "-v", "-V"}:
        index += 1
    if index < len(parts) and parts[index] == "--":
        index += 1
    return parts[index:]


def _codex_strip_env_wrapper(parts: list[str]) -> list[str]:
    index = 0
    while index < len(parts):
        part = parts[index]
        if part == "--":
            return parts[index + 1 :]
        if part in {"-i", "-0", "--ignore-environment", "--null"}:
            index += 1
            continue
        if part in {"-u", "--unset", "-C", "--chdir", "-S", "--split-string"}:
            index += 2
            continue
        if part.startswith(("--unset=", "--chdir=", "--split-string=")):
            index += 1
            continue
        if part.startswith("-"):
            index += 1
            continue
        if "=" in part and not part.startswith("="):
            index += 1
            continue
        return parts[index:]
    return []


def _codex_env_args_clear_environment(parts: list[str]) -> bool:
    saw_clear_environment = False
    for part in parts:
        if part == "--":
            return False
        if part in {"-i", "--ignore-environment"}:
            saw_clear_environment = True
            continue
        if part.startswith("-"):
            continue
        if "=" in part and not part.startswith("="):
            if _codex_env_assignment_uses_shell_expansion(part):
                return False
            continue
        return False
    return saw_clear_environment


def _codex_env_assignment_uses_shell_expansion(part: str) -> bool:
    _, _, value = part.partition("=")
    return "$" in value or "`" in value


def _codex_shell_split(command_text: str) -> list[str]:
    lexer = shlex.shlex(command_text, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    return list(lexer)


def _codex_command_part_is_local_reader(parts: list[str], index: int, *, cwd: Path | None) -> bool:
    local_read_commands = {"cat", "grep", "head", "rg", "sed", "tail"}
    executable = Path(parts[index]).name.lower()
    if executable not in local_read_commands:
        return False
    if index == 0:
        return True
    if parts[index - 1] == "|":
        segment = shlex.join(parts[index:])
        return _codex_command_is_read_only_source_search(segment, cwd=cwd) or _codex_command_is_read_only_source_view(
            segment, cwd=cwd
        )
    return parts[index - 1] in {"&&", "||", ";", "&", "|&"}


def _codex_post_tool_command_is_read_only_source_inspection(
    *,
    payload: dict[str, object],
    cwd: Path | None,
) -> bool:
    command_text = _codex_post_tool_command_text(payload)
    return bool(command_text) and _codex_command_is_read_only_source_inspection(command_text, cwd=cwd)


def _codex_post_tool_command_text(payload: dict[str, object]) -> str:
    tool_input = payload.get("tool_input")
    if isinstance(tool_input, dict):
        command = tool_input.get("command")
        if isinstance(command, str):
            return command.strip()
    return ""


_CODEX_READ_ONLY_SEARCH_COMMANDS = frozenset({"rg", "grep", "egrep", "fgrep"})
_CODEX_READ_ONLY_VIEW_COMMANDS = frozenset({"cat", "head", "tail", "sed"})
_CODEX_READ_ONLY_PIPE_FILTERS = frozenset({"head", "tail", "sed"})
_CODEX_READ_ONLY_SEARCH_WRAPPERS = frozenset({"bash", "sh", "zsh"})
_CODEX_SEARCH_PATTERN_VALUE_FLAGS = frozenset({"-e", "--regexp", "-f", "--file"})
_CODEX_SEARCH_OPTION_VALUE_FLAGS = frozenset(
    {
        *_CODEX_SEARCH_PATTERN_VALUE_FLAGS,
        "-g",
        "--glob",
        "--iglob",
        "--max-depth",
        "--type",
        "-t",
        "--type-not",
    }
)
_CODEX_SEARCH_OPTION_VALUE_FLAGS_BY_EXECUTABLE = {
    "rg": frozenset({"-T"}),
}
_CODEX_SEARCH_UNSAFE_FLAGS = frozenset({"--dereference-recursive", "--follow", "--pre"})
_CODEX_SEARCH_UNSAFE_SHORT_FLAGS_BY_EXECUTABLE = {
    "egrep": frozenset({"R"}),
    "fgrep": frozenset({"R"}),
    "grep": frozenset({"R"}),
    "rg": frozenset({"L"}),
}
_CODEX_GIT_GLOBAL_VALUE_FLAGS = frozenset(
    {"-c", "--config-env", "--exec-path", "--git-dir", "--work-tree", "--namespace"}
)
_CODEX_SOURCE_SEARCH_PREFIXES = tuple(f"{part}/" for part in sorted(SOURCE_INSPECTION_PARTS))
_CODEX_SOURCE_SEARCH_EXTENSIONS = SOURCE_INSPECTION_EXTENSIONS
_CODEX_BENIGN_SOURCE_DOTFILES = SOURCE_INSPECTION_BENIGN_DOTFILES
_CODEX_BENIGN_SECRET_FIXTURE_ASSIGNMENT_PATTERN = re.compile(
    r"""(?ix)
    \s*
    fake[_-]?(?:credential|secret|token)
    \s*[:=]\s*
    (?:
        "[^\r\n"]*"             # double-quoted value
        |'[^\r\n']*'            # single-quoted value
        |[^\s"',}]+             # unquoted token (excludes delimiters ,})
    )
    \s*"""
)
_CODEX_SENSITIVE_SEARCH_BASENAMES = SOURCE_INSPECTION_SENSITIVE_PARTS | frozenset({"id_rsa"})
_CODEX_GIT_DIFF_VALUE_OPTIONS = frozenset(
    {
        "--diff-filter",
        "--inter-hunk-context",
        "--line-prefix",
        "--output-indicator-context",
        "--output-indicator-new",
        "--output-indicator-old",
        "--src-prefix",
        "--dst-prefix",
        "--stat-width",
        "--stat-name-width",
        "--stat-graph-width",
        "--unified",
        "-G",
        "-S",
        "-U",
        "--word-diff-regex",
    }
)
_CODEX_GIT_DIFF_OPTIONAL_VALUE_OPTIONS = frozenset(
    {
        "--color",
        "--color-moved",
        "--find-copies",
        "--find-renames",
        "--ignore-submodules",
        "--submodule",
        "--word-diff",
    }
)
_CODEX_GIT_DIFF_BOOLEAN_OPTIONS = frozenset(
    {
        "--binary",
        "--cached",
        "--check",
        "--compact-summary",
        "--exit-code",
        "--find-copies-harder",
        "--full-index",
        "--ignore-all-space",
        "--ignore-blank-lines",
        "--ignore-cr-at-eol",
        "--ignore-space-at-eol",
        "--ignore-space-change",
        "--minimal",
        "--name-only",
        "--name-status",
        "--no-ext-diff",
        "--no-textconv",
        "--numstat",
        "--patch",
        "--patch-with-raw",
        "--pickaxe-all",
        "--pickaxe-regex",
        "--raw",
        "--relative",
        "--shortstat",
        "--stat",
        "--summary",
    }
)
_CODEX_GIT_DIFF_DISALLOWED_OPTIONS = frozenset({"--ext-diff", "--no-index", "--output", "--textconv"})
_CODEX_SAFE_GIT_GLOBAL_BOOLEAN_FLAGS = frozenset(
    {
        "--bare",
        "--glob-pathspecs",
        "--literal-pathspecs",
        "--no-literal-pathspecs",
        "--no-pager",
        "--noglob-pathspecs",
    }
)


@dataclass(frozen=True, slots=True)
class _CodexSedReadOnlyArgs:
    scripts: tuple[str, ...]
    targets: tuple[str, ...]
    saw_print_suppression: bool


def _codex_source_inspection_can_skip_secret_output(
    *,
    command_text: str,
    response_text: str,
    content_matches: tuple[SecretContentMatch, ...],
    cwd: Path | None,
) -> bool:
    if not _codex_command_is_read_only_source_inspection(command_text, cwd=cwd):
        return False
    if _codex_command_references_sensitive_local_source(command_text, cwd=cwd):
        return False
    if _codex_command_targets_secret_like_source_name(command_text):
        return False
    if any(match.sensitivity != "medium" for match in content_matches):
        return False
    if _codex_command_references_benign_source_dotfile(command_text):
        return _codex_output_is_only_benign_secret_fixture(response_text)
    return True


def _codex_output_is_only_benign_secret_fixture(response_text: str) -> bool:
    lines = [line for line in response_text.splitlines() if line.strip()]
    return bool(lines) and all(_CODEX_BENIGN_SECRET_FIXTURE_ASSIGNMENT_PATTERN.fullmatch(line) for line in lines)


def _codex_command_references_benign_source_dotfile(command_text: str) -> bool:
    try:
        parts = shlex.split(command_text)
    except ValueError:
        return False
    return any(Path(part).name.lower() in _CODEX_BENIGN_SOURCE_DOTFILES for part in parts)


def _codex_command_targets_secret_like_source_name(command_text: str) -> bool:
    dangerous_stems = {
        "auth",
        "credential",
        "credentials",
        "passwd",
        "password",
        "private-key",
        "private_key",
        "secret",
        "secrets",
        "token",
    }
    chained_segments = _split_codex_safe_read_only_chain(command_text)
    if chained_segments is not None:
        return any(_codex_command_targets_secret_like_source_name(segment) for segment in chained_segments)
    pipeline_segments = _split_codex_safe_read_only_pipeline(command_text)
    if pipeline_segments:
        return _codex_command_targets_secret_like_source_name(pipeline_segments[0])
    try:
        parts = shlex.split(command_text)
    except ValueError:
        return False
    for part in _codex_source_inspection_target_tokens(parts):
        stripped = part.strip().strip("'\"")
        if not stripped:
            continue
        name = Path(stripped).name.lower().lstrip(".")
        stem = Path(name).stem or name
        if stem in dangerous_stems or name.startswith("id_"):
            return True
    return False


def _codex_source_inspection_target_tokens(parts: list[str]) -> tuple[str, ...]:
    command_parts = _codex_unwrapped_command_parts(parts)
    if not command_parts:
        return ()
    executable = Path(command_parts[0]).name
    args = command_parts[1:]
    if executable in _CODEX_READ_ONLY_VIEW_COMMANDS:
        if executable == "sed":
            parsed = _parse_codex_sed_read_only_args(args)
            return parsed.targets if parsed is not None else ()
        if executable in {"head", "tail"}:
            targets, valid, skip_next = _parse_codex_head_tail_args(args)
            return tuple(targets) if valid and not skip_next else ()
        return tuple(_codex_cat_targets(args))
    if executable in _CODEX_READ_ONLY_SEARCH_COMMANDS:
        return _codex_search_targets(args, executable=executable)
    if executable == "git":
        git_grep_args = _git_grep_search_args(args)
        if git_grep_args is not None:
            return _codex_search_targets(git_grep_args, executable=executable)
    script_index = (
        _shell_wrapper_script_index(command_parts) if executable in _CODEX_READ_ONLY_SEARCH_WRAPPERS else None
    )
    if script_index is not None and script_index < len(command_parts):
        try:
            nested_parts = shlex.split(command_parts[script_index])
        except ValueError:
            return ()
        return _codex_source_inspection_target_tokens(nested_parts)
    return ()


def _codex_cat_targets(args: list[str]) -> list[str]:
    targets: list[str] = []
    after_option_terminator = False
    for arg in args:
        if after_option_terminator:
            targets.append(arg)
            continue
        if arg == "--":
            after_option_terminator = True
            continue
        if arg == "-" or arg.startswith("-"):
            continue
        targets.append(arg)
    return targets


def _codex_command_is_read_only_source_inspection(command_text: str, *, cwd: Path | None) -> bool:
    command = command_text.strip()
    if not command:
        return False
    if _codex_command_has_unquoted_glob_metachar(command):
        return False
    chained_segments = _split_codex_safe_read_only_chain(command)
    if chained_segments is not None:
        return all(_codex_command_is_read_only_source_inspection(segment, cwd=cwd) for segment in chained_segments)
    segments = _split_codex_safe_read_only_pipeline(command)
    if segments is None:
        return _codex_command_is_read_only_source_search(command, cwd=cwd) or _codex_command_is_read_only_source_view(
            command, cwd=cwd
        )
    if not segments:
        return False
    first_segment, *filter_segments = segments
    if not (
        _codex_command_is_read_only_source_search(first_segment, cwd=cwd)
        or _codex_command_is_read_only_source_view(first_segment, cwd=cwd)
    ):
        return False
    return all(_codex_command_is_bounded_read_only_filter(segment) for segment in filter_segments)


def _split_codex_safe_read_only_chain(command: str) -> list[str] | None:
    segments: list[str] = []
    start = 0
    quote: str | None = None
    escaped = False
    found_chain = False
    index = 0
    while index < len(command):
        char = command[index]
        if escaped:
            escaped = False
            index += 1
            continue
        if char == "\\":
            escaped = True
            index += 1
            continue
        if quote is not None:
            if char == quote:
                quote = None
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            index += 1
            continue
        if command.startswith("&&", index):
            segment = command[start:index].strip()
            if not segment:
                return None
            segments.append(segment)
            found_chain = True
            index += 2
            start = index
            continue
        if command.startswith("||", index) or char in {";", "&"}:
            return None
        index += 1
    if quote is not None or escaped or not found_chain:
        return None
    segment = command[start:].strip()
    if not segment:
        return None
    segments.append(segment)
    return segments if len(segments) > 1 else None


def _codex_command_has_unquoted_glob_metachar(command: str) -> bool:
    quote: str | None = None
    escaped = False
    for char in command:
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if quote is not None:
            if char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char in {"*", "?", "[", "]", "{", "}"}:
            return True
    return False


def _split_codex_safe_read_only_pipeline(command: str) -> list[str] | None:
    segments: list[str] = []
    current: list[str] = []
    quote: str | None = None
    escaped = False
    for char in command:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            current.append(char)
            escaped = True
            continue
        if quote is not None:
            current.append(char)
            if char == quote:
                quote = None
            elif quote == '"' and (char == "`" or char == "$"):
                return None
            continue
        if char in {"'", '"'}:
            current.append(char)
            quote = char
            continue
        if char in {"\n", "\r", "&", ";", "<", "`"}:
            return None
        if char == "$":
            return None
        if char == "|":
            segment = "".join(current).strip()
            if not segment:
                return None
            stripped_segment = _strip_codex_safe_stderr_discard(segment)
            if stripped_segment is None:
                return None
            segments.append(stripped_segment)
            current = []
            continue
        current.append(char)
    segment = "".join(current).strip()
    if not segments:
        return None
    if not segment:
        return None
    stripped_segment = _strip_codex_safe_stderr_discard(segment)
    if stripped_segment is None:
        return None
    segments.append(stripped_segment)
    return segments


def _strip_codex_safe_stderr_discard(segment: str) -> str | None:
    cleaned_segment = _remove_codex_safe_stderr_discard(segment)
    if cleaned_segment is None:
        return None
    try:
        parts = shlex.split(cleaned_segment)
    except ValueError:
        return None
    if not parts:
        return None
    if _codex_command_uses_untrusted_search_binary(parts[0]):
        return None
    return shlex.join(parts)


def _remove_codex_safe_stderr_discard(segment: str) -> str | None:
    cleaned: list[str] = []
    quote: str | None = None
    escaped = False
    index = 0
    while index < len(segment):
        char = segment[index]
        if escaped:
            cleaned.append(char)
            escaped = False
            index += 1
            continue
        if char == "\\":
            cleaned.append(char)
            escaped = True
            index += 1
            continue
        if quote is not None:
            cleaned.append(char)
            if char == quote:
                quote = None
            index += 1
            continue
        if char in {"'", '"'}:
            cleaned.append(char)
            quote = char
            index += 1
            continue
        if segment.startswith("2>", index):
            after_redirect = index + 2
            while after_redirect < len(segment) and segment[after_redirect].isspace():
                after_redirect += 1
            if segment.startswith("/dev/null", after_redirect):
                after_target = after_redirect + len("/dev/null")
                if after_target == len(segment) or segment[after_target].isspace():
                    index = after_target
                    continue
            return None
        if char == ">":
            return None
        cleaned.append(char)
        index += 1
    return "".join(cleaned).strip()


def _codex_command_is_bounded_read_only_filter(command_text: str) -> bool:
    try:
        parts = shlex.split(command_text)
    except ValueError:
        return False
    if not parts:
        return False
    if _codex_command_uses_untrusted_search_binary(parts[0]):
        return False
    executable = Path(parts[0]).name
    if executable not in _CODEX_READ_ONLY_PIPE_FILTERS:
        return False
    if executable == "sed":
        return _codex_sed_args_are_bounded_filter(parts[1:])
    return _codex_head_tail_args_are_bounded_filter(parts[1:])


def _codex_command_is_read_only_source_view(command_text: str, *, cwd: Path | None) -> bool:
    command = command_text.strip()
    if not command:
        return False
    if _codex_command_has_unquoted_shell_control(command):
        return False
    try:
        parts = shlex.split(command)
    except ValueError:
        return False
    if not parts:
        return False
    if _codex_command_uses_untrusted_search_binary(parts[0]):
        return False
    executable = Path(parts[0]).name
    if executable not in _CODEX_READ_ONLY_VIEW_COMMANDS:
        return executable == "git" and _codex_git_diff_targets_are_source_like(parts[1:], cwd=cwd)
    if executable == "sed":
        return _codex_sed_targets_are_read_only_source_like(parts[1:], cwd=cwd)
    if executable in {"head", "tail"}:
        return _codex_head_tail_targets_are_source_like(parts[1:], cwd=cwd)
    return _codex_cat_targets_are_source_like(parts[1:], cwd=cwd)


def _codex_command_is_read_only_source_search(command_text: str, *, cwd: Path | None) -> bool:
    command = command_text.strip()
    if not command:
        return False
    if _codex_command_has_unquoted_shell_control(command):
        return False
    try:
        parts = shlex.split(command)
    except ValueError:
        return False
    if not parts:
        return False
    if _codex_command_uses_untrusted_search_binary(parts[0]):
        return False
    executable = Path(parts[0]).name
    if executable in _CODEX_READ_ONLY_SEARCH_COMMANDS:
        if executable == "rg" and "--no-config" not in parts and os.environ.get("RIPGREP_CONFIG_PATH"):
            return False
        return _codex_search_targets_are_source_like(parts[1:], cwd=cwd, executable=executable)
    git_grep_args = _git_grep_search_args(parts[1:]) if executable == "git" else None
    if git_grep_args is not None:
        if _git_grep_uses_external_execution(git_grep_args):
            return False
        return _codex_search_targets_are_source_like(git_grep_args, cwd=cwd, executable=executable)
    script_index = _shell_wrapper_script_index(parts) if executable in _CODEX_READ_ONLY_SEARCH_WRAPPERS else None
    if script_index is not None and script_index < len(parts):
        return _codex_command_is_read_only_source_search(parts[script_index], cwd=cwd)
    return False


def _codex_command_uses_untrusted_search_binary(executable_token: str) -> bool:
    return executable_token.startswith(".") or "/" in executable_token or "\\" in executable_token


def _codex_cat_targets_are_source_like(args: list[str], *, cwd: Path | None) -> bool:
    targets: list[str] = []
    after_option_terminator = False
    for arg in args:
        if after_option_terminator:
            targets.append(arg)
            continue
        if arg == "--":
            after_option_terminator = True
            continue
        if arg == "-":
            return False
        if arg.startswith("-"):
            continue
        targets.append(arg)
    return bool(targets) and all(_codex_search_target_is_source_like(target, cwd=cwd) for target in targets)


def _codex_head_tail_args_are_bounded_filter(args: list[str]) -> bool:
    targets, valid, skip_next = _parse_codex_head_tail_args(args)
    return valid and not skip_next and not targets


def _codex_head_tail_targets_are_source_like(args: list[str], *, cwd: Path | None) -> bool:
    targets, valid, skip_next = _parse_codex_head_tail_args(args)
    return (
        valid
        and not skip_next
        and bool(targets)
        and all(_codex_search_target_is_source_like(target, cwd=cwd) for target in targets)
    )


def _parse_codex_head_tail_args(args: list[str]) -> tuple[list[str], bool, bool]:
    targets: list[str] = []
    skip_next = False
    after_option_terminator = False
    for arg in args:
        if skip_next:
            skip_next = False
            if not _codex_count_arg_is_bounded(arg):
                return [], False, False
            continue
        if after_option_terminator:
            targets.append(arg)
            continue
        if arg == "--":
            after_option_terminator = True
            continue
        if arg in {"-n", "--lines", "-c", "--bytes"}:
            skip_next = True
            continue
        if arg.startswith("--lines=") or arg.startswith("--bytes="):
            _, value = arg.split("=", 1)
            if not _codex_count_arg_is_bounded(value):
                return [], False, False
            continue
        if re.fullmatch(r"-\d{1,6}", arg):
            continue
        if arg == "-":
            return [], False, False
        if arg.startswith("-"):
            return [], False, False
        targets.append(arg)
    return targets, True, skip_next


def _codex_sed_targets_are_read_only_source_like(args: list[str], *, cwd: Path | None) -> bool:
    parsed = _parse_codex_sed_read_only_args(args)
    if parsed is None:
        return False
    return (
        bool(parsed.targets)
        and parsed.saw_print_suppression
        and all(sed_script_is_bounded_print(script) for script in parsed.scripts)
        and all(_codex_search_target_is_source_like(target, cwd=cwd) for target in parsed.targets)
    )


def _codex_sed_args_are_bounded_filter(args: list[str]) -> bool:
    parsed = _parse_codex_sed_read_only_args(args)
    if parsed is None:
        return False
    return (
        not parsed.targets
        and parsed.saw_print_suppression
        and all(sed_script_is_bounded_print(script) for script in parsed.scripts)
    )


def _parse_codex_sed_read_only_args(args: list[str]) -> _CodexSedReadOnlyArgs | None:
    scripts: list[str] = []
    targets: list[str] = []
    skip_next_script = False
    after_option_terminator = False
    saw_print_suppression = False
    for arg in args:
        if skip_next_script:
            skip_next_script = False
            scripts.append(arg)
            continue
        if after_option_terminator:
            targets.append(arg)
            continue
        if arg == "--":
            after_option_terminator = True
            continue
        if arg in {"-i", "--in-place"} or arg.startswith(("-i", "--in-place=")):
            return None
        if arg == "-n" or arg == "--quiet" or arg == "--silent":
            saw_print_suppression = True
            continue
        if arg == "-e" or arg == "--expression":
            skip_next_script = True
            continue
        if arg.startswith("-e") and len(arg) > 2:
            scripts.append(arg[2:])
            continue
        if arg.startswith("--expression="):
            _, script = arg.split("=", 1)
            scripts.append(script)
            continue
        if arg.startswith("-"):
            return None
        if not scripts:
            scripts.append(arg)
            continue
        targets.append(arg)
    if skip_next_script or not scripts:
        return None
    return _CodexSedReadOnlyArgs(
        scripts=tuple(scripts),
        targets=tuple(targets),
        saw_print_suppression=saw_print_suppression,
    )


def _codex_count_arg_is_bounded(value: str) -> bool:
    normalized = value.strip()
    return bool(re.fullmatch(r"\d{1,6}", normalized))


def _git_grep_search_args(args: list[str]) -> list[str] | None:
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "grep":
            return args[index + 1 :]
        if arg in _CODEX_GIT_GLOBAL_VALUE_FLAGS:
            index += 2
            continue
        if any(arg.startswith(f"{flag}=") for flag in _CODEX_GIT_GLOBAL_VALUE_FLAGS):
            index += 1
            continue
        if arg in _CODEX_SAFE_GIT_GLOBAL_BOOLEAN_FLAGS:
            index += 1
            continue
        return None
    return None


def _codex_git_diff_targets_are_source_like(args: list[str], *, cwd: Path | None) -> bool:
    diff_args = _git_diff_args(args)
    if diff_args is None:
        return False
    targets = _git_diff_path_args(diff_args)
    return (
        bool(targets)
        and all(_codex_search_target_is_source_like(target, cwd=cwd) for target in targets)
        and _git_diff_external_helpers_are_disabled_or_unconfigured(diff_args, cwd=cwd)
    )


def _git_diff_args(args: list[str]) -> list[str] | None:
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "diff":
            return args[index + 1 :]
        if arg in _CODEX_SAFE_GIT_GLOBAL_BOOLEAN_FLAGS:
            index += 1
            continue
        return None
    return None


def _git_diff_path_args(args: list[str]) -> list[str]:
    paths: list[str] = []
    index = 0
    after_path_separator = False
    while index < len(args):
        arg = args[index]
        if after_path_separator:
            paths.append(arg)
            index += 1
            continue
        if arg == "--":
            after_path_separator = True
            index += 1
            continue
        if arg in _CODEX_GIT_DIFF_DISALLOWED_OPTIONS or any(
            arg.startswith(f"{option}=") for option in _CODEX_GIT_DIFF_DISALLOWED_OPTIONS
        ):
            return []
        if arg in _CODEX_GIT_DIFF_OPTIONAL_VALUE_OPTIONS:
            index += 1
            continue
        if any(arg.startswith(f"{option}=") for option in _CODEX_GIT_DIFF_OPTIONAL_VALUE_OPTIONS):
            index += 1
            continue
        if arg in _CODEX_GIT_DIFF_VALUE_OPTIONS:
            if index + 1 >= len(args) or args[index + 1].startswith("-"):
                return []
            index += 2
            continue
        if any(arg.startswith(f"{option}=") for option in _CODEX_GIT_DIFF_VALUE_OPTIONS):
            index += 1
            continue
        if arg in _CODEX_GIT_DIFF_BOOLEAN_OPTIONS:
            index += 1
            continue
        if re.fullmatch(r"-U\d{1,6}", arg):
            index += 1
            continue
        if re.fullmatch(r"(?:-G|-S).+", arg):
            index += 1
            continue
        if arg.startswith("-"):
            return []
        return []
    return paths


def _git_diff_external_helpers_are_disabled_or_unconfigured(args: list[str], *, cwd: Path | None) -> bool:
    has_no_ext_diff = "--no-ext-diff" in args
    has_no_textconv = "--no-textconv" in args
    if has_no_ext_diff and has_no_textconv:
        return True
    return _git_repo_diff_helpers_are_unconfigured(cwd)


def _git_repo_diff_helpers_are_unconfigured(cwd: Path | None) -> bool:
    if cwd is None:
        return False
    if (
        os.environ.get("GIT_EXTERNAL_DIFF")
        or os.environ.get("GIT_CONFIG_COUNT")
        or os.environ.get("GIT_CONFIG_PARAMETERS")
    ):
        return False
    config_paths = _git_repo_config_paths(cwd)
    if not config_paths:
        return True
    repo_dir = _git_repo_root(cwd)
    seen_paths: set[Path] = set()
    for config_path in config_paths:
        if not _git_config_tree_disables_diff_helpers(config_path, seen_paths=seen_paths, repo_dir=repo_dir):
            return False
    return True


def _git_repo_config_paths(cwd: Path) -> tuple[Path, ...]:
    current = cwd.resolve()
    if current.is_file():
        current = current.parent
    for candidate in (current, *current.parents):
        git_path = candidate / ".git"
        if git_path.is_dir():
            return (*_git_global_config_paths(), git_path / "config", git_path / "config.worktree")
        if git_path.is_file():
            git_dir = _git_dir_from_file(git_path)
            if git_dir is None:
                return ()
            common_dir = _git_common_dir(git_dir)
            paths = [*_git_global_config_paths(), git_dir / "config", git_dir / "config.worktree"]
            if common_dir != git_dir:
                paths.extend([common_dir / "config", common_dir / "config.worktree"])
            return tuple(paths)
    return _git_global_config_paths()


def _git_repo_root(cwd: Path) -> Path | None:
    current = cwd.absolute()
    if current.is_file():
        current = current.parent
    for candidate in (current, *current.parents):
        if (candidate / ".git").exists():
            return candidate
    return None


def _git_global_config_paths() -> tuple[Path, ...]:
    paths: list[Path] = []
    system_config = os.environ.get("GIT_CONFIG_SYSTEM")
    if system_config:
        if system_config != os.devnull:
            paths.append(Path(system_config).expanduser())
    elif not os.environ.get("GIT_CONFIG_NOSYSTEM"):
        paths.append(Path("/etc/gitconfig"))
    global_config = os.environ.get("GIT_CONFIG_GLOBAL")
    if global_config:
        if global_config != os.devnull:
            paths.append(Path(global_config).expanduser())
    else:
        home = os.environ.get("HOME")
        if home:
            home_path = Path(home).expanduser()
            paths.append(home_path / ".gitconfig")
            xdg_config_home = Path(os.environ.get("XDG_CONFIG_HOME", str(home_path / ".config"))).expanduser()
            paths.append(xdg_config_home / "git" / "config")
    return tuple(paths)


def _git_dir_from_file(git_file: Path) -> Path | None:
    try:
        content = git_file.read_text(encoding="utf-8", errors="ignore").strip()
    except OSError:
        return None
    prefix = "gitdir:"
    if not content.lower().startswith(prefix):
        return None
    raw_path = content[len(prefix) :].strip()
    git_dir = Path(raw_path)
    if not git_dir.is_absolute():
        git_dir = (git_file.parent / git_dir).resolve()
    return git_dir


def _git_common_dir(git_dir: Path) -> Path:
    common_dir_file = git_dir / "commondir"
    if not common_dir_file.is_file():
        return git_dir
    try:
        raw_path = common_dir_file.read_text(encoding="utf-8", errors="ignore").strip()
    except OSError:
        return git_dir
    common_dir = Path(raw_path)
    if not common_dir.is_absolute():
        common_dir = (git_dir / common_dir).resolve()
    return common_dir


def _git_config_tree_disables_diff_helpers(config_path: Path, *, seen_paths: set[Path], repo_dir: Path | None) -> bool:
    normalized_path = config_path.expanduser().resolve()
    if normalized_path in seen_paths:
        return True
    seen_paths.add(normalized_path)
    if not normalized_path.is_file():
        return True
    try:
        config_text = normalized_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    if _git_config_enables_diff_helper(config_text):
        return False
    for included_path in _git_config_include_paths(
        config_text,
        allow_hasconfig=True,
        base_dir=normalized_path.parent,
        repo_dir=repo_dir,
    ):
        if not _git_config_tree_disables_diff_helpers(included_path, seen_paths=seen_paths, repo_dir=repo_dir):
            return False
    return True


def _git_config_include_paths(
    config_text: str,
    *,
    allow_hasconfig: bool,
    base_dir: Path,
    repo_dir: Path | None,
) -> tuple[Path, ...]:
    paths: list[Path] = []
    section = ""
    section_active = False
    for raw_line in _git_config_logical_lines(config_text):
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        section_match = re.fullmatch(r"\[([^\]]+)\](?:\s*[#;].*)?", line)
        if section_match:
            section = section_match.group(1).strip()
            section_active = _git_include_section_is_active(
                section,
                allow_hasconfig=allow_hasconfig,
                base_dir=base_dir,
                repo_dir=repo_dir,
            )
            continue
        if not section_active:
            continue
        key_match = re.match(r"(?i)^path\s*=\s*(.+)$", line)
        if key_match is None:
            continue
        include_path = Path(_git_config_value_without_inline_comment(key_match.group(1))).expanduser()
        if not include_path.is_absolute():
            include_path = (base_dir / include_path).resolve()
        paths.append(include_path)
    return tuple(paths)


def _git_include_section_is_active(
    section: str,
    *,
    allow_hasconfig: bool,
    base_dir: Path,
    repo_dir: Path | None,
) -> bool:
    section_lower = section.lower()
    if section_lower == "include":
        return True
    if not section_lower.startswith("includeif"):
        return False
    if repo_dir is None:
        return False
    condition_match = re.search(r'"([^"]+)"', section)
    condition = condition_match.group(1) if condition_match else section.removeprefix("includeif").strip()
    condition_lower = condition.lower()
    if condition_lower.startswith("gitdir/i:"):
        return _git_gitdir_condition_matches(
            condition[len("gitdir/i:") :],
            base_dir=base_dir,
            repo_dir=repo_dir,
            case_sensitive=False,
        )
    if condition_lower.startswith("gitdir:"):
        return _git_gitdir_condition_matches(
            condition[len("gitdir:") :],
            base_dir=base_dir,
            repo_dir=repo_dir,
            case_sensitive=True,
        )
    if condition_lower.startswith("onbranch:"):
        return _git_onbranch_condition_matches(condition[len("onbranch:") :], repo_dir=repo_dir)
    if allow_hasconfig and condition_lower.startswith("hasconfig:"):
        return _git_hasconfig_condition_matches(condition[len("hasconfig:") :], repo_dir=repo_dir)
    return False


def _git_gitdir_condition_matches(pattern: str, *, base_dir: Path, repo_dir: Path, case_sensitive: bool) -> bool:
    pattern_text = _git_gitdir_condition_pattern(pattern, base_dir=base_dir)
    patterns = _git_gitdir_condition_patterns(pattern_text)
    candidates = [_git_gitdir_condition_candidate(path) for path in _git_path_aliases(repo_dir)]
    git_dir = _git_effective_git_dir(repo_dir)
    if git_dir is not None:
        candidates.extend(_git_gitdir_condition_candidate(path) for path in _git_path_aliases(git_dir))
    if case_sensitive:
        return any(fnmatch.fnmatchcase(candidate, item) for candidate in candidates for item in patterns)
    return any(fnmatch.fnmatchcase(candidate.lower(), item.lower()) for candidate in candidates for item in patterns)


def _git_path_aliases(path: Path) -> tuple[Path, ...]:
    resolved = path.resolve()
    if resolved == path:
        return (path,)
    return (path, resolved)


def _git_gitdir_condition_candidate(path: Path) -> str:
    return path.as_posix().rstrip("/") + "/"


def _git_gitdir_condition_patterns(pattern_text: str) -> tuple[str, ...]:
    if pattern_text.endswith("/**"):
        return (pattern_text,)
    if pattern_text.endswith("/"):
        return (pattern_text, f"{pattern_text}**")
    return (pattern_text, f"{pattern_text}/", f"{pattern_text}/**")


def _git_gitdir_condition_pattern(pattern: str, *, base_dir: Path) -> str:
    expanded_pattern = pattern.strip()
    pattern_path = Path(expanded_pattern).expanduser()
    if pattern_path.is_absolute():
        return pattern_path.as_posix()
    if expanded_pattern.startswith(("./", "../")):
        return (base_dir / pattern_path).resolve().as_posix()
    return f"**/{expanded_pattern}"


def _git_effective_git_dir(repo_dir: Path) -> Path | None:
    git_path = repo_dir / ".git"
    if git_path.is_dir():
        return git_path
    if git_path.is_file():
        return _git_dir_from_file(git_path)
    return None


def _git_onbranch_condition_matches(pattern: str, *, repo_dir: Path) -> bool:
    git_dir = repo_dir / ".git"
    head_path: Path | None = None
    if git_dir.is_dir():
        head_path = git_dir / "HEAD"
    elif git_dir.is_file():
        parsed_git_dir = _git_dir_from_file(git_dir)
        if parsed_git_dir is not None:
            head_path = parsed_git_dir / "HEAD"
    if head_path is None or not head_path.is_file():
        return False
    try:
        head = head_path.read_text(encoding="utf-8", errors="ignore").strip()
    except OSError:
        return False
    prefix = "ref: refs/heads/"
    if not head.startswith(prefix):
        return False
    normalized_pattern = f"{pattern}**" if pattern.endswith("/") else pattern
    return fnmatch.fnmatchcase(head.removeprefix(prefix), normalized_pattern)


def _git_hasconfig_condition_matches(condition: str, *, repo_dir: Path) -> bool:
    key_pattern, _, value_pattern = condition.partition(":")
    if not key_pattern or not value_pattern:
        return False
    if key_pattern.lower() != "remote.*.url":
        return False
    seen_paths: set[Path] = set()
    for config_path in _git_repo_config_paths(repo_dir):
        if any(
            fnmatch.fnmatchcase(value, value_pattern)
            for value in _git_remote_urls_from_config_tree(config_path, seen_paths=seen_paths, repo_dir=repo_dir)
        ):
            return True
    return False


def _git_remote_urls_from_config_tree(config_path: Path, *, seen_paths: set[Path], repo_dir: Path) -> tuple[str, ...]:
    normalized_path = config_path.expanduser().resolve()
    if normalized_path in seen_paths:
        return ()
    seen_paths.add(normalized_path)
    if not normalized_path.is_file():
        return ()
    try:
        config_text = normalized_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ()
    urls = list(_git_remote_urls_from_config(config_text))
    for included_path in _git_config_include_paths(
        config_text,
        allow_hasconfig=False,
        base_dir=normalized_path.parent,
        repo_dir=repo_dir,
    ):
        urls.extend(_git_remote_urls_from_config_tree(included_path, seen_paths=seen_paths, repo_dir=repo_dir))
    return tuple(urls)


def _git_remote_urls_from_config(config_text: str) -> tuple[str, ...]:
    urls: list[str] = []
    in_remote_section = False
    for raw_line in _git_config_logical_lines(config_text):
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        section_match = re.fullmatch(r"\[([^\]]+)\](?:\s*[#;].*)?", line)
        if section_match:
            in_remote_section = section_match.group(1).strip().lower().startswith("remote ")
            continue
        if not in_remote_section:
            continue
        key_match = re.match(r"(?i)^url\s*=\s*(.+)$", line)
        if key_match is not None:
            urls.append(_git_config_value_without_inline_comment(key_match.group(1)))
    return tuple(urls)


def _git_config_value_without_inline_comment(raw_value: str) -> str:
    value = raw_value.strip()
    if not value:
        return value
    quote = value[0] if value[0] in {"'", '"'} else None
    if quote is not None:
        escaped = False
        parsed: list[str] = []
        for char in value[1:]:
            if escaped:
                parsed.append(char)
                escaped = False
                continue
            if char == "\\":
                escaped = True
                continue
            if char == quote:
                return "".join(parsed)
            parsed.append(char)
        return "".join(parsed)
    for index, char in enumerate(value):
        if char in {"#", ";"} and (index == 0 or value[index - 1].isspace()):
            return value[:index].strip()
    return value


def _git_config_enables_diff_helper(config_text: str) -> bool:
    return any(
        re.match(r"(?i)^\s*(?:command|external|textconv)\s*=", line) for line in _git_config_logical_lines(config_text)
    )


def _git_config_logical_lines(config_text: str) -> tuple[str, ...]:
    lines: list[str] = []
    pending = ""
    for raw_line in config_text.splitlines():
        line = raw_line.rstrip()
        if _git_config_line_continues(line):
            pending = f"{pending}{line[:-1]}"
            continue
        if pending:
            lines.append(f"{pending}{line.lstrip()}")
            pending = ""
            continue
        lines.append(line)
    if pending:
        lines.append(pending)
    return tuple(lines)


def _git_config_line_continues(line: str) -> bool:
    backslashes = 0
    for char in reversed(line):
        if char != "\\":
            break
        backslashes += 1
    return backslashes % 2 == 1


def _git_grep_uses_external_execution(args: list[str]) -> bool:
    return any(
        arg == "-O"
        or (arg.startswith("-O") and len(arg) > 2)
        or arg == "--open-files-in-pager"
        or arg.startswith("--open-files-in-pager=")
        or arg in {"--textconv", "--ext-grep"}
        for arg in args
    )


def _shell_wrapper_script_index(parts: list[str]) -> int | None:
    for index, arg in enumerate(parts[1:], start=1):
        if arg == "-c":
            return index + 1
        if arg.startswith("-") and not arg.startswith("--") and "c" in arg[1:]:
            return index + 1
    return None


def _codex_command_has_unquoted_shell_control(command: str) -> bool:
    quote: str | None = None
    escaped = False
    for char in command:
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if quote is not None:
            if char == quote:
                quote = None
            if quote == '"' and char == "`":
                return True
            if quote == '"' and char == "$":
                return True
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char in {"\n", "\r"}:
            return True
        if char in {"|", "&", ";", ">", "<", "`"}:
            return True
        if char == "$":
            return True
    return False


def _codex_search_targets_are_source_like(args: list[str], *, cwd: Path | None, executable: str) -> bool:
    targets = _codex_search_targets(args, executable=executable)
    if not targets:
        return False
    return bool(targets) and all(_codex_search_target_is_source_like(target, cwd=cwd) for target in targets)


def _codex_search_targets(args: list[str], *, executable: str) -> tuple[str, ...]:
    positional: list[str] = []
    skip_next = False
    pattern_from_option = False
    after_option_terminator = False
    option_value_flags = _CODEX_SEARCH_OPTION_VALUE_FLAGS | _CODEX_SEARCH_OPTION_VALUE_FLAGS_BY_EXECUTABLE.get(
        executable, frozenset()
    )
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if after_option_terminator:
            positional.append(arg)
            continue
        if arg == "--":
            after_option_terminator = True
            continue
        if _codex_search_arg_is_unsafe(arg, executable=executable, option_value_flags=option_value_flags):
            return ()
        if arg in _CODEX_SEARCH_PATTERN_VALUE_FLAGS:
            pattern_from_option = True
            skip_next = True
            continue
        if any(arg.startswith(flag) and len(arg) > len(flag) for flag in ("-e", "-f")):
            pattern_from_option = True
            continue
        if arg in option_value_flags:
            skip_next = True
            continue
        if any(arg.startswith(f"{flag}=") for flag in _CODEX_SEARCH_PATTERN_VALUE_FLAGS):
            pattern_from_option = True
            continue
        if any(arg.startswith(f"{flag}=") for flag in option_value_flags):
            continue
        if arg.startswith("-"):
            continue
        positional.append(arg)
    if pattern_from_option:
        return tuple(positional)
    if len(positional) >= 2:
        return tuple(positional[1:])
    return ()


def _codex_search_arg_is_unsafe(arg: str, *, executable: str, option_value_flags: frozenset[str]) -> bool:
    if arg in _CODEX_SEARCH_UNSAFE_FLAGS:
        return True
    if any(arg.startswith(f"{flag}=") for flag in _CODEX_SEARCH_UNSAFE_FLAGS):
        return True
    if not arg.startswith("-") or arg.startswith("--"):
        return False
    unsafe_short_flags = _CODEX_SEARCH_UNSAFE_SHORT_FLAGS_BY_EXECUTABLE.get(executable, frozenset())
    for flag in arg[1:]:
        if flag in unsafe_short_flags:
            return True
        if f"-{flag}" in option_value_flags:
            return False
    return False


def _codex_search_target_is_source_like(target: str, *, cwd: Path | None) -> bool:
    stripped = target.strip().strip("'\"")
    if not stripped:
        return False
    if stripped.startswith("~"):
        return False
    if any(char in stripped for char in ("*", "?", "{", "}")):
        return False
    target_path = Path(stripped)
    base_dir = (cwd or Path.cwd()).resolve()
    if target_path.is_absolute():
        unresolved_candidate = target_path
        try:
            candidate = unresolved_candidate.resolve(strict=False)
            relative_candidate = candidate.relative_to(base_dir)
        except (RuntimeError, ValueError):
            return False
        if _path_contains_symlink(candidate, base_dir=base_dir):
            return False
        parts = [part for part in relative_candidate.parts if part not in {"", "."}]
    else:
        unresolved_candidate = base_dir / target_path
        if _path_contains_symlink(unresolved_candidate, base_dir=base_dir):
            return False
        try:
            candidate = unresolved_candidate.resolve(strict=False)
        except RuntimeError:
            return False
        if candidate.exists():
            try:
                relative_candidate = candidate.relative_to(base_dir)
            except ValueError:
                return False
            parts = [part for part in relative_candidate.parts if part not in {"", "."}]
        else:
            parts = [part for part in target_path.parts if part not in {"", "."}]
    if not parts:
        return False
    lowered_parts = [part.lower() for part in parts]
    if any(part in _CODEX_SENSITIVE_SEARCH_BASENAMES for part in lowered_parts):
        return False
    hidden_parts = [part for part in lowered_parts if part.startswith(".")]
    if hidden_parts and not all(part in _CODEX_BENIGN_SOURCE_DOTFILES for part in hidden_parts):
        return False
    normalized = "/".join(parts)
    if normalized in {prefix.rstrip("/") for prefix in _CODEX_SOURCE_SEARCH_PREFIXES}:
        return True
    if any(normalized.startswith(prefix) for prefix in _CODEX_SOURCE_SEARCH_PREFIXES):
        return True
    if Path(stripped).name.lower() in _CODEX_BENIGN_SOURCE_DOTFILES:
        return True
    return Path(stripped).suffix.lower() in _CODEX_SOURCE_SEARCH_EXTENSIONS


def _codex_absolute_search_target_is_source_like(target_path: Path) -> bool:
    parts = [part for part in target_path.parts if part not in {"", "/", "."}]
    if not parts:
        return False
    lowered_parts = [part.lower() for part in parts]
    if any(part in _CODEX_SENSITIVE_SEARCH_BASENAMES for part in lowered_parts):
        return False
    hidden_parts = [part for part in lowered_parts if part.startswith(".")]
    if hidden_parts and not all(part in _CODEX_BENIGN_SOURCE_DOTFILES for part in hidden_parts):
        return False
    normalized = "/".join(parts)
    if any(f"/{prefix}" in f"/{normalized}" for prefix in _CODEX_SOURCE_SEARCH_PREFIXES):
        return True
    return target_path.suffix.lower() in _CODEX_SOURCE_SEARCH_EXTENSIONS


def _path_contains_symlink(path: Path, *, base_dir: Path) -> bool:
    candidate = base_dir
    try:
        relative_parts = path.relative_to(base_dir).parts
    except ValueError:
        return True
    for part in relative_parts:
        if part in {"", "."}:
            continue
        candidate /= part
        try:
            if candidate.is_symlink():
                return True
        except OSError:
            return True
    return False


def _collect_codex_tool_response_text(value: object, *, depth: int = 0) -> str:
    if depth > _CODEX_TOOL_RESPONSE_MAX_DEPTH:
        return ""
    if isinstance(value, str):
        return value[:_CODEX_TOOL_RESPONSE_TEXT_LIMIT]
    if isinstance(value, dict):
        parts: list[str] = []
        for key, child in value.items():
            key_text = str(key).lower()
            if key_text in {"stdout", "stderr", "output", "text", "content", "result", "message"} or depth > 0:
                text = _collect_codex_tool_response_text(child, depth=depth + 1)
                if text:
                    parts.append(text)
        return "\n".join(parts)[:_CODEX_TOOL_RESPONSE_TEXT_LIMIT]
    if isinstance(value, list):
        return "\n".join(_collect_codex_tool_response_text(item, depth=depth + 1) for item in value)[
            :_CODEX_TOOL_RESPONSE_TEXT_LIMIT
        ]
    return ""


_PROMPT_PATH_TOKEN_PATTERN = re.compile(
    r"(?<![\w/.-])\.[A-Za-z0-9][A-Za-z0-9_.-]{0,255}|"
    r"(?:~|\.{1,2}|/)[^\s'\"`<>|;(){}\[\]]{0,255}"
)
_PROMPT_FILE_READ_VERB_PATTERN = re.compile(r"\b(?:read|open|print|show|dump|cat|head|tail|less|view|display)\b", re.I)
_PROMPT_CONTENT_SCAN_MAX_BYTES = 64 * 1024
_PROMPT_CONTENT_SCAN_SKIP_BASENAMES = frozenset(
    {
        ".env",
        ".npmrc",
        ".pypirc",
        ".netrc",
        ".git-credentials",
    }
)
_PROMPT_CONTENT_SCAN_SECRET_BASENAME_MARKERS = frozenset(
    {
        "auth",
        "credential",
        "env",
        "key",
        "pass",
        "secret",
        "token",
    }
)


def _codex_prompt_credential_file_artifact(
    *,
    prompt_text: str,
    cwd: Path | None,
    config_path: str,
) -> GuardArtifact | None:
    if _PROMPT_FILE_READ_VERB_PATTERN.search(prompt_text) is None:
        return None
    for match in _PROMPT_PATH_TOKEN_PATTERN.finditer(prompt_text):
        requested_path = match.group(0)
        path = _resolve_prompt_scan_path(requested_path, cwd=cwd)
        if path is None or path.name in _PROMPT_CONTENT_SCAN_SKIP_BASENAMES:
            continue
        if not path.name.startswith("."):
            continue
        if not _prompt_path_looks_secret_bearing(path):
            continue
        if not path.is_file():
            continue
        try:
            with path.open("rb") as handle:
                content = handle.read(_PROMPT_CONTENT_SCAN_MAX_BYTES).decode("utf-8", errors="ignore")
        except OSError:
            continue
        if not classify_secret_content(content):
            continue
        normalized_path = str(path)
        fingerprint = hashlib.sha256(
            json.dumps(
                {
                    "harness": "codex",
                    "prompt_path": normalized_path,
                    "content_class": "credential-looking local file",
                },
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()[:_CODEX_PROMPT_FILE_FINGERPRINT_LENGTH]
        prompt_display = _codex_prompt_display_text(prompt_text, requested_path=requested_path)
        return GuardArtifact(
            artifact_id=f"codex:project:prompt-file:{fingerprint}",
            name=f"credential-looking local file {path.name}",
            harness="codex",
            artifact_type="prompt_request",
            source_scope="project",
            config_path=config_path,
            metadata={
                "prompt_signals": ["requested file content contains credential-looking material"],
                "prompt_summary": "Prompt asks Codex to read a credential-looking local file.",
                "prompt_matched_text": requested_path,
                "prompt_display_text": prompt_display,
                "prompt_request_class": "secret_read",
                "prompt_request_classes": ["secret_read"],
                "request_summary": prompt_display,
                "runtime_request_summary": prompt_display,
                "runtime_request_reason": (
                    "Guard scanned a small local dotfile before Codex read it and found credential-looking text."
                ),
                "normalized_path": normalized_path,
            },
        )
    return None


def _prompt_path_looks_secret_bearing(path: Path) -> bool:
    lowered_name = path.name.lower()
    return any(marker in lowered_name for marker in _PROMPT_CONTENT_SCAN_SECRET_BASENAME_MARKERS)


def _with_codex_prompt_display_metadata(artifact: GuardArtifact, *, prompt_text: str) -> GuardArtifact:
    matched_text = artifact.metadata.get("prompt_matched_text")
    display = _codex_prompt_display_text(
        prompt_text,
        requested_path=matched_text if isinstance(matched_text, str) else None,
    )
    metadata = {
        **artifact.metadata,
        "prompt_display_text": display,
        "request_summary": display,
        "runtime_request_summary": display,
    }
    return replace(artifact, metadata=metadata)


def _codex_prompt_display_text(prompt_text: str, *, requested_path: str | None = None) -> str:
    sanitized_prompt = _sanitize_codex_display_text(prompt_text)
    path_suffix = ""
    if requested_path is not None and requested_path.strip():
        path_suffix = f" for `{_sanitize_codex_display_text(requested_path.strip())}`"
    return f"Codex prompt{path_suffix}: {_truncate_codex_display_text(sanitized_prompt, limit=320)}"


def _sanitize_codex_display_text(value: str) -> str:
    collapsed = " ".join(value.strip().split())
    redacted = _redact_codex_prompt_secret_assignments(collapsed)
    sanitized = re.sub(r"/(?:Users|home)/[^/\s]+", "~", redacted)
    return re.sub(r"[A-Za-z]:\\Users\\[^\\\s]+", "~", sanitized)


def _redact_codex_prompt_secret_assignments(value: str) -> str:
    output: list[str] = []
    index = 0
    while index < len(value):
        equals_index = value.find("=", index)
        if equals_index == -1:
            output.append(value[index:])
            break
        key_start = equals_index - 1
        while key_start >= index and value[key_start] not in {" ", "\t", "\n", "\r", ",", ";"}:
            key_start -= 1
        key_start += 1
        key = value[key_start:equals_index].strip()
        key_upper = key.upper()
        if key and any(marker in key_upper for marker in _CODEX_PROMPT_SECRET_KEY_MARKERS):
            value_start = equals_index + 1
            while value_start < len(value) and value[value_start].isspace():
                value_start += 1
            value_end = value_start
            while value_end < len(value) and value[value_end] not in {" ", "\t", "\n", "\r", ",", ";"}:
                value_end += 1
            output.append(value[index:value_start])
            output.append("[redacted]")
            index = value_end
            continue
        output.append(value[index : equals_index + 1])
        index = equals_index + 1
    return "".join(output)


def _truncate_codex_display_text(value: str, *, limit: int) -> str:
    if len(value) <= limit:
        return value
    return f"{value[: limit - 1].rstrip()}…"


def _resolve_prompt_scan_path(requested_path: str, *, cwd: Path | None) -> Path | None:
    stripped = requested_path.strip().strip("'\"")
    if not stripped:
        return None
    exact_path = _expand_prompt_scan_path(stripped, cwd=cwd)
    if _prompt_scan_path_exists(exact_path):
        return exact_path
    normalized = stripped.rstrip(".,;:!?)]}")
    if not normalized or normalized == stripped:
        return exact_path
    return _expand_prompt_scan_path(normalized, cwd=cwd)


def _expand_prompt_scan_path(requested_path: str, *, cwd: Path | None) -> Path:
    try:
        expanded = Path(requested_path).expanduser()
    except RuntimeError:
        return Path(requested_path)
    if not expanded.is_absolute():
        expanded = (cwd or Path.cwd()) / expanded
    with suppress(OSError):
        return expanded.resolve(strict=False)
    return expanded


def _prompt_scan_path_exists(path: Path) -> bool:
    with suppress(OSError):
        return path.is_file()
    return False


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


def _guard_service_runtime_profile(
    store: GuardStore,
) -> dict[str, str] | None:
    payload = store.get_sync_payload(_SERVICE_RUNTIME_PROFILE_STATE_KEY)
    if not isinstance(payload, dict):
        return None
    runtime = _optional_string(payload.get("runtime"))
    label = _optional_string(payload.get("label"))
    surface = _optional_string(payload.get("surface"))
    client_name = _optional_string(payload.get("client_name"))
    client_title = _optional_string(payload.get("client_title"))
    client_version = _optional_string(payload.get("client_version"))
    if (
        runtime not in _SERVICE_RUNTIME_CHOICES
        or label is None
        or surface is None
        or client_name is None
        or client_title is None
        or client_version is None
    ):
        return None
    return {
        "runtime": runtime,
        "label": label,
        "workspace": _optional_string(payload.get("workspace")) or "",
        "surface": surface,
        "client_name": client_name,
        "client_title": client_title,
        "client_version": client_version,
    }


def _guard_service_login_payload(
    *,
    args: argparse.Namespace,
    store: GuardStore,
) -> tuple[dict[str, object], int]:
    now = _now()
    label = str(args.label).strip()
    workspace = _optional_string(args.workspace) or ""
    sync_url = str(args.sync_url).strip()
    token = str(args.token).strip()
    if not token:
        return {
            "logged_in": False,
            "error": "Hosted Guard runtime token cannot be empty.",
        }, 2
    runtime = str(args.runtime)
    service_profile = {
        "runtime": runtime,
        "label": label,
        "workspace": workspace,
        "surface": _SERVICE_RUNTIME_SURFACE,
        "client_name": "hol-guard",
        "client_title": label,
        "client_version": _GUARD_CLIENT_VERSION,
    }
    store.set_sync_credentials(sync_url, token, now, workspace_id=workspace or None)
    store.set_sync_payload(_SERVICE_RUNTIME_PROFILE_STATE_KEY, service_profile, now)
    device = store.set_device_label(label, now)
    store.add_event(
        "service_sign_in",
        {
            "runtime": runtime,
            "label": label,
            "workspace": workspace or None,
            "sync_url": sync_url,
            "source": "hosted-runtime-cli",
        },
        now,
    )
    return {
        "logged_in": True,
        "sync_url": sync_url,
        "service": service_profile,
        "device": device,
    }, 0


def _guard_service_sync_prerequisite_message() -> str:
    return (
        "Hosted Guard runtime is not configured yet. Run `hol-guard service login --runtime <runtime> "
        '--label "<label>" --sync-url "<url>" --token "<token>"` first.'
    )


def _guard_service_status_payload(store: GuardStore) -> dict[str, object]:
    credentials = store.get_sync_credentials()
    service_profile = _guard_service_runtime_profile(store)
    return {
        "configured": credentials is not None and service_profile is not None,
        "connection": {
            "configured": credentials is not None,
            "sync_url": credentials["sync_url"] if credentials is not None else None,
        },
        "service": service_profile,
        "runtime": store.get_sync_payload("runtime_session_summary") or {},
        "receipts": store.get_sync_payload("sync_summary") or {},
    }


def _guard_service_sync_payload(store: GuardStore) -> dict[str, object]:
    service_profile = _guard_service_runtime_profile(store)
    if service_profile is None:
        raise GuardSyncNotConfiguredError(_guard_service_sync_prerequisite_message())
    runtime_summary = sync_runtime_session(
        store,
        session={
            "harness": service_profile["runtime"],
            "surface": service_profile["surface"],
            "status": "active",
            "client_name": service_profile["client_name"],
            "client_title": service_profile["client_title"],
            "client_version": service_profile["client_version"],
            "workspace": service_profile["workspace"],
            "capabilities": ["hosted-runtime", "guard-cloud-sync"],
        },
    )
    receipts_summary = sync_receipts(store)
    store.add_event(
        "service_sync",
        {
            "runtime": service_profile["runtime"],
            "workspace": service_profile["workspace"] or None,
            "runtime_session_id": runtime_summary.get("runtime_session_id"),
            "synced_at": receipts_summary.get("synced_at"),
        },
        _now(),
    )
    return {
        "synced": True,
        "service": service_profile,
        "runtime": runtime_summary,
        "receipts": receipts_summary,
    }


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


def _handle_daemon_status(guard_home: Path, as_json: bool) -> int:
    from codex_plugin_scanner.version import __version__

    url = load_guard_daemon_url(guard_home)
    running = False
    port: int | None = None
    pid: int | None = None
    state_path = guard_home / "daemon-state.json"
    if state_path.is_file():
        import json as _json

        try:
            state = _json.loads(state_path.read_text())
            pid = state.get("pid") if isinstance(state, dict) else None
            port = state.get("port") if isinstance(state, dict) else None
            if (
                isinstance(pid, int)
                and pid > 0
                and _guard_daemon_pid_is_running(pid)
                and _guard_daemon_pid_matches_command(pid, expected_guard_home=guard_home)
            ):
                running = True
        except Exception:
            pass
    payload: dict[str, object] = {
        "running": running,
        "guard_home": str(guard_home),
        "version": __version__,
    }
    if port is not None:
        payload["port"] = port
    if pid is not None:
        payload["pid"] = pid
    if url is not None:
        payload["url"] = url
    _emit("daemon", payload, as_json)
    return 0


def _handle_daemon_repair(guard_home: Path, as_json: bool) -> int:
    result = repair_approval_center_locator(guard_home)
    _emit("daemon", result, as_json)
    return 0


def _handle_daemon_stop(guard_home: Path, as_json: bool) -> int:
    import json as _json
    import os
    import signal as _signal

    state_path = guard_home / "daemon-state.json"
    stopped = False
    pid: int | None = None
    if state_path.is_file():
        try:
            state = _json.loads(state_path.read_text())
            pid = state.get("pid") if isinstance(state, dict) else None
            if (
                isinstance(pid, int)
                and pid > 0
                and _guard_daemon_pid_is_running(pid)
                and _guard_daemon_pid_matches_command(pid, expected_guard_home=guard_home)
            ):
                os.kill(pid, _signal.SIGTERM)
                stopped = True
        except (ProcessLookupError, PermissionError, OSError, _json.JSONDecodeError, ValueError):
            pass
    from codex_plugin_scanner.guard.daemon.manager import clear_guard_daemon_state

    with suppress(OSError):
        clear_guard_daemon_state(guard_home)
    payload: dict[str, object] = {"stopped": stopped, "running": False}
    if pid is not None:
        payload["pid"] = pid
    _emit("daemon", payload, as_json)
    return 0
