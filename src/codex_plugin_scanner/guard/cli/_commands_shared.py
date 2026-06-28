"""Guard CLI shared imports, constants, and helpers."""

# fmt: off
# ruff: noqa: F401

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import http.client
import importlib
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
    canonical_local_approval_url,
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
    _resolve_guard_sync_auth_context,
    apply_stored_package_policy_override,
    build_local_supply_chain_posture,
    build_supply_chain_explain_payload,
    build_supply_chain_status_payload,
    build_workspace_audit_payload,
    build_workspace_scan_payload,
    package_request_policy_hash,
    resolve_package_firewall_entitlement_with_refresh,
    sync_supply_chain_cloud_state,
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
    build_file_write_request_artifact,
    build_tool_action_request_artifact,
    extract_sensitive_file_read_request,
    extract_sensitive_file_read_request_from_action,
    extract_sensitive_file_write_request,
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
from .approval_gate_prompt import approval_gate_cli_payload, prompt_for_approval_gate
from .connect_flow import (
    CONNECT_SYNC_AUTH_CONTEXT_KEY,
    DEFAULT_GUARD_CONNECT_URL,
    DEFAULT_GUARD_SYNC_URL,
    build_connect_status_payload,
    connect_recovery_command,
    connect_state_requires_oauth,
    guard_api_base_path,
    normalize_connect_state_for_missing_oauth,
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
from .install_dry_run import build_managed_install_plan
from .protect_approvals import _queue_local_protect_approvals, _suppress_package_shim_allow_output
from .remote_pair_flow import dispatch_guard_remote_pair_command
from .uninstall_commands import run_guard_self_uninstall
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
_CODEX_BROWSER_APPROVAL_WAIT_MAX_SECONDS = 8
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
    "  uninstall    Disable Guard management or remove hol-guard entirely\n"
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
    for key in ("command", "cmd", "shell_command", "shellCommand", "pattern", "query", "search", "regex"):
        value = tool_input.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


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

def _load_lazy_export(module_name: str, attribute_name: str):
    return getattr(importlib.import_module(module_name, __package__), attribute_name)


GuardDaemonServer = _load_lazy_export("..daemon", "GuardDaemonServer")
ensure_guard_daemon = _load_lazy_export("..daemon", "ensure_guard_daemon")
load_guard_surface_daemon_client = _load_lazy_export("..daemon", "load_guard_surface_daemon_client")
repair_approval_center_locator = _load_lazy_export("..daemon", "repair_approval_center_locator")
CodexMcpGuardProxy = _load_lazy_export("..proxy", "CodexMcpGuardProxy")
CopilotMcpGuardProxy = _load_lazy_export("..proxy", "CopilotMcpGuardProxy")
CursorMcpGuardProxy = _load_lazy_export("..proxy", "CursorMcpGuardProxy")
OpenCodeMcpGuardProxy = _load_lazy_export("..proxy", "OpenCodeMcpGuardProxy")
RemoteGuardProxy = _load_lazy_export("..proxy", "RemoteGuardProxy")
StdioGuardProxy = _load_lazy_export("..proxy", "StdioGuardProxy")
add_approval_parser = _load_lazy_export(".approval_commands", "add_approval_parser")
run_approval_command = _load_lazy_export(".approval_commands", "run_approval_command")
run_approval_open_command = _load_lazy_export(".approval_commands", "run_approval_open_command")
run_approval_resume_command = _load_lazy_export(".approval_commands", "run_approval_resume_command")
run_approval_retry_hint_command = _load_lazy_export(".approval_commands", "run_approval_retry_hint_command")
DEFAULT_ALIAS_NAME = _load_lazy_export(".bootstrap", "DEFAULT_ALIAS_NAME")
build_guard_bootstrap_payload = _load_lazy_export(".bootstrap", "build_guard_bootstrap_payload")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _require_guard_store(store: GuardStore | None) -> GuardStore:
    if store is None:
        raise RuntimeError("Guard store is required")
    return store


def _require_guard_context(context: HarnessContext | None) -> HarnessContext:
    if context is None:
        raise RuntimeError("Guard context is required")
    return context


def _require_guard_config(config: GuardConfig | None) -> GuardConfig:
    if config is None:
        raise RuntimeError("Guard config is required")
    return config


__all__ = [name for name in globals() if not name.startswith("__")]
