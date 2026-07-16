"""Guard CLI parser policy and settings groups."""

# fmt: off
# ruff: noqa: F403, F405, I001

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ._commands_shared import _guard_risk_action_key


import argparse

from ._commands_shared import *
from .commands_parser_helpers import *

def _configure_guard_policy_parsers(
    guard_subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    policy_parser = guard_subparsers.add_parser(
        "policy",
        help="Validate, format, diff, export, or import canonical Guard policy YAML",
    )
    policy_subparsers = policy_parser.add_subparsers(dest="policy_command", required=True)

    policy_validate_parser = policy_subparsers.add_parser("validate", help="Validate a policy document")
    policy_validate_parser.add_argument("file")
    _add_guard_common_args(policy_validate_parser)
    policy_validate_parser.add_argument("--json", action="store_true")

    policy_fmt_parser = policy_subparsers.add_parser("fmt", help="Format a policy document canonically")
    policy_fmt_parser.add_argument("file")
    policy_fmt_parser.add_argument("--check", action="store_true")
    _add_guard_common_args(policy_fmt_parser)
    policy_fmt_parser.add_argument("--json", action="store_true")

    policy_diff_parser = policy_subparsers.add_parser(
        "diff", help="Diff a candidate document against active local policy"
    )
    policy_diff_parser.add_argument("file")
    _add_guard_common_args(policy_diff_parser)
    policy_diff_parser.add_argument("--json", action="store_true")

    policy_export_parser = policy_subparsers.add_parser("export", help="Export local policies")
    policy_export_parser.add_argument("--format", choices=("yaml",), default="yaml")
    policy_export_parser.add_argument("--output")
    policy_export_parser.add_argument("--include-provenance", action="store_true")
    _add_guard_common_args(policy_export_parser)
    policy_export_parser.add_argument("--json", action="store_true")

    policy_import_parser = policy_subparsers.add_parser("import", help="Import a policy document")
    policy_import_parser.add_argument("file")
    import_mode = policy_import_parser.add_mutually_exclusive_group(required=True)
    import_mode.add_argument("--merge", dest="mode", action="store_const", const="merge")
    import_mode.add_argument("--replace", dest="mode", action="store_const", const="replace")
    import_execution = policy_import_parser.add_mutually_exclusive_group()
    import_execution.add_argument("--dry-run", dest="dry_run", action="store_true", default=True)
    import_execution.add_argument("--apply", dest="dry_run", action="store_false")
    _add_guard_common_args(policy_import_parser)
    policy_import_parser.add_argument("--json", action="store_true")

    policies_parser = guard_subparsers.add_parser(
        "policies",
        help="List or clear remembered rules and synced Cloud policy rows",
    )
    policies_parser.add_argument(
        "policies_command",
        nargs="?",
        choices=("clear", "verify", "integrity-status", "repair", "migrate-local-integrity"),
    )
    policies_parser.add_argument("--harness")
    policies_parser.add_argument("--source")
    policies_parser.add_argument("--scope", choices=("artifact", "workspace", "publisher", "harness", "global"))
    policies_parser.add_argument("--artifact-id")
    policies_parser.add_argument("--artifact-hash")
    policies_parser.add_argument("--policy-workspace", dest="policy_workspace")
    policies_parser.add_argument("--publisher")
    policies_parser.add_argument(
        "--decision-id",
        dest="decision_ids",
        action="append",
        type=int,
        help=(
            "Policy decision ID to clear or preserve during migrate-local-integrity; "
            "repeat to target multiple rows"
        ),
    )
    policies_parser.add_argument(
        "--preserve-all-local",
        action="store_true",
        help="Preserve every local policy row eligible for re-signing during migrate-local-integrity",
    )
    policies_parser.add_argument(
        "--clear-unselected",
        action="store_true",
        help="Delete eligible local policy rows not preserved during migrate-local-integrity",
    )
    policies_parser.add_argument(
        "--clear-invalid",
        action="store_true",
        help="Delete invalid local policy rows during policies repair",
    )
    policies_parser.add_argument(
        "--all",
        action="store_true",
        help="Clear decisions across every harness; cannot be combined with --harness",
    )
    _add_guard_common_args(policies_parser)
    policies_parser.add_argument("--json", action="store_true")

    trust_parser = guard_subparsers.add_parser("trust", help="Inspect local trust without passive OS prompts")
    trust_parser.add_argument(
        "trust_command",
        nargs="?",
        default="status",
        choices=("status", "doctor", "test", "setup", "reset", "explain"),
    )
    trust_parser.add_argument(
        "--backend",
        choices=("auto", "degraded-safe", "macos-native"),
        default="auto",
        help="Local trust backend to inspect or set up.",
    )
    trust_parser.add_argument(
        "--no-ui",
        action="store_true",
        help="Run only bounded no-user-interaction checks.",
    )
    trust_parser.add_argument(
        "--rule",
        type=int,
        help="Explain one remembered rule or Cloud policy row by decision ID.",
    )
    _add_guard_common_args(trust_parser)
    trust_parser.add_argument("--json", action="store_true")

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
    approval_password_change_parser.add_argument("--current-password")
    approval_password_change_parser.add_argument("--new-password", required=True)
    approval_password_change_parser.add_argument("--confirm-password", required=True)
    approval_password_change_parser.add_argument("--totp-code")
    _add_guard_common_args(approval_password_change_parser)
    approval_password_change_parser.add_argument("--json", action="store_true")
    approval_password_disable_parser = approval_password_subparsers.add_parser(
        "disable",
        help="Disable the approval password gate",
    )
    approval_password_disable_parser.add_argument("--current-password")
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
        help="Disable TOTP with a fresh authenticator code",
    )
    approval_totp_disable_parser.add_argument("--current-password")
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
        "--repair",
        "--fix",
        action="store_true",
        help="Repair common local Guard issues such as stale package-manager shims",
    )
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

__all__ = [
    "_configure_guard_policy_parsers",
]
