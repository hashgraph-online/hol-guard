"""Plugin Scanner CLI entry point."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ._scanner_commands import run_doctor, run_lint, run_scan, run_submit, run_verify
from .argparse_utils import FriendlyArgumentParser, should_default_to_scan_target
from .cli_ui import build_cli_epilog, build_plain_text, build_scan_help_epilog
from .ecosystems.registry import list_supported_ecosystems
from .guard.cli import add_guard_parser, add_guard_root_parser, run_guard_command
from .reporting import format_json as render_json
from .rules import get_rule_spec
from .version import __version__


def format_text(result) -> str:
    return build_plain_text(result)


def format_json(
    result,
    *,
    profile: str = "default",
    policy_pass: bool = True,
    verify_pass: bool = True,
    raw_score: int | None = None,
    effective_score: int | None = None,
) -> str:
    return render_json(
        result,
        profile=profile,
        policy_pass=policy_pass,
        verify_pass=verify_pass,
        raw_score=raw_score,
        effective_score=effective_score,
    )


def _add_common_policy_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--profile", choices=("default", "public-marketplace", "strict-security"))
    parser.add_argument("--config", help="Path to a scanner config file such as .plugin-scanner.toml")
    parser.add_argument("--baseline", help="Path to baseline suppression file")
    parser.add_argument("--strict", action="store_true", help="Fail if any finding is present")
    parser.add_argument("--diff-base", help="Not implemented yet. Guard exits with an error if this flag is used.")


def _is_guard_program(program_name: str) -> bool:
    normalized_name = Path(program_name).stem.lower()
    return normalized_name in {"plugin-guard"}


def _is_scanner_program(program_name: str) -> bool:
    normalized_name = Path(program_name).stem.lower()
    return normalized_name in {"plugin-scanner", "plugin-ecosystem-scanner"}


def _build_parser(program_name: str, *, program_mode: str) -> argparse.ArgumentParser:
    if program_mode == "guard":
        parser = FriendlyArgumentParser(
            prog=program_name,
            description="Protect local harnesses before tools run.",
            epilog=build_cli_epilog(program_name, include_guard=False),
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
        add_guard_root_parser(parser)
        return parser

    description = "Scan plugin ecosystems for CI and publish readiness."
    if program_mode == "combined":
        description = "Run HOL Guard locally or scan plugin ecosystems for CI and publish readiness."

    parser = FriendlyArgumentParser(
        prog=program_name,
        description=description,
        epilog=build_cli_epilog(program_name, include_guard=program_mode == "combined"),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--list-ecosystems", action="store_true", help="List supported plugin ecosystems and exit")
    subparsers = parser.add_subparsers(dest="command", parser_class=FriendlyArgumentParser)

    scan_parser = subparsers.add_parser(
        "scan",
        help="Run full weighted scan",
        epilog=build_scan_help_epilog(program_name),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    scan_parser.add_argument("plugin_dir")
    scan_parser.add_argument("--json", action="store_true")
    scan_parser.add_argument("--format", choices=("text", "json", "markdown", "sarif"), default="text")
    scan_parser.add_argument("--output", "-o")
    _add_common_policy_args(scan_parser)
    scan_parser.add_argument("--min-score", type=int, default=0)
    scan_parser.add_argument(
        "--fail-on-severity",
        choices=("none", "critical", "high", "medium", "low", "info"),
        default="none",
    )
    scan_parser.add_argument(
        "--cisco-skill-scan",
        choices=("auto", "on", "off"),
        default="auto",
        help="Run Cisco skill scanning from the baseline install.",
    )
    scan_parser.add_argument(
        "--cisco-mcp-scan",
        choices=("auto", "on", "off"),
        default="auto",
        help="Run Cisco MCP static analysis. Requires the optional [cisco] extra on Python 3.11+.",
    )
    scan_parser.add_argument("--cisco-policy", choices=("permissive", "balanced", "strict"), default="balanced")
    scan_parser.add_argument(
        "--ecosystem",
        choices=("auto", "codex", "claude", "gemini", "opencode"),
        default="auto",
        help="Target one ecosystem explicitly or auto-detect all supported ecosystems.",
    )

    lint_parser = subparsers.add_parser("lint", help="Run rule-level lint evaluation")
    lint_parser.add_argument("plugin_dir", nargs="?", default=".")
    _add_common_policy_args(lint_parser)
    lint_parser.add_argument("--format", choices=("text", "json"), default="text")
    lint_parser.add_argument("--list-rules", action="store_true")
    lint_parser.add_argument("--explain")
    lint_parser.add_argument("--fix", action="store_true")

    verify_parser = subparsers.add_parser("verify", help="Run runtime verification checks")
    verify_parser.add_argument("plugin_dir", nargs="?", default=".")
    verify_parser.add_argument("--online", action="store_true")
    verify_parser.add_argument("--format", choices=("text", "json"), default="text")

    submit_parser = subparsers.add_parser("submit", help="Emit artifact after scan+verify+policy pass")
    submit_parser.add_argument("plugin_dir", nargs="?", default=".")
    submit_parser.add_argument("--profile", choices=("default", "public-marketplace", "strict-security"))
    submit_parser.add_argument("--config")
    submit_parser.add_argument("--baseline")
    submit_parser.add_argument("--attest", required=True)
    submit_parser.add_argument("--online", action="store_true")
    submit_parser.add_argument(
        "--min-score",
        type=int,
        default=None,
        help="Override the minimum score gate. Defaults to the selected policy profile minimum.",
    )

    doctor_parser = subparsers.add_parser("doctor", help="Emit component diagnostics")
    doctor_parser.add_argument("plugin_dir", nargs="?", default=".")
    doctor_parser.add_argument(
        "--component",
        choices=("all", "manifest", "marketplace", "mcp", "skills", "apps", "assets"),
        default="all",
    )
    doctor_parser.add_argument("--bundle")
    if program_mode == "combined":
        add_guard_parser(subparsers)

    return parser


def _is_hol_guard_program(program_name: str) -> bool:
    return Path(program_name).stem.lower() == "hol-guard"


def _resolve_legacy_args(
    argv: list[str] | None,
    *,
    program_mode: str,
    program_name: str = "",
) -> list[str] | None:
    if not argv:
        if program_mode == "combined" and _is_hol_guard_program(program_name):
            return ["guard"]
        return argv
    if program_mode == "guard":
        if argv[0] == "guard":
            return argv[1:]
        if argv[0] == "hermes":
            if len(argv) == 1:
                return ["bootstrap", "hermes"]
            if argv[1] == "bootstrap":
                return ["bootstrap", "hermes", *argv[2:]]
            if argv[1] == "pretool":
                return ["hook", "--harness", "hermes", *argv[2:]]
            if argv[1] == "mcp-proxy":
                return ["hermes-mcp-proxy", *argv[2:]]
        return argv
    if program_mode == "combined" and argv[0] == "hook":
        return ["guard", *argv]
    if program_mode == "combined" and argv[0] == "hermes":
        resolved_guard_args = _resolve_legacy_args(argv, program_mode="guard")
        if resolved_guard_args is None:
            return ["guard"]
        return ["guard", *resolved_guard_args]
    guard_doctor_flags = {
        "--fix",
        "--force-notification-settings",
        "--guard-home",
        "--harnesses",
        "--home",
        "--json",
        "--notifications",
        "--perf",
        "--repair",
        "--workspace",
    }
    if program_mode == "combined" and argv[0] == "doctor":
        has_guard_doctor_flag = any(arg in guard_doctor_flags for arg in argv[1:])
        is_hol_guard_default_doctor = _is_hol_guard_program(program_name) and (
            len(argv) == 1 or "-h" in argv[1:] or "--help" in argv[1:]
        )
        if has_guard_doctor_flag or is_hol_guard_default_doctor:
            return ["guard", *argv]
    known_commands = {
        "scan",
        "lint",
        "verify",
        "submit",
        "doctor",
        "--version",
        "--list-ecosystems",
        "-h",
        "--help",
    }
    if program_mode == "combined":
        known_commands.add("guard")
    if argv[0] in known_commands:
        return argv
    _guard_subcommands = {
        "start",
        "status",
        "dashboard",
        "init",
        "apps",
        "bootstrap",
        "detect",
        "install",
        "update",
        "uninstall",
        "package-shims",
        "run",
        "protect",
        "preflight",
        "diff",
        "receipts",
        "history",
        "inventory",
        "abom",
        "approvals",
        "explain",
        "allow",
        "deny",
        "policies",
        "settings",
        "exceptions",
        "advisories",
        "events",
        "doctor",
        "connect",
        "remote-pair",
        "disconnect",
        "login",
        "sync",
        "device",
        "bridge",
        "daemon",
        "hook",
        "admin",
        "cloud",
        "supply-chain",
        "service",
        "codex-mcp-proxy",
        "opencode-mcp-proxy",
        "copilot-mcp-proxy",
        "cursor-mcp-proxy",
        "hermes-mcp-proxy",
    }
    if program_mode == "combined" and argv[0] in _guard_subcommands and "--format" not in argv:
        return ["guard", *argv]
    if not should_default_to_scan_target(argv[0], known_commands=known_commands):
        return argv
    return ["scan", *argv]


def main(argv: list[str] | None = None) -> int:
    program_name = Path(sys.argv[0]).name or "plugin-scanner"
    if _is_guard_program(program_name):
        program_mode = "guard"
    elif _is_scanner_program(program_name):
        program_mode = "scanner"
    else:
        program_mode = "combined"
    parser = _build_parser(program_name, program_mode=program_mode)
    resolved_argv = _resolve_legacy_args(
        argv or sys.argv[1:],
        program_mode=program_mode,
        program_name=program_name,
    )
    args = parser.parse_args(resolved_argv)
    if getattr(args, "list_ecosystems", False):
        for ecosystem in list_supported_ecosystems():
            print(ecosystem)
        return 0
    if getattr(args, "diff_base", None):
        parser.error("--diff-base is not implemented yet. Remove the flag and rerun without diff-aware gating.")
    if args.command in {None, "scan"}:
        return run_scan(args)
    if args.command == "lint":
        return run_lint(args, get_rule_spec_fn=get_rule_spec)
    if args.command == "verify":
        return run_verify(args)
    if args.command == "submit":
        return run_submit(args)
    if args.command == "doctor":
        return run_doctor(args)
    if args.command == "guard":
        try:
            return run_guard_command(args)
        except ValueError as exc:
            parser.error(str(exc))
        except Exception as exc:
            print(str(exc), file=sys.stderr)
            return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
