"""Plugin Scanner CLI entry point."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .argparse_utils import FriendlyArgumentParser, should_default_to_scan_target
from .cli_ui import build_cli_epilog, build_plain_text, build_scan_help_epilog
from .reporting import format_json as format_json
from .version import __version__


def _guard_cli(name: str):
    # Deferred: importing the Guard CLI eagerly pulls the whole Guard command
    # surface through the package __init__, which short-lived invocations
    # must not pay for. The Guard package itself stays eager so spawned hook
    # workers see the same import order as the daemon.
    from .guard import cli as guard_cli_module

    return getattr(guard_cli_module, name)


def _supported_harness_values() -> tuple[str, ...]:
    # Deferred: product_model transitively imports the whole Guard command
    # surface, which short-lived invocations must not pay for.
    from .guard.product_model import SUPPORTED_HARNESS_VALUES

    return SUPPORTED_HARNESS_VALUES


def _run_scan(args: argparse.Namespace) -> int:
    from ._scanner_commands import run_scan

    return run_scan(args)


def _run_lint(args: argparse.Namespace) -> int:
    # Self-module lookup so the `cli.get_rule_spec` patch seam keeps working
    # while the rules module stays deferred for every non-lint invocation.
    import codex_plugin_scanner.cli as cli_module

    from ._scanner_commands import run_lint

    return run_lint(args, get_rule_spec_fn=cli_module.get_rule_spec)


def __getattr__(name: str):
    if name == "get_rule_spec":
        from .rules import get_rule_spec

        return get_rule_spec
    if name == "run_guard_command":
        from .guard.cli import run_guard_command

        return run_guard_command
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def _run_verify(args: argparse.Namespace) -> int:
    from ._scanner_commands import run_verify

    return run_verify(args)


def _run_submit(args: argparse.Namespace) -> int:
    from ._scanner_commands import run_submit

    return run_submit(args)


def _run_doctor(args: argparse.Namespace) -> int:
    from ._scanner_commands import run_doctor

    return run_doctor(args)


def _list_supported_ecosystems() -> list[str]:
    from .ecosystems.registry import list_supported_ecosystems

    return list(list_supported_ecosystems())


def format_text(result) -> str:
    return build_plain_text(result)


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


def _resolve_hol_guard_help_alias(program_name: str, argv: list[str]) -> list[str]:
    if not _is_hol_guard_program(program_name) or argv[:1] != ["help"]:
        return argv
    return [*argv[1:], "--help"]


def _build_parser(program_name: str, *, program_mode: str) -> argparse.ArgumentParser:
    if program_mode in {"guard", "hol-guard"}:
        parser = FriendlyArgumentParser(
            prog=program_name,
            description="Protect local harnesses before tools run.",
            epilog=build_cli_epilog(program_name, include_guard=False),
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
        _guard_cli("add_guard_root_parser")(parser)
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
        choices=("auto", *_list_supported_ecosystems(), "dsh", "deepseek_harness"),
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
        _guard_cli("add_guard_parser")(subparsers)

    return parser


def _is_hol_guard_program(program_name: str) -> bool:
    return Path(program_name).stem.lower() == "hol-guard"


def _resolve_hermes_args(argv: list[str]) -> list[str]:
    if argv[0] != "hermes":
        return argv
    if len(argv) == 1:
        return ["bootstrap", "hermes"]
    if argv[1] == "bootstrap":
        return ["bootstrap", "hermes", *argv[2:]]
    if argv[1] == "pretool":
        return ["hook", "--harness", "hermes", *argv[2:]]
    if argv[1] == "mcp-proxy":
        return ["hermes-mcp-proxy", *argv[2:]]
    return argv


def _resolve_legacy_args(
    argv: list[str] | None,
    *,
    program_mode: str,
    program_name: str = "",
) -> list[str] | None:
    if not argv:
        if program_mode == "hol-guard":
            return ["--help"]
        return argv
    if program_mode == "guard":
        if argv[0] == "guard":
            return argv[1:]
        return _resolve_hermes_args(argv)
    if program_mode == "hol-guard":
        return _resolve_hermes_args(argv)
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
        has_harness_arg = len(argv) >= 2 and not argv[1].startswith("-") and argv[1] in _supported_harness_values()
        if has_guard_doctor_flag or is_hol_guard_default_doctor or has_harness_arg:
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
        "mdm",
        "update",
        "uninstall",
        "package-shims",
        "run",
        "protect",
        "preflight",
        "pytest-contained",
        "diff",
        "test-eval",
        "command",
        "receipts",
        "history",
        "inventory",
        "abom",
        "approvals",
        "explain",
        "allow",
        "deny",
        "policies",
        "policy",
        "trust",
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
        *("device", "cloud-review"),
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
    if program_mode == "combined" and argv[0] in _guard_subcommands and ("--format" not in argv or argv[0] == "policy"):
        return ["guard", *argv]
    if not should_default_to_scan_target(argv[0], known_commands=known_commands):
        return argv
    return ["scan", *argv]


def _run_frozen_early_dispatch(requested_argv: list[str]) -> int | None:
    if not bool(getattr(sys, "frozen", False)):
        return None
    if requested_argv[:1] == ["__guard-bounded-hook"]:
        from .guard.adapters.bounded_cli_hook_bridge import main_from_argv

        return main_from_argv(requested_argv[1:])
    if requested_argv[:1] == ["__guard-cursor-hook"]:
        from .guard.adapters.cursor_hook_config import run_frozen_cursor_hook

        return run_frozen_cursor_hook(requested_argv[1:])
    from .guard.shims import resolve_frozen_package_shim_path, run_frozen_package_shim

    frozen_shim_path = resolve_frozen_package_shim_path(requested_argv)
    if frozen_shim_path is None:
        return None
    return run_frozen_package_shim(frozen_shim_path, requested_argv[1:])


def main(argv: list[str] | None = None) -> int:
    effective_argv = sys.argv[1:] if argv is None else argv
    if bool(getattr(sys, "frozen", False)) and effective_argv[:1] == ["__guard-bounded-hook"]:
        from .guard.adapters.bounded_cli_hook_bridge import main_from_argv

        return main_from_argv(effective_argv[1:])
    if bool(getattr(sys, "frozen", False)) and effective_argv[:1] == ["__guard-cursor-hook"]:
        from .guard.adapters.cursor_hook_config import run_frozen_cursor_hook

        return run_frozen_cursor_hook(effective_argv[1:])
    program_name = Path(sys.argv[0]).name or "plugin-scanner"
    requested_argv = sys.argv[1:] if argv is None else argv
    frozen_exit = _run_frozen_early_dispatch(requested_argv)
    if frozen_exit is not None:
        return frozen_exit
    requested_argv = _resolve_hol_guard_help_alias(program_name, requested_argv)
    if _is_hol_guard_program(program_name) and requested_argv and requested_argv[0] == "secrets":
        from .guard.secrets.cli import main as secrets_main

        return secrets_main(requested_argv[1:], program_name=f"{program_name} secrets")
    if _is_guard_program(program_name):
        program_mode = "guard"
    elif _is_hol_guard_program(program_name):
        program_mode = "hol-guard"
    elif _is_scanner_program(program_name) and (not requested_argv or requested_argv[0] != "guard"):
        program_mode = "scanner"
    else:
        program_mode = "combined"
    if program_mode == "guard" and requested_argv[:1] == ["help"]:
        requested_argv = [*requested_argv[1:], "--help"]
    if program_mode in {"guard", "hol-guard"} and requested_argv[:1] == ["--version"]:
        # Fast path: answering a version probe must not build the full Guard
        # command surface. Update flows spawn `--version` on every check, and
        # hook wrappers probe it while a tool waits.
        print(f"{program_name} {__version__}")
        return 0
    parser = _build_parser(program_name, program_mode=program_mode)
    resolved_argv = _resolve_legacy_args(
        requested_argv,
        program_mode=program_mode,
        program_name=program_name,
    )
    args = parser.parse_args(resolved_argv)
    # Surface silent stale-install shadowing before dispatching. Non-fatal.
    from .install_integrity import warn_if_shadowed

    warn_if_shadowed()
    if program_mode in {"guard", "hol-guard"}:
        try:
            import codex_plugin_scanner.cli as cli_module

            run_guard = getattr(cli_module, "run_guard_command", None) or _guard_cli("run_guard_command")
            return run_guard(args)
        except ValueError as exc:
            parser.error(str(exc))
        except Exception as exc:
            print(str(exc), file=sys.stderr)
            return 1
    if getattr(args, "list_ecosystems", False):
        for ecosystem in _list_supported_ecosystems():
            print(ecosystem)
        return 0
    if getattr(args, "diff_base", None):
        parser.error("--diff-base is not implemented yet. Remove the flag and rerun without diff-aware gating.")
    return _dispatch_scanner_command(args, parser)


def _dispatch_scanner_command(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
) -> int:
    if args.command in {None, "scan"}:
        return _run_scan(args)
    if args.command == "lint":
        return _run_lint(args)
    if args.command == "verify":
        return _run_verify(args)
    if args.command == "submit":
        return _run_submit(args)
    if args.command == "doctor":
        return _run_doctor(args)
    if args.command == "guard":
        try:
            return _guard_cli("run_guard_command")(args)
        except ValueError as exc:
            parser.error(str(exc))
        except Exception as exc:
            print(str(exc), file=sys.stderr)
            return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
