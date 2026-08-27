"""CLI for free local HOL Guard leaked-secret detection."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from .precommit import install_precommit_hook, uninstall_precommit_hook
from .public_rule_catalog import PUBLIC_RULES_JSON, PUBLIC_RULES_TEXT
from .secret_repository_scanner import (
    DEFAULT_MAX_COMMITS,
    DEFAULT_MAX_FILE_BYTES,
    DEFAULT_MAX_FILES,
    DEFAULT_MAX_FINDINGS,
    DEFAULT_MAX_TOTAL_BYTES,
    RepositorySecretScanResult,
    scan_repository_secrets,
)
from .secret_staged_scanner import scan_staged_secrets


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    return parsed


def build_parser(*, program_name: str = "hol-guard-secrets") -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=program_name,
        description="Find leaked credentials locally. Raw secret values are never printed or sent to Guard Cloud.",
    )
    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
        metavar="{scan,rules,install-hook,uninstall-hook}",
    )
    scan = subparsers.add_parser("scan", help="Scan the working tree, staged index, or bounded Git history")
    scan.add_argument("target", nargs="?", default=".")
    scope = scan.add_mutually_exclusive_group()
    scope.add_argument("--staged", action="store_true", help="Scan only content currently staged for commit")
    scope.add_argument("--history", action="store_true", help="Scan the working tree plus bounded Git history")
    scan.add_argument("--max-commits", type=_positive_int, default=DEFAULT_MAX_COMMITS)
    scan.add_argument("--max-files", type=_positive_int, default=DEFAULT_MAX_FILES)
    scan.add_argument("--max-file-bytes", type=_positive_int, default=DEFAULT_MAX_FILE_BYTES)
    scan.add_argument("--max-total-bytes", type=_positive_int, default=DEFAULT_MAX_TOTAL_BYTES)
    scan.add_argument("--max-findings", type=_positive_int, default=DEFAULT_MAX_FINDINGS)
    scan.add_argument("--fail-on-findings", action="store_true")
    scan.add_argument("--format", choices=("text", "json"), default="text")
    scan.add_argument("--json", action="store_true", help="Compatibility alias for --format json")

    rules = subparsers.add_parser("rules", help="List built-in detector families")
    rules.add_argument("--json", action="store_true")

    install_hook = subparsers.add_parser(
        "install-hook",
        help="Install a staged-secret pre-commit scan without overwriting an existing hook",
    )
    install_hook.add_argument("target", nargs="?", default=".")
    install_hook.add_argument("--json", action="store_true")

    uninstall_hook = subparsers.add_parser(
        "uninstall-hook",
        help="Remove the Guard-managed hook and restore any preserved user hook",
    )
    uninstall_hook.add_argument("target", nargs="?", default=".")
    uninstall_hook.add_argument("--json", action="store_true")
    return parser


def _write_scan(result: RepositorySecretScanResult, *, json_output: bool) -> None:
    public = result.to_public_dict()
    if json_output:
        print(json.dumps(public, sort_keys=True))
        return
    findings = result.findings
    print(
        f"HOL Guard Secrets: {len(findings)} finding(s), "
        f"{result.files_scanned} file version(s), "
        f"{result.commits_scanned} Git commit(s)."
    )
    for finding in findings:
        commit = f" @{finding.commit[:12]}" if finding.commit else ""
        print(
            f"- {finding.severity.upper()} {finding.family} at "
            f"{finding.path}:{finding.line}{commit} [{finding.confidence} confidence]"
        )
    if result.truncated:
        print(
            "Scan coverage is partial. Increase the configured bounds or resolve the "
            "reported Git error before treating it as clean."
        )
    for error in result.errors:
        print(f"Warning: {error}", file=sys.stderr)
    print("Raw secret values are intentionally omitted.")


def _run_scan(args: argparse.Namespace) -> int:
    target = Path(args.target)
    try:
        if bool(args.staged):
            result = scan_staged_secrets(
                target,
                max_files=args.max_files,
                max_file_bytes=args.max_file_bytes,
                max_total_bytes=args.max_total_bytes,
                max_findings=args.max_findings,
            )
        else:
            result = scan_repository_secrets(
                target,
                include_history=bool(args.history),
                max_commits=args.max_commits,
                max_files=args.max_files,
                max_file_bytes=args.max_file_bytes,
                max_total_bytes=args.max_total_bytes,
                max_findings=args.max_findings,
            )
    except (OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2
    _write_scan(result, json_output=bool(args.json) or args.format == "json")
    if result.truncated or result.errors:
        return 2
    return 3 if args.fail_on_findings and result.findings else 0


def _run_rules(args: argparse.Namespace) -> int:
    sys.stdout.write(PUBLIC_RULES_JSON if args.json else PUBLIC_RULES_TEXT)
    return 0


def _run_hook(args: argparse.Namespace, *, install: bool) -> int:
    try:
        result = install_precommit_hook(Path(args.target)) if install else uninstall_precommit_hook(Path(args.target))
    except (OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2
    payload = result.to_public_dict()
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        action = "installed" if install else "uninstalled"
        print(f"HOL Guard Secrets pre-commit hook {action}: {result.status} ({result.hook})")
        if result.chained_existing:
            print("Existing pre-commit behavior is preserved and chained before the staged secret scan.")
    return 0


def main(
    argv: Sequence[str] | None = None,
    *,
    program_name: str = "hol-guard-secrets",
) -> int:
    args = build_parser(program_name=program_name).parse_args(argv)
    if args.command == "scan":
        return _run_scan(args)
    if args.command == "rules":
        return _run_rules(args)
    if args.command == "install-hook":
        return _run_hook(args, install=True)
    if args.command == "uninstall-hook":
        return _run_hook(args, install=False)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
