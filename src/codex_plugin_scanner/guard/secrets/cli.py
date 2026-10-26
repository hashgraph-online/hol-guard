"""CLI for free local HOL Guard leaked-secret detection.

Detection, Git index and history reads, scan bounds and pre-commit hook
installation run in the native runtime's ``secrets-cli`` command. This module
parses arguments, sends one request and renders the public result.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
from collections.abc import Mapping, Sequence
from typing import Any

from .public_rule_catalog import PUBLIC_RULES_JSON, PUBLIC_RULES_TEXT

DEFAULT_MAX_FILES = 5_000
DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 128 * 1024 * 1024
DEFAULT_MAX_FINDINGS = 500
DEFAULT_MAX_COMMITS = 500

SECRETS_CLI_COMMAND = "secrets-cli"
SECRETS_CLI_FEATURE = "secrets-cli-v1"
# A bounded history scan reads up to 128 MiB through Git; the caller asked for
# it interactively, so the budget is generous rather than hook-sized.
_SECRETS_CLI_TIMEOUT_SECONDS = 3600.0
_SECRETS_CLI_OUTPUT_LIMIT_BYTES = 64 * 1024 * 1024
_NATIVE_UNAVAILABLE = "HOL Guard Secrets requires the Guard native runtime."
_NATIVE_FAILED = "HOL Guard Secrets native scan did not complete."


class SecretsNativeError(RuntimeError):
    """The native runtime was unavailable or returned no usable response."""


def _native_request(request: Mapping[str, object]) -> dict[str, Any]:
    """Run one ``secrets-cli`` request and return its ``{ok, result|error}`` reply."""

    from ..native_runtime import native_runtime_status

    status = native_runtime_status()
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or SECRETS_CLI_FEATURE not in status.capabilities.features
    ):
        raise SecretsNativeError(_NATIVE_UNAVAILABLE)
    runtime = status.identity.path
    # The scan runs the user's own Git against the user's repository, so it
    # keeps the caller's environment exactly as the Python scanner did.
    completed = _run_interruptibly(
        (str(runtime), SECRETS_CLI_COMMAND, "--stdin"),
        input_text=json.dumps(dict(request), sort_keys=True, separators=(",", ":")),
        cwd=runtime.parent,
        environment=dict(os.environ),
        timeout_seconds=_SECRETS_CLI_TIMEOUT_SECONDS,
        output_limit=_SECRETS_CLI_OUTPUT_LIMIT_BYTES,
    )
    if (
        completed.returncode != 0
        or completed.timed_out
        or completed.output_limit_exceeded
        or completed.containment_failed
    ):
        raise SecretsNativeError(_NATIVE_FAILED)
    try:
        response = json.loads(completed.stdout)
    except ValueError as error:
        raise SecretsNativeError(_NATIVE_FAILED) from error
    if not isinstance(response, dict) or not isinstance(response.get("ok"), bool):
        raise SecretsNativeError(_NATIVE_FAILED)
    return response


def _run_interruptibly(command: Sequence[str], **options: Any) -> Any:
    """Run the runtime on a worker thread so Ctrl-C stops it.

    The child runs in its own session and never receives the terminal's
    SIGINT. On interrupt the stop event ends it through the same containment
    path as the deadline before the interrupt propagates.
    """

    from ..codex_hook_launch_runtime import run_isolated_hook_process

    stop = threading.Event()
    done = threading.Event()
    outcome: list[Any] = []

    def run() -> None:
        try:
            outcome.append(run_isolated_hook_process(command, stop_event=stop, **options))
        except BaseException as error:  # re-raised on the calling thread
            outcome.append(error)
        finally:
            done.set()

    # An interrupted `Thread.join` can report the worker finished early, so
    # completion is tracked with an event.
    threading.Thread(target=run, name="hol-guard-secrets-cli", daemon=True).start()
    try:
        while not done.wait(0.2):
            pass
    except KeyboardInterrupt:
        stop.set()
        done.wait()
        raise
    result = outcome[0]
    if isinstance(result, BaseException):
        raise result
    return result


def _call(request: Mapping[str, object]) -> dict[str, Any] | None:
    """Return the native result, or print the error and return None."""

    try:
        response = _native_request(request)
    except SecretsNativeError as error:
        print(f"Error: {error}", file=sys.stderr)
        return None
    result = response.get("result")
    if response["ok"] is True and isinstance(result, dict):
        return result
    error = response.get("error")
    print(f"Error: {error if isinstance(error, str) and error else _NATIVE_FAILED}", file=sys.stderr)
    return None


def _target(value: str) -> str:
    # The native runtime runs from its own directory, so relative targets are
    # anchored to the caller's working directory here.
    return os.path.abspath(os.path.expanduser(value))


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


def _write_scan(result: Mapping[str, Any], *, json_output: bool) -> None:
    if json_output:
        print(json.dumps(result, sort_keys=True))
        return
    findings = result["findings"]
    print(
        f"HOL Guard Secrets: {len(findings)} finding(s), "
        f"{result['files_scanned']} file version(s), "
        f"{result['commits_scanned']} Git commit(s)."
    )
    for finding in findings:
        commit = f" @{finding['commit'][:12]}" if finding.get("commit") else ""
        print(
            f"- {finding['severity'].upper()} {finding['family']} at "
            f"{finding['path']}:{finding['line']}{commit} [{finding['confidence']} confidence]"
        )
    if result["truncated"]:
        print(
            "Scan coverage is partial. Increase the configured bounds or resolve the "
            "reported Git error before treating it as clean."
        )
    for error in result["errors"]:
        print(f"Warning: {error}", file=sys.stderr)
    print("Raw secret values are intentionally omitted.")


def _run_scan(args: argparse.Namespace) -> int:
    if args.staged:
        scope = "staged"
    elif args.history:
        scope = "history"
    else:
        scope = "working"
    request: dict[str, object] = {
        "command": "scan",
        "target": _target(args.target),
        "scope": scope,
        "max_files": args.max_files,
        "max_file_bytes": args.max_file_bytes,
        "max_total_bytes": args.max_total_bytes,
        "max_findings": args.max_findings,
    }
    if scope != "staged":
        request["max_commits"] = args.max_commits
    result = _call(request)
    if result is None:
        return 2
    _write_scan(result, json_output=bool(args.json) or args.format == "json")
    if result["truncated"] or result["errors"]:
        return 2
    return 3 if args.fail_on_findings and result["findings"] else 0


def _run_rules(args: argparse.Namespace) -> int:
    sys.stdout.write(PUBLIC_RULES_JSON if args.json else PUBLIC_RULES_TEXT)
    return 0


def _run_hook(args: argparse.Namespace, *, install: bool) -> int:
    command = "install-hook" if install else "uninstall-hook"
    payload = _call({"command": command, "target": _target(args.target)})
    if payload is None:
        return 2
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        action = "installed" if install else "uninstalled"
        print(f"HOL Guard Secrets pre-commit hook {action}: {payload['status']} ({payload['hook']})")
        if payload["chained_existing"]:
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
