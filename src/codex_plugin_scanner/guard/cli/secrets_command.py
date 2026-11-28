"""CLI glue for native Guard secret references and metadata."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from typing import TextIO

from ...argparse_utils import FriendlyArgumentParser

_NATIVE_TIMEOUT_SECONDS = 30.0


class SecretsCommandError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def configure_guard_secrets_parser(
    guard_subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    parser = guard_subparsers.add_parser("secrets", help="Manage guarded secret references")
    commands = parser.add_subparsers(
        dest="secrets_command",
        required=True,
        parser_class=FriendlyArgumentParser,
    )
    for command, help_text in (
        ("metadata", "Show metadata for a secret reference"),
        ("delete", "Delete a native secret reference"),
    ):
        child = commands.add_parser(command, help=help_text)
        child.add_argument("reference")
        child.add_argument("--json", action="store_true", help="Print the native response as JSON")

    set_command = commands.add_parser("set", help="Store a secret in the native secure store")
    set_command.add_argument("reference")
    set_command.add_argument(
        "--value-stdin",
        action="store_true",
        help="Read the value from standard input without echoing it",
    )
    set_command.add_argument("--json", action="store_true", help="Print the native response as JSON")

    execute = commands.add_parser("exec", help="Run one child with a bound secret sink")
    execute.add_argument("reference")
    execute.add_argument("program")
    execute.add_argument("args", nargs=argparse.REMAINDER)
    execute.add_argument("--sink", choices=("environment", "stdin", "file_descriptor"), required=True)
    execute.add_argument("--name", default="", help="Environment variable name for the environment sink")
    execute.add_argument("--approval-binding", required=True, help="Exact reviewed binding digest")
    execute.add_argument("--process-digest", required=True)
    execute.add_argument("--workspace-digest", required=True)
    execute.add_argument("--purpose", required=True)
    execute.add_argument("--policy-digest", required=True)
    execute.add_argument("--extension-digest", required=True)
    execute.add_argument("--version")
    execute.add_argument("--json", action="store_true", help="Print the native response as JSON")


def run_secrets_command(
    args: argparse.Namespace,
    *,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
) -> int:
    output = output_stream if output_stream is not None else sys.stdout
    errors = error_stream if error_stream is not None else sys.stderr
    as_json = bool(getattr(args, "json", False))
    request: dict[str, object] = {"command": str(args.secrets_command), "reference": str(args.reference)}
    try:
        if args.secrets_command == "set":
            result = _native_set_interactive(str(args.reference), from_stdin=bool(args.value_stdin))
        elif args.secrets_command == "exec":
            result = _native_exec_request(args)
        else:
            result = _native_request(request)
    except SecretsCommandError as error:
        if as_json:
            print(json.dumps({"ok": False, "error": {"code": error.code, "message": str(error)}}), file=output)
        else:
            print(f"{error.code}: {error}", file=errors)
        return 2
    if as_json:
        print(json.dumps(result, sort_keys=True), file=output)
    else:
        _print_result(result, output)
    return 0


def _native_exec_request(args: argparse.Namespace) -> dict[str, object]:
    broker: dict[str, object] = {
        "schema": "guard.secret-broker-request.v1",
        "operation": "materialize",
        "reference": str(args.reference),
        "capability": "secret.resolve",
        "sink": str(args.sink),
        "destination": str(args.name),
        "process_digest": str(args.process_digest),
        "workspace_digest": str(args.workspace_digest),
        "purpose": str(args.purpose),
        "policy_digest": str(args.policy_digest),
        "extension_digest": str(args.extension_digest),
    }
    if args.version:
        broker["version"] = str(args.version)
    request: dict[str, object] = {
        "broker": broker,
        "program": str(args.program),
        "args": [str(value) for value in args.args],
        "approval_binding": str(args.approval_binding),
    }
    return _native_request(request, command="secret-exec")


def _native_set_interactive(reference: str, *, from_stdin: bool) -> dict[str, object]:
    from ..native_runtime import native_runtime_status

    status = native_runtime_status()
    if not status.available or not status.compatible or status.identity is None:
        raise SecretsCommandError("native_runtime_unavailable", "The HOL Guard native runtime is required.")
    try:
        completed = subprocess.run(
            (
                str(status.identity.path),
                "secret-store",
                "--stdin-value" if from_stdin else "--prompt",
                reference,
            ),
            cwd=status.identity.path.parent,
            stdin=None,
            stdout=subprocess.PIPE,
            text=True,
            timeout=_NATIVE_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SecretsCommandError(
            "native_secret_store_unavailable", "The native secret operation could not run."
        ) from error
    try:
        result = json.loads(completed.stdout or "")
    except json.JSONDecodeError as error:
        raise SecretsCommandError("secret_store_invalid_response", "The native runtime did not answer.") from error
    if completed.returncode != 0 or not isinstance(result, dict) or result.get("ok") is not True:
        code = str(result.get("error") if isinstance(result, dict) else "secret_store_failed")
        raise SecretsCommandError(code, "The native secret operation was refused.")
    return result


def _native_request(request: dict[str, object], *, command: str = "secret-store") -> dict[str, object]:
    from ..native_runtime import _run_native_process, native_runtime_status

    status = native_runtime_status()
    if not status.available or not status.compatible or status.identity is None:
        raise SecretsCommandError("native_runtime_unavailable", "The HOL Guard native runtime is required.")
    output = _run_native_process(
        status.identity.path,
        (command, "--stdin"),
        input_text=json.dumps(request, separators=(",", ":")),
        timeout_seconds=_NATIVE_TIMEOUT_SECONDS,
    )
    try:
        result = json.loads(output or "")
    except json.JSONDecodeError as error:
        raise SecretsCommandError("secret_store_invalid_response", "The native runtime did not answer.") from error
    if not isinstance(result, dict):
        raise SecretsCommandError("secret_store_invalid_response", "The native runtime returned an invalid answer.")
    if result.get("ok") is not True:
        code = str(result.get("error") or "secret_store_failed")
        raise SecretsCommandError(code, "The native secret operation was refused.")
    return result


def _print_result(result: dict[str, object], output: TextIO) -> None:
    if "status" in result and "stdout" in result:
        print(f"Child exited with status {result.get('status')}.", file=output)
        if result.get("stdout"):
            print(result["stdout"], file=output, end="" if str(result["stdout"]).endswith("\n") else "\n")
        if result.get("stderr"):
            print(result["stderr"], file=output, end="" if str(result["stderr"]).endswith("\n") else "\n")
        return
    if result.get("deleted") is True:
        print(f"Deleted {result.get('reference')}.", file=output)
        return
    state = result.get("state") or "updated"
    print(f"{result.get('reference')}: {state}.", file=output)
