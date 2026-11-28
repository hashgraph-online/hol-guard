"""``hol-guard integrations``: the conformance kit here, the provider routes in a sibling module.

``conformance`` runs the provider conformance kit on one manifest.

The native runtime reads the manifest, finds the provider's recorded responses and the benign gate
in the checkout that holds it (or the paths given), and runs the five checks. Nothing is written and
no provider is called. This module only parses the arguments, sends one request and prints the
answer.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import TextIO

from ...argparse_utils import FriendlyArgumentParser

_NATIVE_TIMEOUT_SECONDS = 60.0


class IntegrationsCommandError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def configure_guard_integrations_parser(
    guard_subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    from .integrations_providers_command import configure_provider_subcommands

    parser = guard_subparsers.add_parser("integrations", help="Connect, test and check provider integrations")
    commands = parser.add_subparsers(dest="integrations_command", required=True, parser_class=FriendlyArgumentParser)
    conformance = commands.add_parser(
        "conformance",
        help="Run the provider conformance checks on a manifest and its recorded responses",
    )
    conformance.add_argument("manifest", help="Path to the provider integration manifest")
    conformance.add_argument(
        "--recordings",
        help="Recorded responses (default: tests/fixtures/provider_integrations/<slug>/recordings.json)",
    )
    conformance.add_argument(
        "--gate", help="Benign gate file (default: tests/fixtures/benign_false_positive_gate.json)"
    )
    conformance.add_argument("--json", action="store_true", help="Print the native answer as JSON")
    configure_provider_subcommands(commands)


def run_integrations_command(
    args: argparse.Namespace,
    *,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
) -> int:
    stream = output_stream if output_stream is not None else sys.stdout
    errors = error_stream if error_stream is not None else sys.stderr
    if getattr(args, "integrations_command", None) != "conformance":
        from .integrations_providers_command import run_provider_command

        return run_provider_command(args, output_stream=stream, error_stream=errors)
    as_json = bool(getattr(args, "json", False))
    try:
        result = _conformance(args)
    except IntegrationsCommandError as exc:
        if as_json:
            print(json.dumps({"ok": False, "error": {"code": exc.code, "message": str(exc)}}), file=stream)
        else:
            print(f"{exc.code}: {exc}", file=errors)
        return 2
    if as_json:
        print(json.dumps(result, sort_keys=True), file=stream)
    else:
        _print(result, stream)
    return 0 if result.get("passed") is True else 1


def _absolute(value: object) -> str | None:
    return None if value is None else str(Path(str(value)).expanduser().absolute())


def _conformance(args: argparse.Namespace) -> dict[str, object]:
    request: dict[str, object] = {"manifest": _absolute(args.manifest)}
    for key in ("recordings", "gate"):
        path = _absolute(getattr(args, key, None))
        if path is not None:
            request[key] = path
    reply = _native_request(json.dumps(request, separators=(",", ":")))
    if reply.get("ok") is not True:
        error = reply.get("error")
        error = error if isinstance(error, dict) else {}
        message = str(error.get("message") or "The conformance checks could not run.")
        raise IntegrationsCommandError(str(error.get("code") or "provider_conformance"), message)
    return {key: value for key, value in reply.items() if key != "ok"}


def _native_request(line: str) -> dict[str, object]:
    from ..native_runtime import _run_native_process, native_runtime_status

    status = native_runtime_status()
    if not status.available or not status.compatible or status.identity is None:
        raise IntegrationsCommandError("native_runtime_unavailable", "The HOL Guard native runtime is required.")
    output = _run_native_process(
        status.identity.path,
        ("provider-conformance", "--stdin"),
        input_text=line,
        timeout_seconds=_NATIVE_TIMEOUT_SECONDS,
    )
    try:
        reply = json.loads(output or "")
    except json.JSONDecodeError as exc:
        raise IntegrationsCommandError("provider_conformance", "The native runtime did not answer.") from exc
    if not isinstance(reply, dict):
        raise IntegrationsCommandError("provider_conformance", "The native runtime returned an invalid answer.")
    return reply


def _print(result: dict[str, object], stream: TextIO) -> None:
    provider = result.get("provider_id") or "The manifest"
    verdict = "passes" if result.get("passed") is True else "fails"
    print(
        f"{provider} {verdict} conformance "
        f"({result.get('recordings')} recordings, {result.get('corpus_rows')} benign browser rows).",
        file=stream,
    )
    checks = result.get("checks")
    for check in checks if isinstance(checks, list) else []:
        if not isinstance(check, dict):
            continue
        mark = "pass" if check.get("passed") is True else "FAIL"
        print(f"  {mark}  {check.get('id')}", file=stream)
        problems = check.get("problems")
        for problem in problems if isinstance(problems, list) else []:
            print(f"        {problem}", file=stream)
