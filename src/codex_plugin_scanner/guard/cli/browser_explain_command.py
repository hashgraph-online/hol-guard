"""``hol-guard browser explain``: show what Guard makes of one browser tool call.

The native runtime projects the call through the named driver profile, evaluates it under the
default policy and checks grant eligibility. This module only parses the arguments, sends one
request and prints the answer. Nothing is read from or written to the Guard home.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import TextIO

from ...argparse_utils import FriendlyArgumentParser

_MAX_ARGUMENTS_CHARS = 64 * 1024
_NATIVE_TIMEOUT_SECONDS = 30.0


class BrowserExplainError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def configure_guard_browser_parser(
    guard_subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    parser = guard_subparsers.add_parser("browser", help="Inspect how Guard classifies browser tool calls")
    commands = parser.add_subparsers(dest="browser_command", required=True, parser_class=FriendlyArgumentParser)
    explain = commands.add_parser(
        "explain",
        help="Show the browser action, default decision and grant eligibility for one tool call",
    )
    explain.add_argument("--driver", required=True, help="Driver profile id, for example browser.playwright-mcp")
    explain.add_argument("--tool", required=True, help="Tool name as the driver lists it")
    explain.add_argument("--args", dest="tool_arguments", default="{}", help="Tool arguments as a JSON object")
    explain.add_argument("--json", action="store_true", help="Print the native answer as JSON")


def run_browser_command(args: argparse.Namespace, *, output_stream: TextIO | None = None) -> int:
    stream = output_stream if output_stream is not None else sys.stdout
    as_json = bool(getattr(args, "json", False))
    try:
        result = _explain(args)
    except BrowserExplainError as exc:
        if as_json:
            print(json.dumps({"ok": False, "error": {"code": exc.code, "message": str(exc)}}), file=stream)
        else:
            print(f"{exc.code}: {exc}", file=sys.stderr)
        return 2
    if as_json:
        print(json.dumps(result, sort_keys=True), file=stream)
    else:
        _print(result, stream)
    return 0


def _explain(args: argparse.Namespace) -> dict[str, object]:
    raw = str(getattr(args, "tool_arguments", None) or "{}")
    if len(raw) > _MAX_ARGUMENTS_CHARS:
        raise BrowserExplainError("arguments_invalid", "--args is too long.")
    try:
        arguments = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise BrowserExplainError("arguments_invalid", "--args must be a JSON object.") from exc
    request = {"driver": str(args.driver).strip(), "tool": str(args.tool).strip(), "arguments": arguments}
    reply = _native_request(json.dumps(request, separators=(",", ":")))
    if reply.get("ok") is not True:
        error = reply.get("error") if isinstance(reply.get("error"), dict) else {}
        message = str(error.get("message") or "The call could not be explained.")
        drivers = reply.get("drivers")
        if isinstance(drivers, list) and drivers:
            message += " Shipped profiles: " + ", ".join(str(item) for item in drivers) + "."
        raise BrowserExplainError(str(error.get("code") or "browser_explain"), message)
    return {key: value for key, value in reply.items() if key != "ok"}


def _native_request(line: str) -> dict[str, object]:
    from ..native_runtime import _run_native_process, native_runtime_status

    status = native_runtime_status()
    if not status.available or not status.compatible or status.identity is None:
        raise BrowserExplainError("native_runtime_unavailable", "The HOL Guard native runtime is required.")
    output = _run_native_process(
        status.identity.path,
        ("browser-explain", "--stdin"),
        input_text=line,
        timeout_seconds=_NATIVE_TIMEOUT_SECONDS,
    )
    try:
        reply = json.loads(output or "")
    except json.JSONDecodeError as exc:
        raise BrowserExplainError("browser_explain", "The native runtime did not answer.") from exc
    if not isinstance(reply, dict):
        raise BrowserExplainError("browser_explain", "The native runtime returned an invalid answer.")
    return reply


def _print(result: dict[str, object], stream: TextIO) -> None:
    driver = result.get("driver") if isinstance(result.get("driver"), dict) else {}
    print(f"{result.get('tool')} on {driver.get('name')} ({driver.get('id')})", file=stream)
    action = result.get("action")
    if isinstance(action, dict):
        print(f"  intent: {action.get('intent')}", file=stream)
        print(f"  verb: {action.get('verb')}", file=stream)
        flags = action.get("sensitive_surface_flags")
        if isinstance(flags, list) and flags:
            print("  sensitive surfaces: " + ", ".join(str(flag) for flag in flags), file=stream)
    else:
        print(f"  unclassified: {result.get('unclassified')}", file=stream)
    decision = result.get("decision") if isinstance(result.get("decision"), dict) else {}
    print(f"Default decision: {decision.get('action')} ({decision.get('summaryCode')})", file=stream)
    risks = result.get("riskCategories")
    if isinstance(risks, list) and risks:
        print("Risk categories: " + ", ".join(str(risk) for risk in risks), file=stream)
    grant = result.get("grant") if isinstance(result.get("grant"), dict) else {}
    if grant.get("eligible") is True:
        print(f"A temporary browser grant can cover this call ({grant.get('category')}).", file=stream)
    else:
        print("No temporary browser grant can cover this call.", file=stream)
    print("Saved approvals, workspace rules and device settings can still change the outcome.", file=stream)
