"""``hol-guard browser``: explain a browser tool call, or report a review that should not have asked.

``explain``: the native runtime projects the call through the named driver profile, evaluates it
under the default policy and checks grant eligibility. Nothing is written, and no saved approval,
grant or setting is read.

``report-prompt``: the native runtime reads one stored approval and prints an anonymized case
skeleton for a public issue. Every argument value is a placeholder and every site is synthetic.
Nothing is written or sent.

This module only parses the arguments, sends one request and prints the answer.
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
    report = commands.add_parser(
        "report-prompt",
        help="Print an anonymized case skeleton for a browser review that should not have asked",
    )
    report.add_argument("request_id", help="The approval request id from the approval card")
    report.add_argument("--json", action="store_true", help="Print the native answer as JSON")
    report.add_argument("--home", help=argparse.SUPPRESS)
    report.add_argument("--guard-home", help=argparse.SUPPRESS)


def run_browser_command(
    args: argparse.Namespace,
    *,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
) -> int:
    stream = output_stream if output_stream is not None else sys.stdout
    errors = error_stream if error_stream is not None else sys.stderr
    as_json = bool(getattr(args, "json", False))
    report = getattr(args, "browser_command", None) == "report-prompt"
    try:
        result = _report_prompt(args) if report else _explain(args)
    except BrowserExplainError as exc:
        if as_json:
            print(json.dumps({"ok": False, "error": {"code": exc.code, "message": str(exc)}}), file=stream)
        else:
            print(f"{exc.code}: {exc}", file=errors)
        return 2
    if as_json:
        print(json.dumps(result, sort_keys=True), file=stream)
    elif report:
        _print_report(result, stream)
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
    if not isinstance(arguments, dict):
        raise BrowserExplainError("arguments_invalid", "--args must be a JSON object.")
    request = {"driver": str(args.driver).strip(), "tool": str(args.tool).strip(), "arguments": arguments}
    reply = _native_request(json.dumps(request, separators=(",", ":")))
    if reply.get("ok") is not True:
        error = _mapping(reply.get("error"))
        message = str(error.get("message") or "The call could not be explained.")
        drivers = reply.get("drivers")
        if isinstance(drivers, list) and drivers:
            message += " Shipped profiles: " + ", ".join(str(item) for item in drivers) + "."
        raise BrowserExplainError(str(error.get("code") or "browser_explain"), message)
    return {key: value for key, value in reply.items() if key != "ok"}


def _report_prompt(args: argparse.Namespace) -> dict[str, object]:
    from ..config import resolve_guard_home

    guard_home = resolve_guard_home(getattr(args, "guard_home", None) or getattr(args, "home", None))
    request = {"guard_home": str(guard_home), "request_id": str(args.request_id).strip()}
    reply = _native_request(json.dumps(request, separators=(",", ":")), command="browser-report-prompt")
    if reply.get("ok") is not True:
        error = _mapping(reply.get("error"))
        message = str(error.get("message") or "The approval could not be reported.")
        raise BrowserExplainError(str(error.get("code") or "browser_report_prompt"), message)
    return {key: value for key, value in reply.items() if key != "ok"}


def _native_request(line: str, *, command: str = "browser-explain") -> dict[str, object]:
    from ..native_runtime import _run_native_process, native_runtime_status

    status = native_runtime_status()
    if not status.available or not status.compatible or status.identity is None:
        raise BrowserExplainError("native_runtime_unavailable", "The HOL Guard native runtime is required.")
    output = _run_native_process(
        status.identity.path,
        (command, "--stdin"),
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


def _mapping(value: object) -> dict[str, object]:
    return {str(key): item for key, item in value.items()} if isinstance(value, dict) else {}


def _print(result: dict[str, object], stream: TextIO) -> None:
    driver = _mapping(result.get("driver"))
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
    decision = _mapping(result.get("decision"))
    print(f"Default decision: {decision.get('action')} ({decision.get('summaryCode')})", file=stream)
    risks = result.get("riskCategories")
    if isinstance(risks, list) and risks:
        print("Risk categories: " + ", ".join(str(risk) for risk in risks), file=stream)
    grant = _mapping(result.get("grant"))
    if grant.get("eligible") is True:
        print(f"A temporary browser grant can cover this call ({grant.get('category')}).", file=stream)
    else:
        print("No temporary browser grant can cover this call.", file=stream)
    print("Saved approvals, workspace rules and device settings can still change the outcome.", file=stream)


def _print_report(result: dict[str, object], stream: TextIO) -> None:
    print("Case skeleton for a browser review that should not have asked:", file=stream)
    print("", file=stream)
    print("```json", file=stream)
    print(json.dumps(result.get("skeleton"), indent=2, sort_keys=True), file=stream)
    print("```", file=stream)
    print("", file=stream)
    print(
        "Every argument value is a placeholder and every site is synthetic. Read it before you paste it"
        " into a public issue. Guard has not sent it anywhere.",
        file=stream,
    )
