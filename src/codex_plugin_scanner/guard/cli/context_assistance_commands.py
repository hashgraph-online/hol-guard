"""Arguments and rendering for the native optional context service."""

from __future__ import annotations

import argparse
import json
import sys
from typing import TextIO

from ...argparse_utils import FriendlyArgumentParser


def configure_context_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser("context", help="Inspect and control optional local CIGAR context assistance")
    parser.add_argument("--guard-home")
    parser.add_argument("--json", action="store_true")
    actions = parser.add_subparsers(dest="context_command", required=True, parser_class=FriendlyArgumentParser)
    for name, kind, help_text in (
        ("status", "status", "Show requested and verified runtime availability without probing CIGAR"),
        ("runtimes", "installations", "Show the built-in engine without launching CIGAR"),
        ("check", "recheck", "Schedule verification of the saved runtime in the background"),
        ("start", "activate", "Start the saved, explicitly enabled runtime after native verification"),
        ("off", "stop", "Cancel context work and persist opt-out; retain Guard approvals"),
    ):
        action = actions.add_parser(name, help=help_text)
        action.set_defaults(context_kind=kind)
        action.add_argument("--guard-home", default=argparse.SUPPRESS)
        action.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    from .context_usage_commands import configure as configure_usage

    configure_usage(actions)

    lean = actions.add_parser(
        "lean",
        help="Pick when Codex sums up older turns in a long session (on --limit N, off or status)",
        description=(
            "Sets Codex's model_auto_compact_token_limit to the size you pick. A smaller chat is not a "
            "cheaper one: after each summary Codex reads again, at full price, the files it had already "
            "read, so this can raise the bill. Guard sets no size of its own."
        ),
    )
    lean.set_defaults(context_kind="lean")
    lean.add_argument("lean_action", nargs="?", choices=("on", "off", "status"), default="status")
    lean.add_argument(
        "--limit",
        type=int,
        default=None,
        help="with on: sum up once a session passes this many tokens (10,000 to 10,000,000)",
    )
    lean.add_argument("--guard-home", default=argparse.SUPPRESS)
    lean.add_argument("--json", action="store_true", default=argparse.SUPPRESS)

    from .context_assistance_versions_commands import configure

    configure(actions)


def run_context_command(
    args: argparse.Namespace,
    *,
    input_text: str | None = None,
    output_stream: TextIO | None = None,
) -> int:
    from ..config import resolve_guard_home
    from ..native_context_assistance import ContextAssistanceError, control

    output = output_stream if output_stream is not None else sys.stdout
    if args.context_kind == "lean":
        return _run_lean(args, output)
    if args.context_kind == "usage":
        from .context_usage_commands import run

        return run(args, output)
    try:
        home = resolve_guard_home(args.guard_home)
        if args.context_kind == "versions":
            from .context_assistance_versions_commands import execute

            state = execute(args, home)
        else:
            state = control(args.context_kind, guard_home=home)
    except ContextAssistanceError as error:
        if args.json:
            print(
                json.dumps({"schema": "guard-context-assistance-cli.v1", "status": "unavailable", "code": error.code}),
                file=output,
            )
        else:
            print(f"Context assistance unavailable ({error.code}). Guard protection remains available.", file=output)
        return 1
    except (OSError, RuntimeError, ValueError):
        if args.json:
            print(
                json.dumps(
                    {
                        "schema": "guard-context-assistance-cli.v1",
                        "status": "unavailable",
                        "code": "native_context_assistance_home_unavailable",
                    }
                ),
                file=output,
            )
        else:
            print(
                "The local Guard context service could not be reached. Check this installation's Guard home.",
                file=output,
            )
        return 1
    if args.json:
        print(json.dumps(state, sort_keys=True), file=output)
        return 0
    if args.context_kind == "versions":
        from .context_assistance_versions_commands import render

        render(state, output)
        return 0
    print(f"CIGAR context assistance: {state['availability']}", file=output)
    print(f"Requested: {state['requested_enabled']} · Active: {state['effective_enabled']}", file=output)
    if state["job"]:
        print(f"Background operation: {state['job']['operation']} ({state['job']['phase']})", file=output)
    if state["diagnostic"]:
        print(f"Diagnostic: {state['diagnostic']}", file=output)
    if state["installation_options"] is not None:
        builtin = [option for option in state["installation_options"] if option["qualification"] == "guard_builtin"]
        for option in builtin:
            print(
                f"  {option['runtime_id']}: Built into Guard · {option['platform']} · {option['qualification']}",
                file=output,
            )
        if not builtin:
            print("The built-in engine is unavailable on this machine.", file=output)
    print(
        "CIGAR runs on the engine built into Guard; no Python or download is needed. "
        "Choose preferences in Protection → Context assistance.",
        file=output,
    )
    return 0


_LEAN_ACTIONS = {"on": "enable", "off": "disable", "status": "status"}


def _codex_home() -> str | None:
    """`CODEX_HOME` as Codex reads it from this working folder."""
    import os

    raw = os.environ.get("CODEX_HOME")
    if not raw or not raw.strip() or raw.strip().startswith("~"):
        return raw or None
    return os.path.abspath(raw.strip())


def _run_lean(args: argparse.Namespace, output: TextIO) -> int:
    from pathlib import Path

    from ..config import resolve_guard_home
    from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    request = {
        "switch": "lean",
        "action": _LEAN_ACTIONS[args.lean_action],
        "home_dir": str(Path.home()),
        "codex_home": _codex_home(),
        "limit": args.limit,
        "text": not args.json,
    }
    try:
        answer = native_runner_authority("codex_config", request, resolve_guard_home(args.guard_home))
    except (NativeRunnerAuthorityError, OSError):
        answer = None
    if not isinstance(answer, dict):
        answer = {"ok": False, "code": "codex_config_unavailable", "text": None}
    if answer.get("ok") is True:
        if args.json:
            print(json.dumps(answer.get("state"), sort_keys=True), file=output)
        else:
            print(answer.get("text") or "", end="", file=output)
        return 0
    code = str(answer.get("code") or "codex_config_unavailable")
    if args.json:
        print(json.dumps({"schema": "guard-codex-lean-sessions.v1", "status": "error", "code": code}), file=output)
    else:
        text = answer.get("text") or f"Guard could not change the Codex config ({code}). Nothing was changed."
        print(text, file=output)
    return 1
