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
        ("runtimes", "installations", "List enrolled runtime metadata without launching CIGAR"),
        ("check", "recheck", "Schedule verification of the saved runtime in the background"),
        ("start", "activate", "Start the saved, explicitly enabled runtime after native verification"),
        ("off", "stop", "Cancel context work and persist opt-out; retain Guard approvals"),
    ):
        action = actions.add_parser(name, help=help_text)
        action.set_defaults(context_kind=kind)
        action.add_argument("--guard-home", default=argparse.SUPPRESS)
        action.add_argument("--json", action="store_true", default=argparse.SUPPRESS)

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
    try:
        home = resolve_guard_home(args.guard_home)
        if args.context_kind == "versions":
            from .context_assistance_versions_commands import execute

            state = execute(args, home, input_text=input_text)
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
        for option in state["installation_options"]:
            version = ".".join(str(part) for part in option["python_version"])
            print(
                f"  {option['runtime_id']}: Python {version} · {option['platform']} · {option['qualification']}",
                file=output,
            )
        if not state["installation_options"]:
            print("No verified runtimes are enrolled.", file=output)
    print(
        "Requires a verified final CPython 3.14 runtime and a qualified CIGAR build. "
        "Choose preferences in Protection → Context assistance.",
        file=output,
    )
    return 0


def _run_lean(args: argparse.Namespace, output: TextIO) -> int:
    import os
    from pathlib import Path

    from ..codex_lean_sessions import LeanSessionsError, disable, enable, render, status
    from ..config import resolve_guard_home

    try:
        home, guard_home = Path.home(), resolve_guard_home(args.guard_home)
        if args.lean_action == "on":
            state = enable(home, guard_home, os.environ, limit=args.limit)
        else:
            state = (disable if args.lean_action == "off" else status)(home, guard_home, os.environ)
    except LeanSessionsError as error:
        return _lean_failure(args, output, error.code)
    except TimeoutError:
        return _lean_failure(args, output, "codex_config_busy")
    except (OSError, RuntimeError, ValueError):
        return _lean_failure(args, output, "codex_config_unavailable")
    if args.json:
        print(json.dumps(state, sort_keys=True), file=output)
    else:
        render(state, output)
    return 0


_LEAN_FAILURES = {
    "codex_lean_limit_required": (
        "Pick a size: hol-guard context lean on --limit 100000. Guard sets no size of its own. Nothing was changed."
    ),
    "codex_lean_limit_invalid": "The limit must be a whole number from 10,000 to 10,000,000. Nothing was changed.",
}


def _lean_failure(args: argparse.Namespace, output: TextIO, code: str) -> int:
    if args.json:
        print(json.dumps({"schema": "guard-codex-lean-sessions.v1", "status": "error", "code": code}), file=output)
    else:
        print(
            _LEAN_FAILURES.get(code, f"Guard could not change the Codex config ({code}). Nothing was changed."),
            file=output,
        )
    return 1
