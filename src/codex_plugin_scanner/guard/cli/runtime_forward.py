"""Commands the native runtime owns end to end.

The runtime reads the arguments and writes the answer; Python only resolves
the Guard home, sets up the resident's key for it and hands everything over.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, TextIO

FEATURE = "native-context-cli-v1"
_SCHEMA = "guard-context-assistance-cli.v1"
_RUNTIME_UNAVAILABLE = "native_runtime_unavailable"
_HOME_UNAVAILABLE = "native_context_assistance_home_unavailable"
_MESSAGES = {
    _RUNTIME_UNAVAILABLE: "Guard's native runtime is unavailable on this machine. Guard protection remains available.",
    _HOME_UNAVAILABLE: "The local Guard context service could not be reached. Check this installation's Guard home.",
}


class _MissingHomeError(ValueError):
    """`--guard-home` was given without a folder."""


def configure_forward(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    name: str,
    help_text: str,
    aliases: tuple[str, ...] = (),
) -> None:
    parser = subparsers.add_parser(name, help=help_text, add_help=False, aliases=list(aliases))
    parser.set_defaults(runtime_command=name)
    parser.add_argument("--guard-home")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("-h", "--help", dest="forward_help", action="store_true")
    parser.add_argument("forward_args", nargs=argparse.REMAINDER)


def _guard_home_argument(forwarded: list[str], default: str | None) -> tuple[list[str], str | None]:
    """Take `--guard-home` out of the forwarded arguments; the last one wins."""
    rest: list[str] = []
    home = default
    items = iter(forwarded)
    for item in items:
        if item == "--guard-home":
            home = next(items, None)
            if home is None or home.startswith("-"):
                raise _MissingHomeError(item)
        elif item.startswith("--guard-home="):
            home = item.split("=", 1)[1]
            if not home:
                raise _MissingHomeError(item)
        else:
            rest.append(item)
    return rest, home


def _fail(code: str, as_json: bool, output: TextIO) -> int:
    if as_json:
        print(json.dumps({"schema": _SCHEMA, "status": "unavailable", "code": code}), file=output)
    else:
        print(_MESSAGES[code], file=output)
    return 1


def run_forward(args: argparse.Namespace, *, output_stream: TextIO | None = None, **_: Any) -> int:
    from ..config import resolve_guard_home
    from ..native_context import ensure_resident_prerequisite
    from ..native_recovery_store import recovery_runtime_path

    output = output_stream if output_stream is not None else sys.stdout
    as_json = bool(args.json) or "--json" in args.forward_args
    try:
        forwarded, raw_home = _guard_home_argument(list(args.forward_args), args.guard_home)
    except _MissingHomeError:
        print(f"hol-guard {args.runtime_command}: --guard-home needs a folder", file=sys.stderr)
        return 2
    argv = list(forwarded)
    if args.json:
        argv.insert(0, "--json")
    if args.forward_help:
        argv.insert(0, "--help")
    else:
        try:
            home = Path(resolve_guard_home(raw_home))
        except (OSError, RuntimeError, ValueError):
            return _fail(_HOME_UNAVAILABLE, as_json, output)
        # The resident refuses every request until the home's verifier key
        # exists, and never creates it itself.
        if not ensure_resident_prerequisite(home):
            return _fail(_HOME_UNAVAILABLE, as_json, output)
        argv[:0] = ["--guard-home", str(home)]
    try:
        runtime = recovery_runtime_path(FEATURE)
        completed = subprocess.run([runtime, args.runtime_command, *argv], stdout=subprocess.PIPE, check=False)
    except (OSError, RuntimeError):
        return _fail(_RUNTIME_UNAVAILABLE, as_json, output)
    output.write(completed.stdout.decode("utf-8", errors="replace"))
    return completed.returncode
