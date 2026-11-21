"""Commands the native runtime owns end to end.

The runtime reads the arguments and writes the answer; Python only resolves
the Guard home and hands everything over.
"""

from __future__ import annotations

import argparse
import contextlib
import subprocess
import sys
from typing import Any, TextIO

FEATURE = "native-context-cli-v1"


def configure_forward(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser], name: str, help_text: str
) -> None:
    parser = subparsers.add_parser(name, help=help_text, add_help=False)
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
        elif item.startswith("--guard-home="):
            home = item.split("=", 1)[1]
        else:
            rest.append(item)
    return rest, home


def run_forward(args: argparse.Namespace, *, output_stream: TextIO | None = None, **_: Any) -> int:
    from ..config import resolve_guard_home
    from ..native_recovery_store import recovery_runtime_path

    output = output_stream if output_stream is not None else sys.stdout
    forwarded, raw_home = _guard_home_argument(list(args.forward_args), args.guard_home)
    argv = list(forwarded)
    if args.json:
        argv.insert(0, "--json")
    if args.forward_help:
        argv.insert(0, "--help")
    with contextlib.suppress(OSError, RuntimeError, ValueError):
        argv[:0] = ["--guard-home", str(resolve_guard_home(raw_home))]
    try:
        runtime = recovery_runtime_path(FEATURE)
    except RuntimeError:
        print("Guard's native runtime is unavailable on this machine. Guard protection remains available.", file=output)
        return 1
    try:
        completed = subprocess.run([runtime, args.runtime_command, *argv], stdout=subprocess.PIPE, check=False)
    except OSError:
        print("Guard's native runtime could not start. Guard protection remains available.", file=output)
        return 1
    output.write(completed.stdout.decode("utf-8", errors="replace"))
    return completed.returncode
