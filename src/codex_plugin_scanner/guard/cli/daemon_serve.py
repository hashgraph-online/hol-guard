"""Fast path for `hol-guard daemon --serve` without the Guard parser surface."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

_VALUE_FLAGS = frozenset({"--guard-home", "--home", "--port", "--workspace"})


def is_daemon_serve_fast_path_argv(argv: Sequence[str]) -> bool:
    """Return True when argv is a bounded daemon serve launch.

    Desktop and the isolated Python launcher start the approval-center with
    `--serve` plus home/port flags. Help and unknown options stay on argparse.
    """

    tokens = list(argv)
    if tokens[:1] == ["guard"]:
        tokens = tokens[1:]
    if not tokens or tokens[0] != "daemon":
        return False
    rest = tokens[1:]
    if "--serve" not in rest or any(token in {"-h", "--help"} for token in rest):
        return False
    index = 0
    while index < len(rest):
        token = rest[index]
        if token == "--serve":
            index += 1
            continue
        if token in _VALUE_FLAGS:
            if index + 1 >= len(rest) or rest[index + 1].startswith("-"):
                return False
            index += 2
            continue
        return False
    return True


def run_daemon_serve_cli(argv: Sequence[str] | None = None) -> int:
    """Start the local approval-center without building the Guard command parser."""

    tokens = list(sys.argv[1:] if argv is None else argv)
    if tokens[:1] == ["guard"]:
        tokens = tokens[1:]
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--guard-home")
    parser.add_argument("--home")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--workspace")
    args = parser.parse_args(tokens[1:])
    if not args.serve:
        print("Choose daemon --serve.", file=sys.stderr)
        return 2

    from ..config import resolve_guard_home

    return serve_native_daemon(
        resolve_guard_home(args.guard_home or args.home),
        args.port or 0,
        user_home=Path(args.home).expanduser().resolve() if args.home else None,
    )


def serve_native_daemon(guard_home: Path, port: int, *, user_home: Path | None) -> int:
    """Hands this process to the native daemon; returns only when it cannot run."""

    from ..daemon.native_serve import exec_native_daemon

    exec_native_daemon(guard_home, port, user_home=user_home)
    print(
        "The Guard daemon needs HOL Guard's native runtime. Run `hol-guard doctor` to repair the installation.",
        file=sys.stderr,
    )
    return 1


__all__ = ["is_daemon_serve_fast_path_argv", "run_daemon_serve_cli", "serve_native_daemon"]
