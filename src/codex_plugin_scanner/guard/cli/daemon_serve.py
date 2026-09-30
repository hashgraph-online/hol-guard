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
    from ..daemon.server import GuardDaemonServer
    from ..store import GuardStore

    home_override = args.home
    home_dir = Path(home_override).expanduser().resolve() if home_override else Path.home().resolve()
    guard_home = resolve_guard_home(args.guard_home or home_override)
    store = GuardStore(
        guard_home,
        source="default",
        prime_policy_integrity=False,
        allow_system_keyring=False,
    )
    workspace_dir = Path(args.workspace).expanduser() if args.workspace else None
    daemon = GuardDaemonServer(
        store,
        port=args.port or 0,
        home_dir=home_dir,
        workspace_dir=workspace_dir,
    )
    daemon.serve()
    return 0


__all__ = ["is_daemon_serve_fast_path_argv", "run_daemon_serve_cli"]
