"""Fast path for the native daemon's Python children.

The native daemon starts `desktop daemon-workers`, `desktop library-serve` and
`desktop library-call` with `--guard-home <path>`. The worker host must
publish policy and the artifact reconcile (a library call) must finish before
the daemon reports ready, so both sit on every cold start. Building the Guard
command parser, importing the command hub and constructing the router's store
and context first added seconds before either ran, and none of them uses that
work. No lifecycle approval gate applies to these subcommands.
"""

from __future__ import annotations

import sys
from collections.abc import Callable, Sequence
from pathlib import Path

_FAST_PATH_COMMANDS = frozenset({"daemon-workers", "library-serve", "library-call"})


def _launch_tokens(argv: Sequence[str]) -> list[str]:
    tokens = list(argv)
    if tokens[:1] == ["guard"]:
        tokens = tokens[1:]
    return tokens


def is_daemon_workers_fast_path_argv(argv: Sequence[str]) -> bool:
    """Return True for the exact launch the native daemon makes.

    That launch is `desktop <child> --guard-home <path>`. Any other shape,
    help included, stays on argparse.
    """

    tokens = _launch_tokens(argv)
    return (
        len(tokens) == 4
        and tokens[0] == "desktop"
        and tokens[1] in _FAST_PATH_COMMANDS
        and tokens[2] == "--guard-home"
        and bool(tokens[3])
        and not tokens[3].startswith("-")
    )


def _child(command: str) -> Callable[[Path], int]:
    if command == "daemon-workers":
        from ..workers.host import run_worker_host

        return run_worker_host
    from .desktop_library_call import run_library_call, serve_library_calls

    return serve_library_calls if command == "library-serve" else run_library_call


def run_daemon_workers_cli(argv: Sequence[str]) -> int:
    """Run the daemon child the launch names, for the guard home it names."""

    from ..config import resolve_guard_home
    from ..native_context import bind_context_digest_home

    tokens = _launch_tokens(argv)
    if not is_daemon_workers_fast_path_argv(tokens):
        print("Guard daemon children require --guard-home.", file=sys.stderr)
        return 2
    guard_home: Path = resolve_guard_home(tokens[3])
    # The command router binds this for every subcommand; the child's digest
    # calls resolve against the same home.
    bind_context_digest_home(guard_home)
    return _child(tokens[1])(guard_home)


__all__ = ["is_daemon_workers_fast_path_argv", "run_daemon_workers_cli"]
