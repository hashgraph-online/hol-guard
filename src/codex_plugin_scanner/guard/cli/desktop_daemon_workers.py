"""Fast path for the native daemon's worker host (`desktop daemon-workers`).

The native daemon starts this child on every cold start and does not report
ready until the host has published policy. Building the Guard command parser,
importing the command hub and loading Guard settings first added seconds
before the host ran, and the host uses none of them.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import Path


def _launch_tokens(argv: Sequence[str]) -> list[str]:
    tokens = list(argv)
    if tokens[:1] == ["guard"]:
        tokens = tokens[1:]
    return tokens


def is_daemon_workers_fast_path_argv(argv: Sequence[str]) -> bool:
    """Return True for the exact launch the native daemon makes.

    That launch is `desktop daemon-workers --guard-home <path>`. Any other
    shape, help included, stays on argparse.
    """

    tokens = _launch_tokens(argv)
    return (
        len(tokens) == 4
        and tokens[:3] == ["desktop", "daemon-workers", "--guard-home"]
        and bool(tokens[3])
        and not tokens[3].startswith("-")
    )


def run_daemon_workers_cli(argv: Sequence[str]) -> int:
    """Run the worker host for the guard home the daemon named."""

    from ..config import resolve_guard_home
    from ..native_context import bind_context_digest_home
    from ..workers.host import run_worker_host

    tokens = _launch_tokens(argv)
    if not is_daemon_workers_fast_path_argv(tokens):
        print("Guard daemon workers require --guard-home.", file=sys.stderr)
        return 2
    guard_home: Path = resolve_guard_home(tokens[3])
    # The command router binds this for every subcommand; the host's digest
    # calls resolve against the same home.
    bind_context_digest_home(guard_home)
    return run_worker_host(guard_home)


__all__ = ["is_daemon_workers_fast_path_argv", "run_daemon_workers_cli"]
