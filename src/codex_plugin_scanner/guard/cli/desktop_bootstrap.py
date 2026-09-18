"""Fast path for `hol-guard desktop bootstrap` without the Guard parser surface."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from typing import TextIO


def is_desktop_bootstrap_fast_path_argv(argv: Sequence[str]) -> bool:
    """Return True when argv is the Desktop warmup command with no extra flags.

    `--guard-home`, `--home`, `--workspace`, `--help`, and other options stay on
    the full parser so those invocations keep their existing argparse behavior.
    """

    tokens = list(argv)
    return tokens == ["desktop", "bootstrap"] or tokens == ["desktop", "bootstrap", "--json"]


def run_desktop_bootstrap_cli(*, output_stream: TextIO | None = None) -> int:
    """Emit desktop bootstrap JSON without building the Guard command parser."""

    from pathlib import Path

    from ..adapters.base import HarnessContext
    from ..config import load_guard_config, overlay_synced_guard_policy, resolve_guard_home
    from ..store import GuardStore
    from ..synced_policy import synced_policy_payload
    from .commands_dispatch_desktop import _run_guard_desktop_command

    guard_home = resolve_guard_home(None)
    context = HarnessContext(
        home_dir=Path.home().resolve(),
        workspace_dir=None,
        guard_home=guard_home,
        executable_overrides={},
        home_override_explicit=False,
        workspace_override_explicit=False,
    )
    try:
        store = GuardStore(
            guard_home,
            source="default",
            prime_policy_integrity=False,
            allow_system_keyring=False,
        )
        config = overlay_synced_guard_policy(
            load_guard_config(guard_home, workspace=None),
            synced_policy_payload(store),
        )
    except (OSError, TimeoutError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2
    args = argparse.Namespace(guard_command="desktop", desktop_command="bootstrap", json=True)
    return _run_guard_desktop_command(
        args,
        guard_home=guard_home,
        workspace=None,
        context=context,
        store=store,
        config=config,
        output_stream=output_stream,
    )


__all__ = [
    "is_desktop_bootstrap_fast_path_argv",
    "run_desktop_bootstrap_cli",
]
