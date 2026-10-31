"""Route native containment receipts through the PreToolUse updatedInput contract.

ZCode, Claude Code and Codex 0.131+ apply a hook's ``updatedInput``, so a contained test run is
rewritten into Guard's execution sink instead of stopping for review.

Whether a receipt is rewritten, and under which profile, is the resident's
answer, and the edge writes the request snapshot and quotes the sink command
(``edge_containment.rs``). This module only names the argv that starts
Guard's CLI.
"""

from __future__ import annotations

import sys
from collections.abc import Mapping
from pathlib import Path

from ..codex_hook_launch_runtime import isolated_guard_cli_command


def contained_sink_command_prefix(
    python_executable: str | None = None, package_root: Path | None = None
) -> tuple[str, ...]:
    """The argv prefix the contained sink starts with."""
    return _sink_command_prefix(
        {
            "python_executable": python_executable or sys.executable,
            "package_root": str(package_root or Path(__file__).resolve().parents[3]),
        }
    )


def _sink_command_prefix(config: Mapping[str, object]) -> tuple[str, ...]:
    if getattr(sys, "frozen", False):
        from ..stable_guard_cli import resolve_frozen_guard_cli

        return (resolve_frozen_guard_cli(),)
    package_root = Path(str(config["package_root"]))
    command = isolated_guard_cli_command(str(config["python_executable"]), package_root, ())
    if sys.platform != "win32":
        return command
    # Git Bash hands a native program each doubled backslash as a single one,
    # which breaks the escaped package root in the bootstrap. The same
    # directory written with forward slashes needs no escaping.
    root = str(package_root.resolve())
    return (*command[:-1], command[-1].replace(repr(root), repr(root.replace("\\", "/")), 1))
