"""Reason codes and path helpers the shell execution-context caller reads.

The resident models the shell itself: which segment runs a directory
command, what its operand is and which reason code explains one it cannot
resolve. What is left here is the vocabulary that answer is read with and
the filesystem identity this process captures for it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

SHELL_CWD_UNRESOLVED_EXPRESSION = "shell_cwd_unresolved_expression"
SHELL_CWD_MISSING_DIRECTORY = "shell_cwd_missing_directory"
SHELL_CWD_NOT_DIRECTORY = "shell_cwd_not_directory"
SHELL_CWD_UNREADABLE_DIRECTORY = "shell_cwd_unreadable_directory"
SHELL_CWD_AMBIGUOUS_STACK = "shell_cwd_ambiguous_stack"
SHELL_CWD_STACK_LIMIT = "shell_cwd_stack_limit"
SHELL_CWD_WORKSPACE_ESCAPE = "shell_cwd_workspace_escape"
SHELL_CWD_SYMLINK_ESCAPE = "shell_cwd_symlink_escape"
SHELL_CWD_UNRESOLVED_CONTROL_FLOW = "shell_cwd_unresolved_control_flow"
SHELL_CWD_UNRESOLVED_PARENT_SHELL = "shell_cwd_unresolved_parent_shell_effect"
SHELL_CWD_UNRESOLVED_SYNTAX = "shell_cwd_unresolved_syntax"
SHELL_CWD_PATH_CHANGED = "shell_cwd_path_changed"

FLOW_OPERATORS = frozenset({"&&", "||", ";", "\n", "|", "|&", "&"})
SHELL_DIRECTORY_COMMAND = re.compile(
    r"(?:^|(?:&&|\|\||[;|&(){}\n]))\s*"
    r"(?:(?:builtin|command|time)\s+(?:-[^\s]+\s+)*|function\s+|!\s+)?"
    r"(?:cd|pushd|popd)\b"
)


@dataclass(frozen=True, slots=True)
class ShellPathIdentity:
    """Filesystem identity captured without retaining an open descriptor."""

    device: int
    inode: int
    mode: int
    change_time_ns: int
    creation_time_ns: int


def shell_path_identity_payload(identity: ShellPathIdentity | None) -> dict[str, int] | None:
    """Return the stable JSON payload for a captured shell path identity."""

    if identity is None:
        return None
    return {
        "change_time_ns": identity.change_time_ns,
        "creation_time_ns": identity.creation_time_ns,
        "device": identity.device,
        "inode": identity.inode,
        "mode": identity.mode,
    }


@dataclass(frozen=True, slots=True)
class ShellPathProof:
    """A lexical directory path bound to the target observed during modeling."""

    lexical_path: Path
    resolved_path: Path
    identity: ShellPathIdentity


def last_flow_operator(controls: tuple[str, ...]) -> str | None:
    return next((control for control in reversed(controls) if control in FLOW_OPERATORS), None)
