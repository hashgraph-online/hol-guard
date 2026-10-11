"""Native transparent-wrapper normalization and path trust."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..native_shell_helpers import call

SHELL_COMMAND_NORMALIZE_MAX_BYTES = 8192


@dataclass(frozen=True, slots=True)
class ShellCommandNormalization:
    raw_command: str
    normalized_command: str
    wrapper_chain: tuple[str, ...] = ()


def normalize_transparent_shell_command(
    command_text: str, *, cwd: Path | None = None, home_dir: Path | None = None
) -> ShellCommandNormalization:
    row = call(
        "normalization",
        command_text,
        cwd=str(cwd) if cwd is not None else None,
        home_dir=str(home_dir) if home_dir is not None else None,
    )
    return ShellCommandNormalization(row["raw_command"], row["normalized_command"], tuple(row["wrapper_chain"]))


def is_trusted_absolute_command_path(command_path: Path, *, cwd: Path | None, home_dir: Path | None) -> bool:
    return call(
        "trusted_path",
        str(command_path),
        cwd=str(cwd) if cwd is not None else None,
        home_dir=str(home_dir) if home_dir is not None else None,
    )


__all__ = ["ShellCommandNormalization", "is_trusted_absolute_command_path", "normalize_transparent_shell_command"]
