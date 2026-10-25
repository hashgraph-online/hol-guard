"""Direct native calls for the wrapper behaviour the Python runtime no longer owns.

Rust owns transparent-wrapper normalization and absolute-path trust. The tests
below call the resident helper transport straight through so they keep covering
that native behaviour without a Python runtime module standing in the middle.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from codex_plugin_scanner.guard.native_shell_helpers import call


@dataclass(frozen=True, slots=True)
class ShellWrapperNormalization:
    raw_command: str
    normalized_command: str
    wrapper_chain: tuple[str, ...] = ()


def native_shell_normalization(
    command_text: str, *, cwd: Path | None = None, home_dir: Path | None = None
) -> ShellWrapperNormalization:
    row = call(
        "normalization",
        command_text,
        cwd=str(cwd) if cwd is not None else None,
        home_dir=str(home_dir) if home_dir is not None else None,
    )
    return ShellWrapperNormalization(row["raw_command"], row["normalized_command"], tuple(row["wrapper_chain"]))


def native_trusted_absolute_path(command_path: Path, *, cwd: Path | None, home_dir: Path | None) -> bool:
    return call(
        "trusted_path",
        str(command_path),
        cwd=str(cwd) if cwd is not None else None,
        home_dir=str(home_dir) if home_dir is not None else None,
    )


__all__ = ["ShellWrapperNormalization", "native_shell_normalization", "native_trusted_absolute_path"]
