"""Present resident-derived local tool contexts through the existing API."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from ..native_direct_tool_context import native_direct_tool_context

if TYPE_CHECKING:
    from .shell_execution_context import ShellExecutionContext


def direct_local_typescript_execution_context(
    command_text: str, *, cwd: Path | None, home_dir: Path
) -> ShellExecutionContext | None:
    return native_direct_tool_context("typescript", command_text, cwd=cwd, home_dir=home_dir)
