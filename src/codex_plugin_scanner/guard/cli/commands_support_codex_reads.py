"""Guard CLI read-only source inspection review (resident-owned)."""

from __future__ import annotations

from pathlib import Path

from ..native_codex_tool_output import codex_tool_output_native


def _codex_command_is_read_only_source_inspection(
    command_text: str,
    *,
    cwd: Path | None,
    home_dir: Path | None = None,
) -> bool:
    """Ask the resident whether the command is a bounded read-only source inspection."""
    return codex_tool_output_native("read_only_inspection", command=command_text, cwd=cwd, home_dir=home_dir).allowed


__all__ = ["_codex_command_is_read_only_source_inspection"]
