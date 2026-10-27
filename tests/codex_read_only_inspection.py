"""Test-side resident questions for Codex read-only source inspection.

The resident owns the read-only inspection decision. These wrappers ask it
directly so tests can pin its answers; no production path calls them.
"""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.native_codex_tool_output import codex_tool_output_native
from codex_plugin_scanner.guard.native_path_anchor import anchor_to_process_directory


def codex_command_is_read_only_source_inspection(
    command_text: str,
    *,
    cwd: Path | None,
    home_dir: Path | None = None,
) -> bool:
    """Ask the resident whether the command is a bounded read-only source inspection."""
    return codex_tool_output_native("read_only_inspection", command=command_text, cwd=cwd, home_dir=home_dir).allowed


def codex_post_tool_command_is_read_only_source_inspection(
    *,
    payload: dict[str, object],
    cwd: Path | None,
    home_dir: Path | None,
) -> bool:
    """Whether every command the payload names only inspects source or git metadata."""
    return codex_tool_output_native(
        "post_tool_read_only_payload",
        body={
            "tool_name": payload.get("tool_name"),
            "tool_input": payload.get("tool_input"),
            "cwd": None if cwd is None else anchor_to_process_directory(cwd),
            "home_dir": None if home_dir is None else anchor_to_process_directory(home_dir),
        },
    ).allowed
