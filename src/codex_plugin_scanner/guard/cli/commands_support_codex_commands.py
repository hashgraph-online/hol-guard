"""Guard CLI helper definitions."""

# pyright: reportImportCycles=false

# fmt: off
# ruff: noqa: F403, F405

from __future__ import annotations

from ..native_codex_tool_output import codex_tool_output_native
from ..native_path_anchor import anchor_to_process_directory
from ._commands_shared import *
from .commands_parser_helpers import *


def _codex_post_tool_command_is_read_only_source_inspection(
    *,
    payload: dict[str, object],
    cwd: Path | None,
    home_dir: Path | None,
) -> bool:
    """Whether every command the payload names only inspects source or git metadata.

    The resident reads the commands from the tool name and input itself.
    """

    return codex_tool_output_native(
        "post_tool_read_only_payload",
        body={
            "tool_name": payload.get("tool_name"),
            "tool_input": payload.get("tool_input"),
            "cwd": None if cwd is None else anchor_to_process_directory(cwd),
            "home_dir": None if home_dir is None else anchor_to_process_directory(home_dir),
        },
    ).allowed


__all__ = [
    "_codex_post_tool_command_is_read_only_source_inspection",
]
