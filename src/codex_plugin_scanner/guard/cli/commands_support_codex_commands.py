"""Guard CLI helper definitions."""

# pyright: reportImportCycles=false

# fmt: off
# ruff: noqa: F403, F405

from __future__ import annotations

from ..native_codex_tool_output import codex_tool_output_native
from ..native_sensitive_request import NativeSensitiveRequestError
from ..runtime.secret_file_requests import (
    COMMAND_CANDIDATE_LIST_KEYS,
    COMMAND_SEQUENCE_KEYS,
    command_list_candidate_texts,
)
from ._commands_shared import *
from .commands_parser_helpers import *


def _codex_post_tool_command_is_read_only_source_inspection(
    *,
    payload: dict[str, object],
    cwd: Path | None,
    home_dir: Path | None,
) -> bool:
    try:
        command_texts = _codex_post_tool_command_texts(payload)
    except NativeSensitiveRequestError:
        return False
    if not command_texts:
        return False
    return codex_tool_output_native(
        "post_tool_read_only", commands=command_texts, cwd=cwd, home_dir=home_dir
    ).allowed


def _codex_post_tool_command_texts(payload: dict[str, object]) -> tuple[str, ...]:
    tool_input = payload.get("tool_input")
    if isinstance(tool_input, dict):
        candidates: list[str] = []
        command = tool_input.get("command")
        if isinstance(command, str):
            stripped = command.strip()
            if stripped:
                candidates.append(stripped)
        for key in COMMAND_CANDIDATE_LIST_KEYS:
            candidate = tool_input.get(key)
            if isinstance(candidate, list):
                candidates.extend(
                    command_list_candidate_texts(
                        candidate, preserve_items=key in COMMAND_SEQUENCE_KEYS
                    )
                )
        if not candidates and str(payload.get("tool_name", "")).strip().lower() in {
            "cat_file",
            "open_file",
            "read",
            "read_file",
            "view",
            "view_file",
        }:
            for key in ("path", "file_path", "filePath", "filepath", "file", "filename"):
                value = tool_input.get(key)
                if isinstance(value, str) and value.strip():
                    candidates.append(f"cat -- {shlex.quote(value.strip())}")
        if not candidates:
            native_command = command_text_from_tool_payload(payload.get("tool_name"), tool_input)
            if native_command is not None:
                candidates.append(native_command)
        return tuple(dict.fromkeys(text for text in candidates if text))
    return ()


__all__ = [
    "_codex_post_tool_command_is_read_only_source_inspection",
]
