"""Devin CLI config and hook JSON helpers for HOL Guard.

Devin's user config lives under ``~/.config/devin/config.json`` (or
``%APPDATA%\\devin\\config.json`` on Windows) and holds a ``hooks`` key whose
event groups are Claude-Code-shaped: ``{"<Event>": [{"matcher": <regex>,
"hooks": [{"type": "command", "command": ..., "timeout": 30}]}]}``.
Config files are JSONC (comments and trailing commas are allowed); Guard only
ever writes strict JSON and refuses to rewrite a JSONC file it cannot
preserve byte-for-byte. The native ``devin_jsonc`` kind applies the JSONC
rules, and ``devin_detect`` inventories hooks, MCP servers and skills with
them.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

DEVIN_DIR = ".devin"
DEVIN_CONFIG_FILE = "config.json"

GUARD_MANAGED_MARKER = "HOL_GUARD_MANAGED_DEVIN"

# Tool names Devin surfaces through hooks: file read/write/edit and notebook
# tools, search tools, exec, webfetch, and MCP tools, which arrive either as
# the ``mcp_call_tool`` dispatcher or as direct ``mcp__<server>__<tool>``
# names, so both shapes are matched. Interactive shell helpers
# (write_to_process, get_output, kill_shell) are intentionally not matched:
# their payloads carry no new command for Guard to review.
DEVIN_GUARD_TOOL_MATCHER = (
    "^(exec|read|write|edit|apply_patch|notebook_read|notebook_edit|grep|glob|webfetch|mcp_call_tool|mcp__.*)$"
)


def is_guard_managed_hook_command(command: object) -> bool:
    """Return True when a hook command string is owned by HOL Guard for Devin."""

    if not isinstance(command, str):
        return False
    # Windows cmdline quoting escapes inner quotes as \"; normalize so the
    # harness marker in the bounded-bridge config matches on every platform.
    normalized = command.replace('\\"', '"')
    return (
        GUARD_MANAGED_MARKER in command
        or ("codex_plugin_scanner.cli" in command and "'guard', 'hook'" in command and "--harness', 'devin'" in command)
        or ("bounded_cli_hook_bridge" in command and '"harness":"devin"' in normalized)
        or ("__guard-bounded-hook" in command and '"harness":"devin"' in normalized)
        or ("managed/bounded-hooks/devin.py" in normalized.replace("\\", "/"))
    )


@dataclass(frozen=True)
class DevinJsonDocument:
    """Result of tolerantly reading a Devin JSON/JSONC file."""

    payload: dict[str, object]
    had_comments: bool
    parse_failed: bool
    exists: bool


def load_devin_jsonc(path: Path) -> DevinJsonDocument:
    """Read a Devin JSONC config for inventory only.

    ``had_comments`` is True when strict JSON parsing failed but the tolerant
    JSONC parse (``//``/``/* */`` comments and trailing commas stripped)
    succeeded, meaning the file must never be rewritten by Guard.
    ``parse_failed`` is True when both parses fail, or when the parsed
    top-level value is not a JSON object; an empty or whitespace-only file
    counts as an empty parseable document.
    """

    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return DevinJsonDocument(payload={}, had_comments=False, parse_failed=False, exists=False)
    except UnicodeDecodeError:
        return DevinJsonDocument(payload={}, had_comments=False, parse_failed=True, exists=True)
    except OSError:
        # A read failure on an existing file (permission denied, I/O error)
        # must fail closed so install() refuses rather than rewriting it.
        exists = path.exists()
        return DevinJsonDocument(payload={}, had_comments=False, parse_failed=exists, exists=exists)
    return parse_devin_jsonc(text)


def parse_devin_jsonc(text: str) -> DevinJsonDocument:
    """Parse an already captured generation with the native JSONC inventory rules."""

    answer = native_runner_authority("devin_jsonc", {"text": text})
    source = answer.get("source")
    had_comments = answer.get("had_comments")
    parse_failed = answer.get("parse_failed")
    if not (source is None or isinstance(source, str)) or not isinstance(had_comments, bool):
        raise NativeRunnerAuthorityError("Devin JSONC answer is malformed")
    if not isinstance(parse_failed, bool):
        raise NativeRunnerAuthorityError("Devin JSONC answer is malformed")
    payload: object = json.loads(source) if source is not None else {}
    if not isinstance(payload, dict):
        raise NativeRunnerAuthorityError("Devin JSONC answer is malformed")
    return DevinJsonDocument(
        payload=cast("dict[str, object]", payload),
        had_comments=had_comments,
        parse_failed=parse_failed,
        exists=True,
    )


__all__ = [
    "DEVIN_CONFIG_FILE",
    "DEVIN_DIR",
    "DEVIN_GUARD_TOOL_MATCHER",
    "GUARD_MANAGED_MARKER",
    "DevinJsonDocument",
    "is_guard_managed_hook_command",
    "load_devin_jsonc",
]
