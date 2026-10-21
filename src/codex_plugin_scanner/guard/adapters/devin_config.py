"""Devin CLI config and hook JSON helpers for HOL Guard.

Devin's user config lives under ``~/.config/devin/config.json`` (or
``%APPDATA%\\devin\\config.json`` on Windows) and holds a ``hooks`` key whose
event groups are Claude-Code-shaped: ``{"<Event>": [{"matcher": <regex>,
"hooks": [{"type": "command", "command": ..., "timeout": 30}]}]}``.
Config files are JSONC (comments and trailing commas are allowed); Guard only
ever writes strict JSON and refuses to rewrite a JSONC file it cannot
preserve byte-for-byte. The native ``devin_detect`` kind inventories hooks,
MCP servers and skills with the same JSONC rules.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

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


def _strip_jsonc_syntax(text: str) -> str:
    """Remove ``//``/``/* */`` comments and trailing commas outside strings."""

    output: list[str] = []
    index = 0
    in_string = False
    length = len(text)
    while index < length:
        char = text[index]
        if in_string:
            output.append(char)
            if char == "\\" and index + 1 < length:
                output.append(text[index + 1])
                index += 2
                continue
            if char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            output.append(char)
            index += 1
            continue
        if char == "/" and index + 1 < length:
            nxt = text[index + 1]
            if nxt == "/":
                index += 2
                while index < length and text[index] not in "\r\n":
                    index += 1
                continue
            if nxt == "*":
                index += 2
                while index + 1 < length and not (text[index] == "*" and text[index + 1] == "/"):
                    index += 1
                index += 2
                continue
        if char == ",":
            lookahead = index + 1
            while lookahead < length:
                if text[lookahead] in " \t\r\n":
                    lookahead += 1
                    continue
                if text[lookahead] == "/" and lookahead + 1 < length:
                    nxt = text[lookahead + 1]
                    if nxt == "/":
                        lookahead += 2
                        while lookahead < length and text[lookahead] not in "\r\n":
                            lookahead += 1
                        continue
                    if nxt == "*":
                        lookahead += 2
                        while lookahead + 1 < length and not (text[lookahead] == "*" and text[lookahead + 1] == "/"):
                            lookahead += 1
                        lookahead += 2
                        continue
                break
            if lookahead < length and text[lookahead] in "]}":
                index += 1
                continue
        output.append(char)
        index += 1
    return "".join(output)


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
    """Parse an already captured generation with the same JSONC inventory rules."""

    if not text.strip():
        return DevinJsonDocument(payload={}, had_comments=False, parse_failed=False, exists=True)
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        pass
    else:
        if isinstance(payload, dict):
            return DevinJsonDocument(payload=payload, had_comments=False, parse_failed=False, exists=True)
        return DevinJsonDocument(payload={}, had_comments=False, parse_failed=True, exists=True)
    stripped = _strip_jsonc_syntax(text)
    if not stripped.strip():
        return DevinJsonDocument(payload={}, had_comments=True, parse_failed=False, exists=True)
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        return DevinJsonDocument(payload={}, had_comments=False, parse_failed=True, exists=True)
    if isinstance(payload, dict):
        return DevinJsonDocument(payload=payload, had_comments=True, parse_failed=False, exists=True)
    return DevinJsonDocument(payload={}, had_comments=True, parse_failed=True, exists=True)


__all__ = [
    "DEVIN_CONFIG_FILE",
    "DEVIN_DIR",
    "DEVIN_GUARD_TOOL_MATCHER",
    "GUARD_MANAGED_MARKER",
    "DevinJsonDocument",
    "is_guard_managed_hook_command",
    "load_devin_jsonc",
]
