"""Grok Build CLI config and hook JSON helpers for HOL Guard."""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path

GROK_PRETOOL_HOOK_TIMEOUT_SECONDS = 90
GROK_HOOK_INTERNAL_TIMEOUT_SECONDS = 85
GROK_APPROVAL_WAIT_MAX_SECONDS = 80

GROK_DIR = ".grok"
GROK_CONFIG_FILE = "config.toml"
GROK_MANAGED_CONFIG_FILE = "managed_config.toml"
GROK_HOOKS_DIR = "hooks"
GUARD_MANAGED_BEGIN = "# BEGIN HOL GUARD MANAGED GROK"
GUARD_MANAGED_END = "# END HOL GUARD MANAGED GROK"
GUARD_MANAGED_MARKER = "HOL GUARD MANAGED GROK"
GUARD_HOOK_PRETOOL_FILE = "hol-guard-pretooluse.json"
GUARD_HOOK_PROMPT_FILE = "hol-guard-prompt.json"
# Kept empty: a per-tool matcher list double-fired after Grok aliased Bash→run_terminal_command.
MANAGED_DENY_RULES = (
    "Bash(hol-guard apps disconnect grok*)",
    "Bash(hol-guard apps uninstall*)",
    "Bash(rm -rf **/.grok/hooks/hol-guard*)",
    "Edit(**/.grok/hooks/hol-guard*)",
    "Edit(**/.grok/managed_config.toml)",
    "Edit(**/.grok/config.toml)",
    "Read(**/.grok/auth/**)",
    "Read(**/.grok/auth.json)",
    "Read(**/.env)",
    "Read(**/.npmrc)",
    "Read(**/.ssh/**)",
    "Read(**/.hol-guard/secrets/**)",
    "Read(**/.hol-guard/totp-secrets/**)",
    "Read(**/.hol-guard/daemon-auth-token)",
)
OBSERVE_HOOK_EVENTS = ("UserPromptSubmit", "SubagentStart", "SessionStart")
SYSTEM_MANAGED_CONFIG = Path("/etc/grok/managed_config.toml")
SYSTEM_REQUIREMENTS = Path("/etc/grok/requirements.toml")


def _command_hook_entry(hook_command: str, *, timeout: int) -> dict[str, object]:
    return {
        "hooks": [
            {
                "type": "command",
                "command": hook_command,
                "timeout": timeout,
            }
        ]
    }


def build_pretool_hook_json(hook_command: str) -> dict[str, object]:
    """Install one catch-all PreToolUse handler.

    Grok matchers are regexes against the native tool name and also expand
    aliases, so listing both ``Bash`` and ``run_terminal_command`` ran Guard
    twice. An omitted matcher covers current and future tools, including
    ``spawn_subagent``, ``list_dir``, and ``server__tool`` MCP names.
    """

    return {"hooks": {"PreToolUse": [_command_hook_entry(hook_command, timeout=GROK_PRETOOL_HOOK_TIMEOUT_SECONDS)]}}


def build_observe_hook_json(hook_command: str) -> dict[str, object]:
    """Install the prompt gate alongside passive session and subagent hooks."""

    return {
        "hooks": {event_name: [_command_hook_entry(hook_command, timeout=15)] for event_name in OBSERVE_HOOK_EVENTS}
    }


FOREIGN_HOOK_COMPAT_VENDORS = ("claude", "cursor")


def _compat_table_span(text: str, vendor: str) -> tuple[int, int] | None:
    match = re.search(
        rf"(?m)^[ \t]*\[compat\.{re.escape(vendor)}\][ \t]*(?:#.*)?$",
        text,
    )
    if match is None:
        return None
    rest = text[match.end() :]
    nxt = re.search(r"(?m)^[ \t]*\[", rest)
    end = match.end() + (nxt.start() if nxt else len(rest))
    return match.start(), end


def _compat_hooks_assignment(block: str) -> tuple[int, int, str, str] | None:
    """Locate one compat hooks assignment and preserve its physical line ending."""

    offset = 0
    for line in block.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        newline = line[len(body) :]
        stripped = body.lstrip(" \t")
        if stripped.startswith("hooks"):
            remainder = stripped[len("hooks") :].lstrip(" \t")
            if remainder.startswith("="):
                value = remainder[1:].lstrip(" \t").strip()
                return offset, offset + len(line), value, newline
        offset += len(line)
    return None


def restore_compat_hooks(text: str, prior_hooks: Mapping[str, str | None]) -> str:
    """Restore pre-install compat.hooks values after Guard uninstall."""

    updated = text
    for vendor, previous in prior_hooks.items():
        span = _compat_table_span(updated, vendor)
        if span is None or previous is None:
            continue
        start, end = span
        block = updated[start:end]
        assignment = _compat_hooks_assignment(block)
        if previous == "":
            if assignment is not None:
                line_start, line_end, _, _ = assignment
                block = block[:line_start] + block[line_end:]
        else:
            if assignment is not None:
                line_start, line_end, _, newline = assignment
                block = block[:line_start] + f"hooks = {previous}" + newline + block[line_end:]
            else:
                header = f"[compat.{vendor}]"
                block = block.replace(header, header + f"\nhooks = {previous}", 1)
        updated = updated[:start] + block + updated[end:]
    return updated


def remove_managed_block(text: str) -> str:
    pattern = re.compile(
        rf"^\s*{re.escape(GUARD_MANAGED_BEGIN)}.*?{re.escape(GUARD_MANAGED_END)}\s*\n?",
        re.MULTILINE | re.DOTALL,
    )
    cleaned = pattern.sub("", text)
    cleaned = re.sub(rf"^\s*#.*{re.escape(GUARD_MANAGED_MARKER)}.*$\n?", "", cleaned, flags=re.MULTILINE)
    return cleaned
