"""Grok Build CLI config and hook JSON helpers for HOL Guard."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path

GROK_PRETOOL_HOOK_TIMEOUT_SECONDS = 90
GROK_HOOK_INTERNAL_TIMEOUT_SECONDS = 85
GROK_APPROVAL_WAIT_MAX_SECONDS = 80

GROK_DIR = ".grok"
GROK_CONFIG_FILE = "config.toml"
GROK_MANAGED_CONFIG_FILE = "managed_config.toml"
GROK_REQUIREMENTS_FILE = "requirements.toml"
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


def _toml_inline_command_hook(hook_command: str, *, timeout: int) -> str:
    return '{ type = "command", command = ' + json.dumps(hook_command) + f", timeout = {timeout} }}"


FOREIGN_HOOK_COMPAT_VENDORS = ("claude", "cursor")


def foreign_hook_compat_toml(vendors: tuple[str, ...] = FOREIGN_HOOK_COMPAT_VENDORS) -> str:
    """Disable Grok's vendor hook-file import.

    Grok merges other products' hook settings by default. Those files often
    split the interpreter from its arguments. Grok runs only the interpreter
    and feeds the hook JSON on stdin, so Python treats the payload as source
    and exits 1 with a traceback on every prompt and tool event. Guard keeps
    Grok-native hooks in this managed block and the dedicated hook JSON files.
    """

    chunks: list[str] = []
    for vendor in vendors:
        if chunks:
            chunks.append("")
        chunks.extend([f"[compat.{vendor}]", "hooks = false"])
    return "\n".join(chunks)


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


def force_compat_hooks_false(text: str, vendor: str) -> tuple[str, str | None]:
    """Set hooks=false on an existing compat table. Return prior hooks value."""

    span = _compat_table_span(text, vendor)
    if span is None:
        return text, None
    start, end = span
    block = text[start:end]
    assignment = _compat_hooks_assignment(block)
    previous = assignment[2] if assignment is not None else ""
    if assignment is not None:
        line_start, line_end, _, newline = assignment
        block = block[:line_start] + "hooks = false" + newline + block[line_end:]
    else:
        header = f"[compat.{vendor}]"
        block = block.replace(header, header + "\nhooks = false", 1)
    return text[:start] + block + text[end:], previous


def prepare_managed_config_text(
    existing_text: str,
    hook_command: str,
    *,
    saved_prior_hooks: Mapping[str, str | None] | None = None,
) -> tuple[str, dict[str, str | None]]:
    """Merge Guard's managed block without duplicating compat tables."""

    cleaned = remove_managed_block(existing_text)
    saved = dict(saved_prior_hooks or {})
    prior_hooks: dict[str, str | None] = {}
    emit_vendors: list[str] = []
    for vendor in FOREIGN_HOOK_COMPAT_VENDORS:
        if _compat_table_span(cleaned, vendor) is None:
            emit_vendors.append(vendor)
            prior_hooks[vendor] = saved.get(vendor)
            continue
        cleaned, previous = force_compat_hooks_false(cleaned, vendor)
        saved_value = saved.get(vendor)
        prior_hooks[vendor] = saved_value if saved_value is not None else previous
    managed_block = build_managed_config_block(hook_command, emit_compat_vendors=tuple(emit_vendors))
    merged = f"{cleaned.rstrip()}\n\n{managed_block}\n".lstrip()
    return merged, prior_hooks


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


def build_managed_config_block(
    hook_command: str = "",
    *,
    emit_compat_vendors: tuple[str, ...] = FOREIGN_HOOK_COMPAT_VENDORS,
) -> str:
    deny_lines = ",\n".join(f'  "{rule}"' for rule in MANAGED_DENY_RULES)
    lines = [
        GUARD_MANAGED_BEGIN,
        "# Permission rules below are managed by HOL Guard. Do not edit manually.",
        "[permission]",
        "deny = [",
        deny_lines,
        "]",
    ]
    compat = foreign_hook_compat_toml(emit_compat_vendors)
    if compat:
        lines.extend(["", compat])
    if hook_command.strip():
        command_hook = _toml_inline_command_hook(hook_command, timeout=GROK_PRETOOL_HOOK_TIMEOUT_SECONDS)
        observe_hook = _toml_inline_command_hook(hook_command, timeout=15)
        lines.extend(
            [
                "",
                "[[hooks.PreToolUse]]",
                f"hooks = [{command_hook}]",
                "",
                "[[hooks.UserPromptSubmit]]",
                f"hooks = [{observe_hook}]",
                "",
                "[[hooks.SubagentStart]]",
                f"hooks = [{observe_hook}]",
                "",
                "[[hooks.SessionStart]]",
                f"hooks = [{observe_hook}]",
            ]
        )
    lines.append(GUARD_MANAGED_END)
    return "\n".join(lines)


def remove_managed_block(text: str) -> str:
    pattern = re.compile(
        rf"^\s*{re.escape(GUARD_MANAGED_BEGIN)}.*?{re.escape(GUARD_MANAGED_END)}\s*\n?",
        re.MULTILINE | re.DOTALL,
    )
    cleaned = pattern.sub("", text)
    cleaned = re.sub(rf"^\s*#.*{re.escape(GUARD_MANAGED_MARKER)}.*$\n?", "", cleaned, flags=re.MULTILINE)
    return cleaned
