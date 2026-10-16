"""Cursor hook event names and the preToolUse matcher Guard relies on for file changes."""

from __future__ import annotations

import re

# Events cursor-agent 2026.10.01 accepts. Cursor ignores the whole hooks.json when
# it names any other event, so one unknown key silently disables every hook.
CURSOR_SUPPORTED_HOOK_EVENTS = frozenset(
    {
        "beforeShellExecution",
        "beforeMCPExecution",
        "afterShellExecution",
        "afterMCPExecution",
        "beforeReadFile",
        "afterFileEdit",
        "beforeTabFileRead",
        "afterTabFileEdit",
        "stop",
        "beforeSubmitPrompt",
        "afterAgentResponse",
        "afterAgentThought",
        "sessionStart",
        "sessionEnd",
        "preCompact",
        "subagentStart",
        "subagentStop",
        "preToolUse",
        "postToolUse",
        "postToolUseFailure",
        "workspaceOpen",
    }
)
# Cursor has no pre-write event; its native write, edit and delete tools reach preToolUse.
# The matcher is a regex on tool_name, so shell, MCP and read calls keep their own hooks.
CURSOR_FILE_MUTATION_TOOLS = ("Write", "Edit", "StrReplace", "MultiEdit", "Delete")
CURSOR_FILE_MUTATION_TOOL_MATCHER = "^(" + "|".join(CURSOR_FILE_MUTATION_TOOLS) + ")$"


def unsupported_cursor_hook_events(hooks: dict[str, object]) -> list[str]:
    """Event keys Cursor would reject, which would disable every configured hook."""

    return sorted(str(event) for event in hooks if event not in CURSOR_SUPPORTED_HOOK_EVENTS)


def cursor_entry_guards_file_mutations(entry: dict[str, object]) -> bool:
    """Whether a preToolUse entry fails closed and its matcher selects every file mutation tool."""

    if entry.get("failClosed") is not True:
        return False
    matcher = entry.get("matcher")
    if matcher is None or matcher in ("", "*"):
        return True
    if not isinstance(matcher, str):
        return False
    try:
        pattern = re.compile(matcher)
    except re.error:
        return False
    return all(pattern.search(tool) for tool in CURSOR_FILE_MUTATION_TOOLS)
