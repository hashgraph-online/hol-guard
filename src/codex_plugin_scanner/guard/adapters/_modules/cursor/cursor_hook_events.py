"""The preToolUse matchers Guard relies on for Cursor file changes."""

from __future__ import annotations

import re

# Cursor has no pre-write event; its native write, edit and delete tools reach preToolUse.
# The matcher is a regex on tool_name, so shell, MCP and read calls keep their own hooks.
CURSOR_FILE_MUTATION_TOOLS = ("Write", "Edit", "StrReplace", "MultiEdit", "Delete")
CURSOR_FILE_MUTATION_TOOL_MATCHER = "^(" + "|".join(CURSOR_FILE_MUTATION_TOOLS) + ")$"
# Outside Windows preToolUse also takes Shell: Cursor applies its updated_input before
# beforeShellExecution runs, so a test call can move into Guard's contained sink. That
# probe only ever allows; beforeShellExecution stays the shell call's review.
CURSOR_SHELL_ROUTE_TOOL_MATCHER = "^(" + "|".join((*CURSOR_FILE_MUTATION_TOOLS, "Shell")) + ")$"


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
