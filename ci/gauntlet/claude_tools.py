"""Which tools the Claude Code lane hands the CLI for one case.

A case that names its tools gets exactly those, because the request each tool
makes is what the case tests: reading a file with the Read tool is a different
request from spelling the same read in the shell. Cases that also list shell
commands add Bash to the named tools rather than replacing them.
"""

from __future__ import annotations

from .catalog import Scenario

# A full task leaves every step to the model, so Claude gets its ordinary coding tools.
FULL_TASK_CLAUDE_TOOLS = "Bash,Read,Write,Edit,Glob,Grep,TodoWrite"


_CLAUDE_TOOL_NAMES = {"bash": "Bash", "read": "Read", "write": "Write", "edit": "Edit"}


def claude_tools(scenario: Scenario) -> str:
    """The tools this lane hands the CLI for one case.

    A case that names its tools gets exactly those. Several also list shell
    commands, and granting Bash alone for them would leave the model unable to
    make the structured call the case exists to exercise, so the commands add
    Bash to the named tools rather than replacing them.
    """
    if scenario.oracle == "full-task":
        return FULL_TASK_CLAUDE_TOOLS
    if scenario.oracle == "home-copy-task":
        return "Bash,Read"
    if scenario.required_tools:
        granted = {_CLAUDE_TOOL_NAMES[tool] for tool in scenario.required_tools}
        if scenario.commands:
            granted.add("Bash")
        return ",".join(name for name in _CLAUDE_TOOL_NAMES.values() if name in granted)
    if scenario.commands:
        return "Bash"
    if scenario.oracle == "blocked-read":
        return "Read"
    return "Bash,Read,Write,Edit"
