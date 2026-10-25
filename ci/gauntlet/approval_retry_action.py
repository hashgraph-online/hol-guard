"""The action an approval covers, for a shell command and for a file tool.

An approval row binds one action, and the lane's question is whether the agent's own
next attempt at that action rides the approval already granted. A shell attempt names
its action with a program and a subcommand. A file-tool attempt has no command text at
all: its action is the tool and the file it names, which the review row carries as its
launch target and the decision row as its path. Both shapes resolve here so the lane
compares a grant with a later attempt the same way whichever tool made it.
"""

from __future__ import annotations

import shlex
from typing import Any

# The file tools whose repeated call this lane can judge. A call to one of them names
# its action by path, so an approval for it is matched on the path rather than on
# command text the request never carried.
FILE_TOOLS = frozenset({"read", "write", "edit"})

# The keys a harness spells the file a tool call names with. One list, so every lane
# reads the same field whether it holds a whole hook payload or a bare tool input.
PATH_KEYS = ("file_path", "path", "filePath")

# The fixture roots a Windows host spells with backslashes.
WORKSPACE_ROOTS = ("{{workspace}}\\", "{{home}}\\", ".\\")

# Options that carry their value as the next word, so that word is not the
# subcommand. Everything else a command places before its subcommand either is
# a flag or attaches its value with "=", both of which this skips on sight.
VALUE_OPTIONS = frozenset({"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path"})


def relative_path(value: str) -> str:
    """A fixture path as the workspace spells it, whichever host wrote it.

    Grants and decisions are redacted with the same replacements, so both carry the
    fixture roots as templates; stripping them here is what lets a grant target be
    compared with the path a later decision names.
    """
    if value.startswith(WORKSPACE_ROOTS):
        value = value.replace("\\", "/")
    for prefix in ("{{workspace}}/", "./"):
        value = value.removeprefix(prefix)
    return value


def input_path(fields: Any) -> str | None:
    """The file a tool call's own input names, in any harness's spelling."""
    if not isinstance(fields, dict):
        return None
    return next((value for key in PATH_KEYS if isinstance(value := fields.get(key), str) and value.strip()), None)


def pinned_file_tool(required_tools: tuple[str, ...]) -> str | None:
    """The one file tool a case requires, when its pinned action is a file-tool call.

    A pinned case claims a named tool runs on a named file. Without the tool, an allowed
    call any other file tool made on the same path would satisfy the pin, although the
    call the case pinned never happened.
    """
    tools = {str(tool).strip().lower() for tool in required_tools}
    return tools.pop() if len(tools) == 1 and tools <= FILE_TOOLS else None


def _names_a_path(word: str) -> bool:
    """Is this operand a filesystem location rather than a subcommand?

    A subcommand is a bare name the program defines. A path carries a separator, a
    leading dot or tilde, or a suffix, and none of the subcommands this lane has to tell
    apart ("status", "config", "run") does. Judged on the word's shape rather than on a
    list of programs, so a program this lane has never run is read the same way.
    """
    return word in {".", ".."} or word.startswith(("/", "./", "../", "~", ".")) or "/" in word or "." in word


def action_key(command: str) -> tuple[str, ...]:
    """The program and subcommand an attempt names.

    A reworded retry keeps both and changes only its options, so this is what ties a
    retry to the attempt the operator approved. Other work the review floor also stops —
    the status and config calls an agent or its harness makes to orient itself — names a
    different subcommand and is not counted against the approval.

    Options before the subcommand are skipped rather than counted, so a retry that adds
    one ("git -C dir status") still names the action the operator approved. So is an
    operand that names a filesystem location, because a program whose arguments are all
    paths has no subcommand at all: "ls -la" and "ls -la ." are one action worded twice,
    and reading the path as a subcommand would split them into two and let a second
    approval for the same outcome pass unseen.
    """
    try:
        words = shlex.split(command)
    except ValueError:
        words = command.split()
    if not words:
        return ()
    rest = iter(words[1:])
    for word in rest:
        if word in VALUE_OPTIONS:
            next(rest, None)
            continue
        if word.startswith("-") or _names_a_path(word):
            continue
        return (words[0], word)
    return (words[0],)


def _file_action(tool: Any, target: Any) -> tuple[str, ...]:
    """The action a file tool names, or no action when this is not one."""
    name = str(tool or "").strip().lower()
    if name not in FILE_TOOLS or not isinstance(target, str) or not target.strip():
        return ()
    return ("file", name, relative_path(target.strip()))


def decision_action(row: dict[str, Any]) -> tuple[str, ...]:
    """The action a Guard decision row records.

    Command text wins where the request carried any, so a Bash call is read exactly as
    before. A file tool carries none, and its path is the action. A row with neither —
    an apply_patch call, whose command the judge deliberately drops — resolves to no
    action and is left out of the retry comparison entirely.
    """
    command = row.get("command")
    if isinstance(command, str) and command.strip():
        return action_key(command)
    return _file_action(row.get("tool"), row.get("path"))


def grant_action(row: dict[str, Any]) -> tuple[str, ...]:
    """The action an approval grant covers.

    A review row for a shell command carries its command text; one for a file tool
    carries the file as its launch target and the tool as its artifact name, so the
    grant records that name and the target resolves against it.
    """
    target = str(row.get("target") or "")
    file_action = _file_action(row.get("tool"), target)
    return file_action or action_key(target)
