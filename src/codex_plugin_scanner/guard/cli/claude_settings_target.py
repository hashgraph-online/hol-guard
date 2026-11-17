"""Where Claude Code hooks go: ask the native runtime, then show its answer.

The values are paths and messages from the native ``install_target`` op. They
are shown literally: a directory named ``[red]`` must not become Rich markup.
"""

from __future__ import annotations

import os
import re
import shlex

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from ..adapters.base import HarnessContext
from ..native_runner_authority import NativeRunnerAuthorityError


def claude_settings_target(context: HarnessContext) -> dict[str, object]:
    """The native answer for where Claude Code hooks go, shown before anything is written."""
    from ..adapters.native_harness import ask

    try:
        return ask("install_target", context, harness="claude-code")
    except (NativeRunnerAuthorityError, OSError, ValueError) as error:
        return {"unavailable": True, "reason": str(error) or type(error).__name__}


_POWERSHELL_PLAIN = re.compile(r"[A-Za-z0-9_./:\\-]+")
# PowerShell ends a single-quoted string at the ASCII quote and at the
# typographic quotes U+2018 to U+201B, so each one is doubled.
_POWERSHELL_QUOTES = re.compile("(['\u2018\u2019\u201a\u201b])")


def _powershell_word(word: str) -> str:
    """A PowerShell literal: only single quotes stop `$` and backtick expansion."""
    if _POWERSHELL_PLAIN.fullmatch(word):
        return word
    return "'" + _POWERSHELL_QUOTES.sub(r"\1\1", word) + "'"


def _command_text(words: list[str], *, windows: bool = os.name == "nt") -> str:
    """The command for the shell that will run it: PowerShell on Windows, POSIX sh elsewhere."""
    return " ".join(_powershell_word(word) for word in words) if windows else shlex.join(words)


def _lines(target: dict[str, object]) -> list[str]:
    lines = [f"Writes: {target.get('settings_path')} ({target.get('scope')} settings)"]
    workspace_note = target.get("workspace_note")
    if isinstance(workspace_note, str) and workspace_note:
        lines.append(workspace_note)
    precedence = target.get("precedence")
    if isinstance(precedence, list):
        lines.append("Claude Code reads, highest precedence first:")
        for layer in precedence:
            if isinstance(layer, dict):
                marker = "  * " if layer.get("guard_writes") else "  - "
                lines.append(f"{marker}{layer.get('scope')}: {layer.get('path')}")
    for key in ("hooks_merge", "background"):
        value = target.get(key)
        if isinstance(value, str) and value:
            lines.append(value)
    rollback = target.get("rollback")
    if isinstance(rollback, dict):
        command = rollback.get("command")
        if isinstance(command, list):
            undo = _command_text([str(part) for part in command])
            label = "Undo (PowerShell)" if os.name == "nt" else "Undo"
            lines.append(f"{label}: {undo}. {rollback.get('effect', '')}".rstrip())
    overrides = target.get("hook_overrides")
    if isinstance(overrides, list):
        lines.extend(f"Warning: {item.get('message')}" for item in overrides if isinstance(item, dict))
    return lines


def render_settings_target(console: Console, target: object) -> None:
    if not isinstance(target, dict):
        return
    if target.get("unavailable"):
        body = Text(f"Guard could not read where Claude Code hooks would go: {target.get('reason')}")
        console.print(Panel(body, title="Claude Code settings", border_style="red"))
        return
    overrides = target.get("hook_overrides")
    border = "red" if isinstance(overrides, list) and overrides else "cyan"
    console.print(Panel(Text("\n".join(_lines(target))), title="Claude Code settings", border_style=border))
