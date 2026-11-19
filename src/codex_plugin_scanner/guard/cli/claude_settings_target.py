"""Where Claude Code hooks go: ask the native runtime, then show its answer.

The native ``install_target`` op words the panel (``text``) and picks its
border. They are shown literally: a directory named ``[red]`` must not become Rich markup.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from ..harness_context import HarnessContext
from ..native_runner_authority import NativeRunnerAuthorityError


def claude_settings_target(context: HarnessContext) -> dict[str, object]:
    """The native answer for where Claude Code hooks go, shown before anything is written."""
    from ..native_harness_client import ask

    try:
        return ask("install_target", context, harness="claude-code")
    except (NativeRunnerAuthorityError, OSError, ValueError) as error:
        return {"unavailable": True, "reason": str(error) or type(error).__name__}


def render_settings_target(console: Console, target: object) -> None:
    if not isinstance(target, dict):
        return
    if target.get("unavailable"):
        body = Text(f"Guard could not read where Claude Code hooks would go: {target.get('reason')}")
        console.print(Panel(body, title="Claude Code settings", border_style="red"))
        return
    text, border = target.get("text"), target.get("border")
    if not isinstance(text, str) or not isinstance(border, str):
        return
    console.print(Panel(Text(text), title="Claude Code settings", border_style=border))
