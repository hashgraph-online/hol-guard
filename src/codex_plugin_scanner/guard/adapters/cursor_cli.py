"""Cursor CLI entry-point resolution for Guard launch shims."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from .base import HarnessContext, _resolve_command, _run_command_probe

CURSOR_AGENT_EXECUTABLE = "cursor-agent"
CURSOR_EXECUTABLE = "cursor"
CURSOR_AGENT_SUBCOMMAND = "agent"
CURSOR_CLI_SHIM_COMMANDS = ("guard-cursor-agent", "guard-cursor")


@dataclass(frozen=True, slots=True)
class CursorCliLaunchEntry:
    """Resolved local Cursor CLI agent launcher."""

    executable: str
    prefix_args: tuple[str, ...] = ()
    launch_mode: str = "cursor-agent"

    def launch_argv(self, passthrough_args: list[str]) -> list[str]:
        args = list(passthrough_args)
        if not self.prefix_args and args and args[0] == CURSOR_AGENT_SUBCOMMAND:
            args = args[1:]
        if self.prefix_args and args and args[0] == self.prefix_args[0]:
            return [self.executable, *args]
        return [self.executable, *self.prefix_args, *args]


@lru_cache(maxsize=8)
def cursor_agent_subcommand_available(cursor_path: str) -> bool:
    probe = _run_command_probe([cursor_path, CURSOR_AGENT_SUBCOMMAND, "--help"], timeout_seconds=5)
    return probe.get("ok") is True or probe.get("return_code") == 0


def resolve_cursor_cli_entry(context: HarnessContext) -> CursorCliLaunchEntry | None:
    del context
    agent_path = _resolve_command(CURSOR_AGENT_EXECUTABLE)
    if agent_path is not None:
        return CursorCliLaunchEntry(executable=agent_path, launch_mode="cursor-agent")
    cursor_path = _resolve_command(CURSOR_EXECUTABLE)
    if cursor_path is not None and cursor_agent_subcommand_available(cursor_path):
        return CursorCliLaunchEntry(
            executable=cursor_path,
            prefix_args=(CURSOR_AGENT_SUBCOMMAND,),
            launch_mode="cursor-agent-subcommand",
        )
    return None


def cursor_cli_command_available(context: HarnessContext) -> bool:
    return resolve_cursor_cli_entry(context) is not None


def cursor_cli_shim_installed(context: HarnessContext) -> bool:
    shim_dir = context.guard_home / "bin"
    return any((shim_dir / command).exists() for command in CURSOR_CLI_SHIM_COMMANDS)


def cursor_cli_detected(context: HarnessContext) -> bool:
    if cursor_cli_command_available(context):
        return True
    return cursor_cli_shim_installed(context)


__all__ = [
    "CURSOR_AGENT_EXECUTABLE",
    "CURSOR_AGENT_SUBCOMMAND",
    "CURSOR_CLI_SHIM_COMMANDS",
    "CURSOR_EXECUTABLE",
    "CursorCliLaunchEntry",
    "cursor_agent_subcommand_available",
    "cursor_cli_command_available",
    "cursor_cli_detected",
    "cursor_cli_shim_installed",
    "resolve_cursor_cli_entry",
]
