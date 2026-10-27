"""Command catalog and argv matching for custom extensions."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

LocalCliCommandState = Literal["inherit", "allow", "review", "block"]

ROOT_COMMAND_ID = "root"
OTHER_COMMAND_ID = "other"
_COMMAND_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,40}$")
MAX_LOCAL_CLI_COMMANDS = 101
_MAX_COMMANDS = MAX_LOCAL_CLI_COMMANDS
_MAX_DEPTH = 4


@dataclass(frozen=True, slots=True)
class LocalCliCommand:
    """One discovered or synthetic command on a custom extension."""

    command_id: str
    name: str
    usage: str
    description: str
    parent_id: str | None = None

    def to_dict(self, *, state: LocalCliCommandState = "inherit") -> dict[str, object]:
        return {
            "command_id": self.command_id,
            "name": self.name,
            "usage": self.usage,
            "description": self.description,
            "parent_id": self.parent_id,
            "state": state,
        }


def is_local_cli_command_id(value: str) -> bool:
    if value in {ROOT_COMMAND_ID, OTHER_COMMAND_ID}:
        return True
    parts = value.split(".")
    return 1 <= len(parts) <= _MAX_DEPTH and all(_COMMAND_NAME.fullmatch(part) for part in parts)


def slug_local_cli_command_id(name: str) -> str:
    """Turn an MCP tool name or CLI token into a catalog command id."""

    stripped = name.strip()
    if stripped not in {ROOT_COMMAND_ID, OTHER_COMMAND_ID} and is_local_cli_command_id(stripped):
        return stripped
    compact = "".join(ch.lower() if ch.isalnum() else "-" for ch in stripped).strip("-")
    compact = "-".join(part for part in compact.split("-") if part)
    digest = hashlib.sha256(stripped.encode("utf-8")).hexdigest()[:8]
    base = (compact or "tool")[:31]
    candidate = f"{base}-{digest}"
    return candidate if is_local_cli_command_id(candidate) else OTHER_COMMAND_ID


def is_local_cli_command_state(value: object) -> bool:
    return value in {"inherit", "allow", "review", "block"}


def local_cli_command_state(value: object) -> LocalCliCommandState | None:
    if value == "inherit":
        return "inherit"
    if value == "allow":
        return "allow"
    if value == "block":
        return "block"
    if value == "review":
        return "review"
    return None


def default_local_cli_commands(tool_name: str) -> tuple[LocalCliCommand, ...]:
    label = tool_name.strip() or "tool"
    return (
        LocalCliCommand(
            command_id=ROOT_COMMAND_ID,
            name=label,
            usage=label,
            description=f"Run {label} without a subcommand.",
        ),
        LocalCliCommand(
            command_id=OTHER_COMMAND_ID,
            name="Other commands",
            usage=f"{label} …",
            description="Any other command from this file that --help did not list.",
        ),
    )


def merge_discovered_commands(
    tool_name: str,
    discovered: Sequence[LocalCliCommand],
) -> tuple[LocalCliCommand, ...]:
    root, other = default_local_cli_commands(tool_name)
    merged: list[LocalCliCommand] = [root]
    seen = {ROOT_COMMAND_ID, OTHER_COMMAND_ID}
    for command in discovered:
        if not is_local_cli_command_id(command.command_id):
            continue
        if command.command_id in seen:
            continue
        seen.add(command.command_id)
        merged.append(command)
        if len(merged) >= _MAX_COMMANDS - 1:
            break
    merged.append(other)
    return tuple(merged)
