"""Preview the one settings entry that adds Cloud actions to an AI tool.

Each supported AI tool keeps its MCP servers in one user-level file. The
preview reads that file and works out the single entry Guard would add or
change, named `hol-guard-cloud`. It renders the whole file as it would be
written and checks that, apart from that entry, it reads back exactly as
before: other servers, their environment values, Guard Local's own entries
and every unrelated setting. Guard's native runtime finds the file, reads it
within a size bound, renders the change and runs that check; this module only
asks it and shows the answer. Nothing is written here; cloud_actions_host_apply
asks the native runtime to write the rendered file.

The entry starts `hol-guard cloud-actions bridge <ai-tool>`, which the AI
tool launches like any local MCP server. The bridge obtains short-lived Cloud
actions access from this computer's `hol-guard connect` pairing each time it is
needed and keeps it in memory only, so the settings file never holds a
credential and the AI tool never signs in to Guard Cloud itself. Entries an
earlier alpha wrote, holding only the Guard Cloud address, are still
recognised so they can be replaced or put back.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, cast

CLOUD_ACTIONS_SERVER_NAME = "hol-guard-cloud"
_MAX_SETTINGS_BYTES = 32 * 1024 * 1024
_FEATURE: Final = "native-cloud-actions-host-config-v2"
_COMMAND: Final = "cloud-actions-host-config"
_TIMEOUT_SECONDS: Final = 30.0
# The rendered file, at most six times longer once escaped as JSON.
_PLAN_OUTPUT_LIMIT: Final = 6 * _MAX_SETTINGS_BYTES + 1024 * 1024
_SMALL_OUTPUT_LIMIT: Final = 1024 * 1024
# The only variables the native runtime reads to find an AI tool's own home.
_HOME_VARIABLES: Final = ("CLAUDE_CONFIG_DIR", "CODEX_HOME")
_NATIVE_UNAVAILABLE: Final = "Guard's native runtime is not available, so the settings file was left as it is."
_PLAN_ACTIONS: Final = frozenset(
    {"create_file", "add", "update", "unchanged", "already_configured", "conflict", "unreadable"}
)

PlanAction = Literal["create_file", "add", "update", "unchanged", "already_configured", "conflict", "unreadable"]


class AiToolNotSupportedError(ValueError):
    """The named AI tool has no Cloud actions setup."""


class HostConfigNativeUnavailableError(ValueError):
    """Guard's native runtime could not render the settings change."""


@dataclass(frozen=True, slots=True)
class _AiTool:
    slug: str
    display_name: str
    file_format: Literal["json", "toml"]
    table: str
    typed: bool
    reload_hint: str


_AI_TOOLS: dict[str, _AiTool] = {
    "claude-code": _AiTool(
        slug="claude-code",
        display_name="Claude Code",
        file_format="json",
        table="mcpServers",
        typed=True,
        reload_hint="Start a new Claude Code session to load hol-guard-cloud.",
    ),
    "codex": _AiTool(
        slug="codex",
        display_name="Codex",
        file_format="toml",
        table="mcp_servers",
        typed=False,
        reload_hint="Start a new Codex session to load hol-guard-cloud.",
    ),
    "cursor": _AiTool(
        slug="cursor",
        display_name="Cursor",
        file_format="json",
        table="mcpServers",
        typed=False,
        reload_hint="In Cursor, open Settings > MCP and turn hol-guard-cloud on.",
    ),
}

SUPPORTED_AI_TOOLS = tuple(_AI_TOOLS)


@dataclass(frozen=True, slots=True)
class HostConfigPlan:
    ai_tool: str
    display_name: str
    path: Path
    action: PlanAction
    url: str
    entry: Mapping[str, object]
    other_entries: int
    reload_hint: str
    previous_url: str | None = None
    configured_as: tuple[str, ...] = ()
    problem: str | None = None
    before_sha256: str | None = None
    after: bytes | None = None

    @property
    def server_name(self) -> str:
        return CLOUD_ACTIONS_SERVER_NAME

    @property
    def changes(self) -> bool:
        return self.action in {"create_file", "add", "update"}

    @property
    def entry_lines(self) -> tuple[str, ...]:
        """The Guard entry in the file's own syntax; no other entry is shown."""

        tool = _AI_TOOLS[self.ai_tool]
        if tool.file_format == "toml":
            return (f"[{tool.table}.{CLOUD_ACTIONS_SERVER_NAME}]", *_toml_lines(self.entry))
        entry = json.dumps(_wanted_entry(tool, self.entry), ensure_ascii=False)
        return (f'"{tool.table}": {{ "{CLOUD_ACTIONS_SERVER_NAME}": {entry} }}',)


def bridge_entry(ai_tool: str, *, guard_home: Path) -> dict[str, object]:
    """The entry that launches the Cloud actions bridge for `ai_tool` with this Guard home."""

    from ..stable_guard_cli import guard_cli_launcher

    tool = _tool(ai_tool)
    prefix = [] if getattr(sys, "frozen", False) else ["-m", "codex_plugin_scanner.cli", "guard"]
    args = [*prefix, *_BRIDGE_ARGS, tool.slug, "--guard-home", str(guard_home)]
    return {"command": guard_cli_launcher(), "args": args}


_BRIDGE_ARGS = ("cloud-actions", "bridge")


def settings_path(ai_tool: str, *, home: Path, environ: Mapping[str, str] | None) -> Path:
    """The user-level settings file the AI tool reads its MCP servers from.

    `environ` is None when the caller named the home folder explicitly; the AI
    tool's own home variables are then ignored. The native runtime derives the
    path; HostConfigNativeUnavailableError when it cannot be asked.
    """

    _ = _tool(ai_tool)
    answer = host_native_answer(
        {
            "op": "settings_path",
            "ai_tool": ai_tool,
            "home": os.path.abspath(home),
            "environ": None
            if environ is None
            else {name: environ[name] for name in _HOME_VARIABLES if name in environ},
        }
    )
    path = answer.get("path") if answer is not None else None
    if not isinstance(path, str):
        raise HostConfigNativeUnavailableError(_NATIVE_UNAVAILABLE)
    return Path(path)


def plan_host_config(ai_tool: str, *, path: Path, entry: Mapping[str, object], url: str) -> HostConfigPlan:
    """Work out the change to `path`; never writes.

    `entry` is what Guard writes (see bridge_entry); `url` is the Cloud actions
    server it reaches, used to spot another entry already connected to it.
    """

    tool = _tool(ai_tool)
    wanted = dict(entry)

    def plan(action: PlanAction, **fields: object) -> HostConfigPlan:
        return HostConfigPlan(
            ai_tool=tool.slug,
            display_name=tool.display_name,
            path=path,
            action=action,
            url=url,
            entry=wanted,
            reload_hint=tool.reload_hint,
            **fields,  # pyright: ignore[reportArgumentType]
        )

    request = {"op": "plan_file", "ai_tool": tool.slug, "path": os.path.abspath(path), "entry": wanted, "url": url}
    answer = host_native_answer(request, output_limit=_PLAN_OUTPUT_LIMIT)
    action = answer.get("action") if answer is not None else None
    if answer is None or action not in _PLAN_ACTIONS:
        return plan("unreadable", other_entries=0, problem=_NATIVE_UNAVAILABLE)
    after = answer.get("after")
    before_sha256 = answer.get("before_sha256")
    previous_url = answer.get("previous_url")
    problem = answer.get("problem")
    others = answer.get("other_entries")
    configured_as = answer.get("configured_as")
    return plan(
        cast(PlanAction, action),
        other_entries=others if isinstance(others, int) else 0,
        previous_url=previous_url if isinstance(previous_url, str) else None,
        configured_as=tuple(name for name in configured_as if isinstance(name, str))
        if isinstance(configured_as, list)
        else (),
        problem=problem if isinstance(problem, str) else None,
        before_sha256=before_sha256 if isinstance(before_sha256, str) else None,
        after=after.encode() if isinstance(after, str) else None,
    )


def host_native_answer(
    request: Mapping[str, object], *, output_limit: int = _SMALL_OUTPUT_LIMIT
) -> dict[str, object] | None:
    """The native runtime's answer to one settings-file request; None when it cannot be asked."""

    from ..mdm.runtime_request import runtime_answer

    try:
        encoded = json.dumps(request, sort_keys=True)
    except (TypeError, ValueError):
        return None
    return runtime_answer(_FEATURE, _COMMAND, encoded, output_limit=output_limit, timeout_seconds=_TIMEOUT_SECONDS)


def supported_tool(ai_tool: str) -> None:
    """Raise AiToolNotSupportedError unless `ai_tool` has a Cloud actions setup."""

    _ = _tool(ai_tool)


def _tool(ai_tool: str) -> _AiTool:
    tool = _AI_TOOLS.get(ai_tool)
    if tool is None:
        raise AiToolNotSupportedError(ai_tool)
    return tool


def _wanted_entry(tool: _AiTool, fields: Mapping[str, object]) -> dict[str, object]:
    if not tool.typed:
        return dict(fields)
    return {"type": "http" if "url" in fields else "stdio", **fields}


def _toml_lines(fields: Mapping[str, object]) -> tuple[str, ...]:
    # JSON string and array syntax is valid TOML for the plain strings Guard writes.
    return tuple(f"{key} = {json.dumps(value)}" for key, value in fields.items())


__all__ = [
    "CLOUD_ACTIONS_SERVER_NAME",
    "SUPPORTED_AI_TOOLS",
    "AiToolNotSupportedError",
    "HostConfigNativeUnavailableError",
    "HostConfigPlan",
    "bridge_entry",
    "host_native_answer",
    "plan_host_config",
    "settings_path",
    "supported_tool",
]
