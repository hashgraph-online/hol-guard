"""Preview the one settings entry that adds Cloud actions to an AI tool.

Each supported AI tool keeps its MCP servers in one user-level file. The
preview reads that file and works out the single entry Guard would add or
change, named `hol-guard-cloud`. It renders the whole file as it would be
written and checks that, apart from that entry, it reads back exactly as
before: other servers, their environment values, Guard Local's own entries
and every unrelated setting. Nothing is written here; cloud_actions_host_apply
writes the rendered file.

The entry starts `hol-guard cloud-actions bridge <ai-tool>`, which the AI
tool launches like any local MCP server. The bridge obtains short-lived Cloud
actions access from this computer's `hol-guard connect` pairing each time it is
needed and keeps it in memory only, so the settings file never holds a
credential and the AI tool never signs in to Guard Cloud itself. Entries an
earlier alpha wrote, holding only the Guard Cloud address, are still
recognised so they can be replaced or put back.
"""

from __future__ import annotations

import importlib
import json
import sys
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .cloud_actions_host_config_toml import UnreadableSettingsError as _UnreadableError
from .cloud_actions_host_config_toml import render_toml_edit, render_toml_removal

CLOUD_ACTIONS_SERVER_NAME = "hol-guard-cloud"
_MAX_SETTINGS_BYTES = 32 * 1024 * 1024

PlanAction = Literal["create_file", "add", "update", "unchanged", "already_configured", "conflict", "unreadable"]


class AiToolNotSupportedError(ValueError):
    """The named AI tool has no Cloud actions setup."""


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
    before: bytes | None = None
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
    tool's own home variables are then ignored.
    """

    tool = _tool(ai_tool)
    env = environ if environ is not None else {}
    if tool.slug == "claude-code":
        base = env.get("CLAUDE_CONFIG_DIR", "").strip()
        return (Path(base).expanduser() if base else home) / ".claude.json"
    if tool.slug == "codex":
        base = env.get("CODEX_HOME", "").strip()
        return (Path(base).expanduser() if base else home / ".codex") / "config.toml"
    return home / ".cursor" / "mcp.json"


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

    try:
        before = _read_bounded(path)
    except _UnreadableError as error:
        return plan("unreadable", other_entries=0, problem=str(error))
    if before is None:
        after = _render_new(tool, wanted)
        return plan("create_file", other_entries=0, after=after)
    try:
        document = _parse(tool, before)
        servers = _servers(tool, document)
    except _UnreadableError as error:
        return plan("unreadable", other_entries=0, problem=str(error), before=before)
    others = {name: value for name, value in servers.items() if name != CLOUD_ACTIONS_SERVER_NAME}
    existing = servers.get(CLOUD_ACTIONS_SERVER_NAME)
    if existing is not None:
        current = _guard_fields(tool, existing)
        if current is None:
            return plan(
                "conflict",
                other_entries=len(others),
                problem=f"An entry named {CLOUD_ACTIONS_SERVER_NAME} already exists with other settings.",
                before=before,
            )
        if current == wanted:
            return plan("unchanged", other_entries=len(others), before=before, after=before)
        current_url = current.get("url")
        previous_url = _display_url(current_url) if isinstance(current_url, str) else None
    else:
        previous_url = None
    # Another entry already reaching this server is left as the one in use,
    # so pointing ours at it too would not add a second connection.
    same_server = tuple(sorted(name for name, value in others.items() if _points_at(value, url)))
    if same_server:
        return plan("already_configured", other_entries=len(others), configured_as=same_server, before=before)
    try:
        after = _render_edit(tool, before, wanted)
        _check_only_guard_entry_changed(tool, before, after, wanted)
    except UnicodeEncodeError:
        problem = "The settings file holds text that cannot be written back unchanged."
        return plan("unreadable", other_entries=len(others), problem=problem, before=before)
    except _UnreadableError as error:
        return plan("unreadable", other_entries=len(others), problem=str(error), before=before)
    action: PlanAction = "update" if existing is not None else "add"
    return plan(action, other_entries=len(others), previous_url=previous_url, before=before, after=after)


def render_entry_undo(
    ai_tool: str, *, current: bytes, written: Mapping[str, object], prior: bytes | None
) -> tuple[bytes, bool]:
    """`current` with Guard's entry put back as it was in `prior`, or removed; True when removed.

    Only Guard's entry changes, and only while it is still exactly `written`;
    anything else edited since stays as it is. Raises ValueError when that
    cannot be done exactly.
    """

    tool = _tool(ai_tool)
    try:
        entry = _servers(tool, _parse(tool, current)).get(CLOUD_ACTIONS_SERVER_NAME)
        if entry is None or _guard_fields(tool, entry) != dict(written):
            raise _UnreadableError(f"The {CLOUD_ACTIONS_SERVER_NAME} entry changed after Guard wrote it.")
        prior_document = _parse(tool, prior) if prior is not None else {}
        prior_entry = _servers(tool, prior_document).get(CLOUD_ACTIONS_SERVER_NAME)
        if prior_entry is not None:
            prior_fields = _guard_fields(tool, prior_entry)
            if prior_fields is None:
                raise _UnreadableError(f"The earlier {CLOUD_ACTIONS_SERVER_NAME} entry was not one Guard wrote.")
            after = _render_edit(tool, current, prior_fields)
            _check_only_guard_entry_changed(tool, current, after, prior_fields)
            return after, False
        after = _render_removal(tool, current, drop_empty_table=tool.table not in prior_document)
        _check_guard_entry_removed(tool, current, after)
        return after, True
    except UnicodeEncodeError:
        raise ValueError("The settings file holds text that cannot be written back unchanged.") from None
    except _UnreadableError as error:
        raise ValueError(str(error)) from None


def _tool(ai_tool: str) -> _AiTool:
    tool = _AI_TOOLS.get(ai_tool)
    if tool is None:
        raise AiToolNotSupportedError(ai_tool)
    return tool


def _wanted_entry(tool: _AiTool, fields: Mapping[str, object]) -> dict[str, object]:
    if not tool.typed:
        return dict(fields)
    return {"type": "http" if "url" in fields else "stdio", **fields}


def _guard_fields(tool: _AiTool, entry: Mapping[str, object]) -> dict[str, object] | None:
    """The fields of an entry shaped exactly like one Guard writes, else None.

    That is the bridge launch for this AI tool, or the address-only entry an
    earlier alpha wrote.
    """

    fields = {key: value for key, value in entry.items() if key != "type"}
    if tool.typed:
        if entry.get("type") != ("http" if "url" in fields else "stdio"):
            return None
    elif "type" in entry:
        return None
    if set(fields) == {"url"}:
        return fields if isinstance(fields["url"], str) else None
    if set(fields) != {"command", "args"}:
        return None
    command, args = fields["command"], fields["args"]
    if not isinstance(command, str) or not isinstance(args, list):
        return None
    values: list[str] = [value for value in args if isinstance(value, str)]  # pyright: ignore[reportUnknownVariableType]
    if len(values) != len(args) or not _names_bridge(values, tool.slug):  # pyright: ignore[reportUnknownArgumentType]
        return None
    return {"command": command, "args": values}


def _names_bridge(args: list[str], ai_tool: str) -> bool:
    wanted = [*_BRIDGE_ARGS, ai_tool]
    return any(args[index : index + len(wanted)] == wanted for index in range(len(args)))


def _toml_lines(fields: Mapping[str, object]) -> tuple[str, ...]:
    # JSON string and array syntax is valid TOML for the plain strings Guard writes.
    return tuple(f"{key} = {json.dumps(value)}" for key, value in fields.items())


def _points_at(entry: object, url: str) -> bool:
    if not isinstance(entry, Mapping):
        return False
    value = entry.get("url")  # pyright: ignore[reportUnknownMemberType]
    return isinstance(value, str) and value.rstrip("/") == url.rstrip("/")


def _display_url(value: str) -> str | None:
    """Show only scheme, host and path of an address Guard did not write."""

    try:
        parts = urllib.parse.urlsplit(value)
        port = parts.port
    except ValueError:
        return None
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    if port is not None:
        host = f"{host}:{port}"
    return urllib.parse.urlunsplit((parts.scheme, host, parts.path, "", ""))


def _read_bounded(path: Path) -> bytes | None:
    try:
        if not path.exists():
            return None
        # Also keeps a named pipe or device from blocking the read.
        if not path.is_file():
            raise _UnreadableError(f"{path} is not a file.")
        if path.stat().st_size > _MAX_SETTINGS_BYTES:
            raise _UnreadableError(f"{path} is too large to change safely.")
        return path.read_bytes()
    except OSError as error:
        raise _UnreadableError(f"{path} could not be read ({error.strerror or 'error'}).") from None


def read_settings_bytes(path: Path) -> bytes | None:
    """The file's bytes, or None when it does not exist; ValueError when it cannot be read safely."""

    try:
        return _read_bounded(path)
    except _UnreadableError as error:
        raise ValueError(str(error)) from None


def _parse(tool: _AiTool, raw: bytes) -> dict[str, object]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise _UnreadableError("The settings file is not UTF-8 text.") from None
    if tool.file_format == "toml":
        tomllib = importlib.import_module("tomllib" if sys.version_info >= (3, 11) else "tomli")
        try:
            return tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            raise _UnreadableError("The settings file is not valid TOML.") from None
    if not text.strip():
        return {}
    try:
        payload = json.loads(text, object_pairs_hook=_refuse_duplicate_keys)
    except _UnreadableError:
        raise
    except ValueError:
        raise _UnreadableError("The settings file is not valid JSON.") from None
    if not isinstance(payload, dict):
        raise _UnreadableError("The settings file does not hold a JSON object.")
    return payload  # pyright: ignore[reportUnknownVariableType]


def _refuse_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    # Rewriting would silently keep only the last of the repeated keys.
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _UnreadableError("The settings file repeats a key, so rewriting it could change what it means.")
        result[key] = value
    return result


def _servers(tool: _AiTool, document: Mapping[str, object]) -> dict[str, Mapping[str, object]]:
    servers = document.get(tool.table)
    if servers is None:
        return {}
    if not isinstance(servers, Mapping):
        raise _UnreadableError(f"{tool.table} in the settings file is not a table of servers.")
    result: dict[str, Mapping[str, object]] = {}
    for name, value in servers.items():  # pyright: ignore[reportUnknownVariableType]
        if isinstance(name, str):
            result[name] = value if isinstance(value, Mapping) else {}  # pyright: ignore[reportUnknownArgumentType]
    return result


def _render_new(tool: _AiTool, fields: Mapping[str, object]) -> bytes:
    if tool.file_format == "toml":
        return "\n".join((f"[{tool.table}.{CLOUD_ACTIONS_SERVER_NAME}]", *_toml_lines(fields), "")).encode()
    payload = {tool.table: {CLOUD_ACTIONS_SERVER_NAME: _wanted_entry(tool, fields)}}
    return (json.dumps(payload, indent=2, ensure_ascii=False) + "\n").encode()


def _render_edit(tool: _AiTool, before: bytes, fields: Mapping[str, object]) -> bytes:
    text = before.decode("utf-8")
    if tool.file_format == "toml":
        return render_toml_edit(tool.table, CLOUD_ACTIONS_SERVER_NAME, text, fields).encode()
    document = json.loads(text) if text.strip() else {}
    servers = document.get(tool.table)
    if not isinstance(servers, dict):
        servers = {}
        document[tool.table] = servers
    servers[CLOUD_ACTIONS_SERVER_NAME] = _wanted_entry(tool, fields)
    return _dump_json_like(document, text)


def _dump_json_like(document: object, text: str) -> bytes:
    """Render `document` with the indentation and line endings of `text`."""

    newline = "\r\n" if "\r\n" in text else "\n"
    rendered = json.dumps(document, indent=_json_indent(text), ensure_ascii=False)
    if newline != "\n":
        rendered = rendered.replace("\n", newline)
    if text.endswith(("\n", "\r\n")) or not text.strip():
        rendered += newline
    return rendered.encode()


def _render_removal(tool: _AiTool, current: bytes, *, drop_empty_table: bool) -> bytes:
    text = current.decode("utf-8")
    if tool.file_format == "toml":
        return render_toml_removal(
            tool.table, CLOUD_ACTIONS_SERVER_NAME, text, drop_empty_table=drop_empty_table
        ).encode()
    document = json.loads(text)
    servers = document[tool.table]
    del servers[CLOUD_ACTIONS_SERVER_NAME]
    if not servers and drop_empty_table:
        del document[tool.table]
    return _dump_json_like(document, text)


def _json_indent(text: str) -> int | str:
    for line in text.splitlines():
        stripped = line.lstrip(" \t")
        if stripped and stripped != line:
            prefix = line[: len(line) - len(stripped)]
            return prefix if "\t" in prefix else len(prefix)
    return 2


def _check_guard_entry_removed(tool: _AiTool, before: bytes, after: bytes) -> None:
    old = _parse(tool, before)
    new = _parse(tool, after)
    if CLOUD_ACTIONS_SERVER_NAME in _servers(tool, new):
        raise _UnreadableError("Guard could not edit the settings file without changing other settings.")
    if _without_guard_entry(tool, new) != _without_guard_entry(tool, old):
        raise _UnreadableError("Guard could not edit the settings file without changing other settings.")


def _check_only_guard_entry_changed(tool: _AiTool, before: bytes, after: bytes, fields: Mapping[str, object]) -> None:
    """Refuse a rendering that changes anything but Guard's own entry."""

    old = _parse(tool, before)
    new = _parse(tool, after)
    new_servers = new.get(tool.table)
    if not isinstance(new_servers, dict) or new_servers.get(CLOUD_ACTIONS_SERVER_NAME) != _wanted_entry(tool, fields):
        raise _UnreadableError("Guard could not edit the settings file without changing other settings.")
    if _without_guard_entry(tool, new) != _without_guard_entry(tool, old):
        raise _UnreadableError("Guard could not edit the settings file without changing other settings.")


def _without_guard_entry(tool: _AiTool, document: dict[str, object]) -> dict[str, object]:
    rest = dict(document)
    servers = rest.get(tool.table)
    if isinstance(servers, dict):
        remaining = {key: value for key, value in servers.items() if key != CLOUD_ACTIONS_SERVER_NAME}  # pyright: ignore[reportUnknownVariableType]
        if remaining:
            rest[tool.table] = remaining
        else:
            rest.pop(tool.table)
    return rest


__all__ = [
    "CLOUD_ACTIONS_SERVER_NAME",
    "SUPPORTED_AI_TOOLS",
    "AiToolNotSupportedError",
    "HostConfigPlan",
    "bridge_entry",
    "plan_host_config",
    "read_settings_bytes",
    "render_entry_undo",
    "settings_path",
]
