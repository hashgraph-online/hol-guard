"""Preview the one settings entry that adds Cloud actions to an AI tool.

Each supported AI tool keeps its MCP servers in one user-level file. The
preview reads that file and works out the single entry Guard would add or
change, named `hol-guard-cloud`. It renders the whole file as it would be
written and checks that, apart from that entry, it reads back exactly as
before: other servers, their environment values, Guard Local's own entries
and every unrelated setting. Nothing is written here.

The entry holds only the Guard Cloud address. The AI tool signs in to Guard
Cloud itself and keeps its own credentials, so no credential is read, copied
or shown, and the workspace is the one chosen when the AI tool signs in.
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
    entry_type: str | None
    sign_in_hint: str


_AI_TOOLS: dict[str, _AiTool] = {
    "claude-code": _AiTool(
        slug="claude-code",
        display_name="Claude Code",
        file_format="json",
        table="mcpServers",
        entry_type="http",
        sign_in_hint="In Claude Code, run /mcp and choose hol-guard-cloud to sign in.",
    ),
    "codex": _AiTool(
        slug="codex",
        display_name="Codex",
        file_format="toml",
        table="mcp_servers",
        entry_type=None,
        sign_in_hint="Run `codex mcp login hol-guard-cloud` to sign in.",
    ),
    "cursor": _AiTool(
        slug="cursor",
        display_name="Cursor",
        file_format="json",
        table="mcpServers",
        entry_type=None,
        sign_in_hint="In Cursor, open Settings > MCP and choose Connect next to hol-guard-cloud.",
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
    other_entries: int
    sign_in_hint: str
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
            return (f"[{tool.table}.{CLOUD_ACTIONS_SERVER_NAME}]", f"url = {json.dumps(self.url)}")
        entry = json.dumps(_wanted_entry(tool, self.url), ensure_ascii=False)
        return (f'"{tool.table}": {{ "{CLOUD_ACTIONS_SERVER_NAME}": {entry} }}',)


def gateway_url(origin: str) -> str:
    from .cloud_actions_oauth import CLOUD_ACTIONS_RESOURCE_PATH

    return f"{origin}{CLOUD_ACTIONS_RESOURCE_PATH}"


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


def plan_host_config(ai_tool: str, *, path: Path, url: str) -> HostConfigPlan:
    """Work out the change to `path`; never writes."""

    tool = _tool(ai_tool)

    def plan(action: PlanAction, **fields: object) -> HostConfigPlan:
        return HostConfigPlan(
            ai_tool=tool.slug,
            display_name=tool.display_name,
            path=path,
            action=action,
            url=url,
            sign_in_hint=tool.sign_in_hint,
            **fields,  # pyright: ignore[reportArgumentType]
        )

    try:
        before = _read_bounded(path)
    except _UnreadableError as error:
        return plan("unreadable", other_entries=0, problem=str(error))
    if before is None:
        after = _render_new(tool, url)
        return plan("create_file", other_entries=0, after=after)
    try:
        document = _parse(tool, before)
        servers = _servers(tool, document)
    except _UnreadableError as error:
        return plan("unreadable", other_entries=0, problem=str(error), before=before)
    others = {name: value for name, value in servers.items() if name != CLOUD_ACTIONS_SERVER_NAME}
    existing = servers.get(CLOUD_ACTIONS_SERVER_NAME)
    if existing is not None:
        if not _is_guard_entry(tool, existing):
            return plan(
                "conflict",
                other_entries=len(others),
                problem=f"An entry named {CLOUD_ACTIONS_SERVER_NAME} already exists with other settings.",
                before=before,
            )
        current = existing.get("url")
        if current == url:
            return plan("unchanged", other_entries=len(others), before=before, after=before)
        previous_url = _display_url(current) if isinstance(current, str) else None
    else:
        previous_url = None
    # Another entry already reaching this server is left as the one in use,
    # so pointing ours at it too would not add a second connection.
    same_server = tuple(sorted(name for name, value in others.items() if _points_at(value, url)))
    if same_server:
        return plan("already_configured", other_entries=len(others), configured_as=same_server, before=before)
    try:
        after = _render_edit(tool, before, url)
        _check_only_guard_entry_changed(tool, before, after, url)
    except UnicodeEncodeError:
        problem = "The settings file holds text that cannot be written back unchanged."
        return plan("unreadable", other_entries=len(others), problem=problem, before=before)
    except _UnreadableError as error:
        return plan("unreadable", other_entries=len(others), problem=str(error), before=before)
    action: PlanAction = "update" if existing is not None else "add"
    return plan(action, other_entries=len(others), previous_url=previous_url, before=before, after=after)


class _UnreadableError(Exception):
    pass


def _tool(ai_tool: str) -> _AiTool:
    tool = _AI_TOOLS.get(ai_tool)
    if tool is None:
        raise AiToolNotSupportedError(ai_tool)
    return tool


def _wanted_entry(tool: _AiTool, url: str) -> dict[str, str]:
    return {"type": tool.entry_type, "url": url} if tool.entry_type is not None else {"url": url}


def _is_guard_entry(tool: _AiTool, entry: Mapping[str, object]) -> bool:
    """True only for an entry shaped exactly like the one Guard writes."""

    if set(entry) != set(_wanted_entry(tool, "")):
        return False
    if tool.entry_type is not None and entry.get("type") != tool.entry_type:
        return False
    return isinstance(entry.get("url"), str)


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


def _render_new(tool: _AiTool, url: str) -> bytes:
    if tool.file_format == "toml":
        return f"[{tool.table}.{CLOUD_ACTIONS_SERVER_NAME}]\nurl = {json.dumps(url)}\n".encode()
    payload = {tool.table: {CLOUD_ACTIONS_SERVER_NAME: _wanted_entry(tool, url)}}
    return (json.dumps(payload, indent=2, ensure_ascii=False) + "\n").encode()


def _render_edit(tool: _AiTool, before: bytes, url: str) -> bytes:
    text = before.decode("utf-8")
    if tool.file_format == "toml":
        return _render_toml_edit(tool, text, url).encode()
    document = json.loads(text) if text.strip() else {}
    servers = document.get(tool.table)
    if not isinstance(servers, dict):
        servers = {}
        document[tool.table] = servers
    servers[CLOUD_ACTIONS_SERVER_NAME] = _wanted_entry(tool, url)
    newline = "\r\n" if "\r\n" in text else "\n"
    rendered = json.dumps(document, indent=_json_indent(text), ensure_ascii=False)
    if newline != "\n":
        rendered = rendered.replace("\n", newline)
    if text.endswith(("\n", "\r\n")) or not text.strip():
        rendered += newline
    return rendered.encode()


def _json_indent(text: str) -> int | str:
    for line in text.splitlines():
        stripped = line.lstrip(" \t")
        if stripped and stripped != line:
            prefix = line[: len(line) - len(stripped)]
            return prefix if "\t" in prefix else len(prefix)
    return 2


def _render_toml_edit(tool: _AiTool, text: str, url: str) -> str:
    import tomlkit
    from tomlkit.exceptions import TOMLKitError

    try:
        document = tomlkit.parse(text)
        servers = document.get(tool.table)
        if servers is None:
            servers = tomlkit.table(is_super_table=True)
            document[tool.table] = servers
        existing = servers.get(CLOUD_ACTIONS_SERVER_NAME)
        if existing is not None:
            existing["url"] = url
        else:
            entry = tomlkit.table()
            entry["url"] = url
            entry.add(tomlkit.nl())
            servers[CLOUD_ACTIONS_SERVER_NAME] = entry
        rendered = tomlkit.dumps(document)
        if rendered.endswith("\n\n") and not text.endswith("\n\n"):
            rendered = rendered.rstrip("\n") + "\n"
        return rendered
    except (TOMLKitError, TypeError, ValueError, AttributeError):
        raise _UnreadableError("Guard could not edit the settings file without changing other settings.") from None


def _check_only_guard_entry_changed(tool: _AiTool, before: bytes, after: bytes, url: str) -> None:
    """Refuse a rendering that changes anything but Guard's own entry."""

    old = _parse(tool, before)
    new = _parse(tool, after)
    new_servers = new.get(tool.table)
    if not isinstance(new_servers, dict) or new_servers.get(CLOUD_ACTIONS_SERVER_NAME) != _wanted_entry(tool, url):
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
    "gateway_url",
    "plan_host_config",
    "settings_path",
]
