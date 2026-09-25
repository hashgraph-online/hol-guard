"""Devin CLI config, hook JSON, and detection helpers for HOL Guard.

Devin's user config lives under ``~/.config/devin/config.json`` (or
``%APPDATA%\\devin\\config.json`` on Windows) and holds a ``hooks`` key whose
event groups are Claude-Code-shaped: ``{"<Event>": [{"matcher": <regex>,
"hooks": [{"type": "command", "command": ..., "timeout": 30}]}]}``. Project
hooks live in ``.devin/hooks.v1.json`` (the hooks object is the whole file),
``.devin/config.json``, and ``.devin/config.local.json`` under ``"hooks"``.
Config files are JSONC (comments and trailing commas are allowed); Guard only
ever writes strict JSON and refuses to rewrite a JSONC file it cannot
preserve byte-for-byte.

MCP servers are read from ``~/.config/devin/mcp_config.json``,
``.devin/mcp_config.json``, and ``.devin/mcp_config.local.json`` under
``"mcpServers"``; legacy Devin versions kept ``mcpServers`` inside
``config.json``, so both locations are read.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from ..aibom_detection import enrich_mcp_server_metadata
from ..models import GuardArtifact
from ..skill_directory_discovery import discover_skill_documents
from ..skill_directory_identity import (
    incomplete_skill_directory_identity,
    inspect_skill_directory,
    skill_directory_identity_metadata,
)

DEVIN_DIR = ".devin"
DEVIN_CONFIG_FILE = "config.json"
DEVIN_LOCAL_CONFIG_FILE = "config.local.json"
DEVIN_HOOKS_FILE = "hooks.v1.json"
DEVIN_MCP_CONFIG_FILE = "mcp_config.json"
DEVIN_LOCAL_MCP_CONFIG_FILE = "mcp_config.local.json"
DEVIN_SKILLS_DIR = "skills"
DEVIN_AGENTS_SKILLS_DIR = ".agents/skills"
DEVIN_USER_CONFIG_DIR = ".config/devin"

GUARD_MANAGED_MARKER = "HOL_GUARD_MANAGED_DEVIN"

# Events Devin fires for managed and user hooks alike.
DEVIN_HOOK_EVENT_NAMES = (
    "PreToolUse",
    "PostToolUse",
    "PermissionRequest",
    "UserPromptSubmit",
    "Stop",
    "PostCompaction",
    "SessionStart",
    "SessionEnd",
)

# Tool names Devin surfaces through hooks: file read/write/edit and notebook
# tools, search tools, exec, webfetch, and MCP tools, which arrive either as
# the ``mcp_call_tool`` dispatcher or as direct ``mcp__<server>__<tool>``
# names, so both shapes are matched. Interactive shell helpers
# (write_to_process, get_output, kill_shell) are intentionally not matched:
# their payloads carry no new command for Guard to review.
DEVIN_GUARD_TOOL_MATCHER = (
    "^(exec|read|write|edit|apply_patch|notebook_read|notebook_edit|grep|glob|webfetch|mcp_call_tool|mcp__.*)$"
)

# Devin also loads Claude Code hook files by default; Guard-managed Claude
# hooks there would double-attribute Devin events to Claude Code.
CLAUDE_HOOK_COMMAND_MARKERS = (
    "--harness', 'claude-code'",
    "--harness claude-code",
    "HOL_GUARD_CLAUDE_DAEMON_HOOK",
    "HOL_GUARD_CLAUDE_SESSION_START_HOOK",
)
CLAUDE_HOOK_SETTINGS_BASENAMES = (
    ".claude/settings.json",
    ".claude/settings.local.json",
)
CLAUDE_HOOK_USER_PATHS = (
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".claude.json",
)


def append_found_path(found_paths: list[str], path: Path) -> None:
    candidate = str(path)
    if candidate not in found_paths:
        found_paths.append(candidate)


def is_guard_managed_hook_command(command: object) -> bool:
    """Return True when a hook command string is owned by HOL Guard for Devin."""

    if not isinstance(command, str):
        return False
    # Windows cmdline quoting escapes inner quotes as \"; normalize so the
    # harness marker in the bounded-bridge config matches on every platform.
    normalized = command.replace('\\"', '"')
    return (
        GUARD_MANAGED_MARKER in command
        or ("codex_plugin_scanner.cli" in command and "'guard', 'hook'" in command and "--harness', 'devin'" in command)
        or ("bounded_cli_hook_bridge" in command and '"harness":"devin"' in normalized)
        or ("__guard-bounded-hook" in command and '"harness":"devin"' in normalized)
        or ("managed/bounded-hooks/devin.py" in normalized.replace("\\", "/"))
    )


def _strip_jsonc_syntax(text: str) -> str:
    """Remove ``//``/``/* */`` comments and trailing commas outside strings."""

    output: list[str] = []
    index = 0
    in_string = False
    length = len(text)
    while index < length:
        char = text[index]
        if in_string:
            output.append(char)
            if char == "\\" and index + 1 < length:
                output.append(text[index + 1])
                index += 2
                continue
            if char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            output.append(char)
            index += 1
            continue
        if char == "/" and index + 1 < length:
            nxt = text[index + 1]
            if nxt == "/":
                index += 2
                while index < length and text[index] not in "\r\n":
                    index += 1
                continue
            if nxt == "*":
                index += 2
                while index + 1 < length and not (text[index] == "*" and text[index + 1] == "/"):
                    index += 1
                index += 2
                continue
        if char == ",":
            lookahead = index + 1
            while lookahead < length:
                if text[lookahead] in " \t\r\n":
                    lookahead += 1
                    continue
                if text[lookahead] == "/" and lookahead + 1 < length:
                    nxt = text[lookahead + 1]
                    if nxt == "/":
                        lookahead += 2
                        while lookahead < length and text[lookahead] not in "\r\n":
                            lookahead += 1
                        continue
                    if nxt == "*":
                        lookahead += 2
                        while lookahead + 1 < length and not (text[lookahead] == "*" and text[lookahead + 1] == "/"):
                            lookahead += 1
                        lookahead += 2
                        continue
                break
            if lookahead < length and text[lookahead] in "]}":
                index += 1
                continue
        output.append(char)
        index += 1
    return "".join(output)


@dataclass(frozen=True)
class DevinJsonDocument:
    """Result of tolerantly reading a Devin JSON/JSONC file."""

    payload: dict[str, object]
    had_comments: bool
    parse_failed: bool
    exists: bool


def load_devin_jsonc(path: Path) -> DevinJsonDocument:
    """Read a Devin JSONC config for inventory only.

    ``had_comments`` is True when strict JSON parsing failed but the tolerant
    JSONC parse (``//``/``/* */`` comments and trailing commas stripped)
    succeeded, meaning the file must never be rewritten by Guard.
    ``parse_failed`` is True when both parses fail, or when the parsed
    top-level value is not a JSON object; an empty or whitespace-only file
    counts as an empty parseable document.
    """

    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return DevinJsonDocument(payload={}, had_comments=False, parse_failed=False, exists=False)
    except UnicodeDecodeError:
        return DevinJsonDocument(payload={}, had_comments=False, parse_failed=True, exists=True)
    except OSError:
        # A read failure on an existing file (permission denied, I/O error)
        # must fail closed so install() refuses rather than rewriting it.
        exists = path.exists()
        return DevinJsonDocument(payload={}, had_comments=False, parse_failed=exists, exists=exists)
    if not text.strip():
        return DevinJsonDocument(payload={}, had_comments=False, parse_failed=False, exists=True)
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        pass
    else:
        if isinstance(payload, dict):
            return DevinJsonDocument(payload=payload, had_comments=False, parse_failed=False, exists=True)
        return DevinJsonDocument(payload={}, had_comments=False, parse_failed=True, exists=True)
    stripped = _strip_jsonc_syntax(text)
    if not stripped.strip():
        return DevinJsonDocument(payload={}, had_comments=True, parse_failed=False, exists=True)
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        return DevinJsonDocument(payload={}, had_comments=False, parse_failed=True, exists=True)
    if isinstance(payload, dict):
        return DevinJsonDocument(payload=payload, had_comments=True, parse_failed=False, exists=True)
    return DevinJsonDocument(payload={}, had_comments=True, parse_failed=True, exists=True)


def _string_args(server_config: dict[str, object]) -> tuple[str, ...]:
    raw_args = server_config.get("args")
    if not isinstance(raw_args, list):
        return ()
    return tuple(str(value) for value in raw_args if isinstance(value, (str, int, float, bool)))


def _mcp_endpoint(server_config: dict[str, object]) -> tuple[str | None, str | None]:
    command = server_config.get("command")
    url = server_config.get("url")
    return (command if isinstance(command, str) else None, url if isinstance(url, str) else None)


def _mcp_transport(server_config: dict[str, object]) -> str:
    url = server_config.get("url")
    transport = server_config.get("transport")
    if isinstance(transport, str) and transport.strip():
        return transport.strip()
    if isinstance(url, str) and url.strip():
        return "http"
    return "stdio"


def _mcp_environment(server_config: dict[str, object]) -> dict[str, str]:
    value = server_config.get("env")
    if isinstance(value, dict):
        return {
            key.strip(): item
            for key, item in value.items()
            if isinstance(key, str) and key.strip() and isinstance(item, str)
        }
    return {}


def append_mcp_server_artifacts(
    *,
    harness: str,
    artifacts: list[GuardArtifact],
    servers: object,
    config_path: Path,
    scope: str,
) -> None:
    """Emit ``mcp_server`` artifacts for a Devin ``mcpServers`` mapping."""

    if not isinstance(servers, dict):
        return
    for server_name, server_config in servers.items():
        if not isinstance(server_name, str) or not isinstance(server_config, dict):
            continue
        command, url = _mcp_endpoint(server_config)
        if command is None and url is None:
            continue
        args = _string_args(server_config)
        transport = _mcp_transport(server_config)
        environment = _mcp_environment(server_config)
        artifacts.append(
            GuardArtifact(
                artifact_id=f"{harness}:{scope}:mcp:{config_path.name}:{server_name}",
                name=server_name,
                harness=harness,
                artifact_type="mcp_server",
                source_scope=scope,
                config_path=str(config_path),
                command=command,
                args=args,
                url=url,
                transport=transport,
                metadata=enrich_mcp_server_metadata(
                    {
                        "name": server_name,
                        "env_keys": sorted(environment),
                    },
                    command=command,
                    args=args,
                    url=url,
                    transport=transport,
                    configured_environment=environment,
                    configured_headers={},
                ),
            )
        )


def append_devin_hook_artifacts(
    *,
    artifacts: list[GuardArtifact],
    hooks: object,
    config_path: Path,
    scope: str,
) -> None:
    """Emit ``hook`` artifacts for a Devin ``hooks`` event-group mapping.

    Guard-managed handlers are skipped so an installed Guard does not appear
    as an external hook artifact in its own inventory.
    """

    if not isinstance(hooks, dict):
        return
    for event_name, groups in hooks.items():
        if not isinstance(event_name, str) or not isinstance(groups, list):
            continue
        index = 0
        for group in groups:
            if not isinstance(group, dict):
                continue
            matcher = group.get("matcher")
            handlers = group.get("hooks")
            if not isinstance(handlers, list):
                continue
            for handler in handlers:
                if not isinstance(handler, dict):
                    continue
                command = handler.get("command")
                if not isinstance(command, str) or not command.strip():
                    continue
                if is_guard_managed_hook_command(command):
                    continue
                metadata: dict[str, object] = {"event": event_name}
                if isinstance(matcher, str) and matcher:
                    metadata["matcher"] = matcher
                timeout = handler.get("timeout")
                if isinstance(timeout, (int, float)) and not isinstance(timeout, bool):
                    metadata["timeout"] = timeout
                handler_type = handler.get("type")
                if isinstance(handler_type, str) and handler_type:
                    metadata["type"] = handler_type
                artifacts.append(
                    GuardArtifact(
                        artifact_id=f"devin:{scope}:hook:{config_path.name}:{event_name.lower()}:{index}",
                        name=f"{event_name}:{matcher}" if isinstance(matcher, str) and matcher else event_name,
                        harness="devin",
                        artifact_type="hook",
                        source_scope=scope,
                        config_path=str(config_path),
                        command=command,
                        metadata=metadata,
                    )
                )
                index += 1


def append_devin_skill_artifacts(
    *,
    artifacts: list[GuardArtifact],
    found_paths: list[str],
    warnings: list[str],
    skill_root: Path,
    identity_scope_root: Path,
    scope: str,
) -> None:
    """Emit ``skill`` artifacts for ``<skill_root>/<name>/SKILL.md`` trees."""

    discovery = discover_skill_documents(skill_root)
    for skill_path in discovery.documents:
        append_found_path(found_paths, skill_path)
        relative = skill_path.parent.relative_to(skill_root).as_posix()
        identity = inspect_skill_directory(skill_path, scope_root=identity_scope_root)
        metadata = skill_directory_identity_metadata(identity, version_label=f"skills/{relative}")
        if identity.status != "complete":
            warnings.append(f"Devin {scope} skill directory identity is incomplete; approval reuse is disabled.")
        artifacts.append(
            GuardArtifact(
                artifact_id=f"devin:{scope}:skill:{relative}",
                name=relative,
                harness="devin",
                artifact_type="skill",
                source_scope=scope,
                config_path=str(skill_path),
                metadata=metadata,
            )
        )
    for issue in discovery.issues:
        append_found_path(found_paths, issue.path)
        identity = incomplete_skill_directory_identity(issue.failure_reason)
        metadata = skill_directory_identity_metadata(
            identity, version_label=f"skills/.guard-discovery/{issue.issue_id}"
        )
        warnings.append(f"Devin {scope} skill discovery is incomplete; approval reuse is disabled.")
        artifacts.append(
            GuardArtifact(
                artifact_id=f"devin:{scope}:skill-discovery:{issue.issue_id}",
                name="Incomplete Devin skill discovery",
                harness="devin",
                artifact_type="skill",
                source_scope=scope,
                config_path=str(issue.path),
                metadata=metadata,
            )
        )


def devin_hook_commands_in_payload(payload: dict[str, object]) -> list[str]:
    """Collect hook handler command strings from a Claude-Code-shaped config."""

    commands: list[str] = []
    hooks = payload.get("hooks")
    if not isinstance(hooks, dict):
        return commands
    for groups in hooks.values():
        if not isinstance(groups, list):
            continue
        for group in groups:
            if not isinstance(group, dict):
                continue
            direct = group.get("command")
            if isinstance(direct, str):
                commands.append(direct)
            handlers = group.get("hooks")
            if isinstance(handlers, list):
                commands.extend(
                    handler["command"]
                    for handler in handlers
                    if isinstance(handler, dict) and isinstance(handler.get("command"), str)
                )
    return commands


def has_guard_managed_claude_hooks(payload: dict[str, object]) -> bool:
    """Return True when a Claude config payload contains Guard-managed Claude hooks."""

    return any(
        marker in command
        for command in devin_hook_commands_in_payload(payload)
        for marker in CLAUDE_HOOK_COMMAND_MARKERS
    )


__all__ = [
    "CLAUDE_HOOK_COMMAND_MARKERS",
    "CLAUDE_HOOK_SETTINGS_BASENAMES",
    "CLAUDE_HOOK_USER_PATHS",
    "DEVIN_AGENTS_SKILLS_DIR",
    "DEVIN_CONFIG_FILE",
    "DEVIN_DIR",
    "DEVIN_GUARD_TOOL_MATCHER",
    "DEVIN_HOOKS_FILE",
    "DEVIN_HOOK_EVENT_NAMES",
    "DEVIN_LOCAL_CONFIG_FILE",
    "DEVIN_LOCAL_MCP_CONFIG_FILE",
    "DEVIN_MCP_CONFIG_FILE",
    "DEVIN_SKILLS_DIR",
    "DEVIN_USER_CONFIG_DIR",
    "GUARD_MANAGED_MARKER",
    "DevinJsonDocument",
    "append_devin_hook_artifacts",
    "append_devin_skill_artifacts",
    "append_found_path",
    "append_mcp_server_artifacts",
    "devin_hook_commands_in_payload",
    "has_guard_managed_claude_hooks",
    "is_guard_managed_hook_command",
    "load_devin_jsonc",
]
