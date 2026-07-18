"""z.ai ZCode config, hook JSON, and detection helpers for HOL Guard.

ZCode stores its CLI app config under ``~/.zcode/``. ``~/.zcode/cli/config.json``
is Claude-Code-shaped: an ``mcp`` section (``mcp.servers.<name>``), a ``plugins``
section (``plugins.enabledPlugins.<name@marketplace>``), and an optional
``hooks`` section using Claude Code's hook group schema. Plugins are cached
under ``~/.zcode/cli/plugins/cache/<marketplace>/<plugin>/<version>/`` with a
``.zcode-plugin/plugin.json`` manifest, a ``.zcode-plugin-seed.json`` provenance
file, ``hooks/hooks.json``, ``.mcp.json``, ``skills/`` and ``commands/`` trees.
"""

from __future__ import annotations

from pathlib import Path

from ..aibom_detection import enrich_mcp_server_metadata
from ..models import GuardArtifact
from .base import _json_payload

ZCODE_DIR = ".zcode"
ZCODE_CLI_DIR = ".zcode/cli"
ZCODE_CLI_CONFIG_FILE = "config.json"
ZCODE_PLUGINS_DIR = "plugins"
ZCODE_PLUGIN_CACHE_DIR = "plugins/cache"
ZCODE_PLUGIN_MARKETPLACES_DIR = "plugins/marketplaces"
ZCODE_PLUGIN_MANIFEST_DIR = ".zcode-plugin"
ZCODE_PLUGIN_MANIFEST_FILE = "plugin.json"
ZCODE_PLUGIN_SEED_FILE = ".zcode-plugin-seed.json"
ZCODE_PLUGIN_HOOKS_FILE = "hooks/hooks.json"
ZCODE_PLUGIN_HOOKS_CURSOR_FILE = "hooks/hooks-cursor.json"
ZCODE_PLUGIN_MCP_FILE = ".mcp.json"
ZCODE_PLUGIN_SKILLS_DIR = "skills"
ZCODE_PLUGIN_COMMANDS_DIR = "commands"
ZCODE_MARKETPLACE_FILE = "marketplace.json"

GUARD_MANAGED_MARKER = "HOL_GUARD_MANAGED_ZCODE"

# Claude Code tool matchers ZCode surfaces. MCP tools arrive as mcp__<server>__<tool>;
# the mcp__.* matcher must be present so the PreToolUse hook fires for MCP calls too,
# otherwise an MCP server's tools could be invoked without Guard interception.
ZCODE_PRETOOL_MATCHERS = (
    "Bash",
    "Read",
    "Write",
    "Edit",
    "MultiEdit",
    "Grep",
    "WebFetch",
    "WebSearch",
    "mcp__.*",
    "run_terminal_command",
    "run_command",
    "read_file",
    "write_file",
    "search_replace",
    "multi_edit",
    "grep",
    "web_fetch",
    "web_search",
)

# z.ai/ZCode process identity and runtime env hints (never secret-bearing).
ZCODE_BUNDLE_IDENTIFIER = "dev.zcode.app"
ZCODE_ENV_HINTS = (
    "ZCODE_BASE_URL",
    "ZCODE_APP_VERSION",
    "ZCODE_ENV",
    "ZCODE_RUNTIME_ENV",
    "ZCODE_PROCESS_LABEL",
    "ZCODE_RG_BINARY",
    "ZAI_OAUTH_ORIGIN",
    "ZAI_OAUTH_CLIENT_ID",
)


def append_found_path(found_paths: list[str], path: Path) -> None:
    candidate = str(path)
    if candidate not in found_paths:
        found_paths.append(candidate)


def is_guard_managed_hook_command(command: object) -> bool:
    """Return True when a hook command string is owned by HOL Guard for ZCode."""

    if not isinstance(command, str):
        return False
    return GUARD_MANAGED_MARKER in command or (
        "codex_plugin_scanner.cli" in command and "'guard', 'hook'" in command and "--harness', 'zcode'" in command
    )


def _string_args(server_config: dict[str, object]) -> tuple[str, ...]:
    raw_args = server_config.get("args")
    if not isinstance(raw_args, list):
        return ()
    return tuple(str(value) for value in raw_args if isinstance(value, (str, int, float, bool)))


def _mcp_env_keys(server_config: dict[str, object]) -> list[str]:
    return sorted(_mcp_environment(server_config))


def _mcp_environment(server_config: dict[str, object]) -> dict[str, str]:
    for field in ("env", "environment"):
        value = server_config.get(field)
        if isinstance(value, dict):
            return {
                key.strip(): item
                for key, item in value.items()
                if isinstance(key, str) and key.strip() and isinstance(item, str)
            }
    return {}


def _mcp_headers(server_config: dict[str, object]) -> dict[str, str]:
    value = server_config.get("headers")
    if not isinstance(value, dict):
        return {}
    return {
        key.strip(): item
        for key, item in value.items()
        if isinstance(key, str) and key.strip() and isinstance(item, str)
    }


def _mcp_metadata(
    *,
    server_name: str,
    server_config: dict[str, object],
    command: str | None,
    args: tuple[str, ...],
    url: str | None,
    transport: str,
    additional: dict[str, object] | None = None,
) -> dict[str, object]:
    environment = _mcp_environment(server_config)
    headers = _mcp_headers(server_config)
    return enrich_mcp_server_metadata(
        {
            "name": server_name,
            "env_keys": sorted(environment),
            "headers_keys": sorted(headers),
            **(additional or {}),
        },
        command=command,
        args=args,
        url=url,
        transport=transport,
        configured_environment=environment,
        configured_headers=headers,
    )


def _mcp_transport(server_config: dict[str, object]) -> str:
    url = server_config.get("url")
    transport = server_config.get("transport")
    if isinstance(transport, str) and transport.strip():
        return transport.strip()
    if isinstance(url, str) and url.strip():
        return "http"
    explicit_type = server_config.get("type")
    if isinstance(explicit_type, str) and explicit_type.strip() == "stdio":
        return "stdio"
    return "stdio"


def _mcp_endpoint(server_config: dict[str, object]) -> tuple[str | None, str | None]:
    """Return the (command, url) endpoint for an MCP server config, if any."""

    command = server_config.get("command")
    url = server_config.get("url")
    return (command if isinstance(command, str) else None, url if isinstance(url, str) else None)


def append_cli_config_artifacts(
    *,
    harness: str,
    artifacts: list[GuardArtifact],
    payload: dict[str, object],
    config_path: Path,
    scope: str,
) -> None:
    """Parse the ZCode CLI config.json into MCP, plugin, and hook artifacts."""

    mcp_section = payload.get("mcp")
    if isinstance(mcp_section, dict):
        servers = mcp_section.get("servers")
        if isinstance(servers, dict):
            for server_name, server_config in servers.items():
                if not isinstance(server_name, str) or not isinstance(server_config, dict):
                    continue
                command, url = _mcp_endpoint(server_config)
                if command is None and url is None:
                    continue
                args = _string_args(server_config)
                transport = _mcp_transport(server_config)
                artifacts.append(
                    GuardArtifact(
                        artifact_id=f"{harness}:{scope}:mcp:{server_name}",
                        name=server_name,
                        harness=harness,
                        artifact_type="mcp_server",
                        source_scope=scope,
                        config_path=str(config_path),
                        command=command,
                        args=args,
                        url=url,
                        transport=transport,
                        metadata=_mcp_metadata(
                            server_name=server_name,
                            server_config=server_config,
                            command=command,
                            args=args,
                            url=url,
                            transport=transport,
                        ),
                    )
                )

    plugins_section = payload.get("plugins")
    if isinstance(plugins_section, dict):
        enabled = plugins_section.get("enabledPlugins")
        if isinstance(enabled, dict):
            for plugin_handle, state in enabled.items():
                if not isinstance(plugin_handle, str):
                    continue
                artifacts.append(
                    GuardArtifact(
                        artifact_id=f"{harness}:{scope}:plugin:{plugin_handle}",
                        name=plugin_handle,
                        harness=harness,
                        artifact_type="plugin",
                        source_scope=scope,
                        config_path=str(config_path),
                        metadata={"enabled": bool(state)},
                    )
                )

    hooks_section = payload.get("hooks")
    if isinstance(hooks_section, dict):
        _append_hook_groups(
            harness=harness,
            artifacts=artifacts,
            hooks=hooks_section,
            config_path=config_path,
            scope=scope,
        )


def _append_hook_groups(
    *,
    harness: str,
    artifacts: list[GuardArtifact],
    hooks: dict[str, object],
    config_path: Path,
    scope: str,
) -> None:
    for event_name, entries in hooks.items():
        if not isinstance(event_name, str) or not isinstance(entries, list):
            continue
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                continue
            matcher = entry.get("matcher")
            collected: list[tuple[str, str]] = []
            direct_command = entry.get("command")
            if isinstance(direct_command, str) and direct_command.strip():
                collected.append((f"{event_name.lower()}:{index}", direct_command))
            nested_hooks = entry.get("hooks")
            if isinstance(nested_hooks, list):
                for nested_index, hook_entry in enumerate(nested_hooks):
                    if not isinstance(hook_entry, dict):
                        continue
                    command = hook_entry.get("command")
                    if isinstance(command, str) and command.strip():
                        collected.append((f"{event_name.lower()}:{index}:{nested_index}", command))
            for artifact_suffix, command in collected:
                artifacts.append(
                    GuardArtifact(
                        artifact_id=f"{harness}:{scope}:hook:{artifact_suffix}",
                        name=_hook_name(event_name, matcher),
                        harness=harness,
                        artifact_type="hook",
                        source_scope=scope,
                        config_path=str(config_path),
                        command=command,
                        metadata={
                            "event": event_name,
                            "matcher": matcher,
                            "managed": is_guard_managed_hook_command(command),
                        },
                    )
                )


def _hook_name(event_name: str, matcher: object) -> str:
    return f"{event_name}:{matcher}" if isinstance(matcher, str) and matcher else event_name


def append_hooks_file_artifacts(
    *,
    harness: str,
    artifacts: list[GuardArtifact],
    found_paths: list[str],
    hooks_file: Path,
    scope: str,
) -> None:
    """Parse a plugin ``hooks/hooks.json`` (or ``hooks-cursor.json``) file."""

    payload = _json_payload(hooks_file)
    if not payload:
        return
    append_found_path(found_paths, hooks_file)
    hooks = payload.get("hooks")
    if isinstance(hooks, dict):
        _append_hook_groups(
            harness=harness,
            artifacts=artifacts,
            hooks=hooks,
            config_path=hooks_file,
            scope=scope,
        )


def append_plugin_manifest_artifacts(
    *,
    harness: str,
    artifacts: list[GuardArtifact],
    found_paths: list[str],
    plugin_root: Path,
    scope: str,
) -> None:
    """Parse ``.zcode-plugin/plugin.json`` and ``.zcode-plugin-seed.json`` provenance."""

    manifest_path = plugin_root / ZCODE_PLUGIN_MANIFEST_DIR / ZCODE_PLUGIN_MANIFEST_FILE
    payload = _json_payload(manifest_path)
    if not payload:
        return
    append_found_path(found_paths, manifest_path)
    raw_name = payload.get("name")
    plugin_name = raw_name if isinstance(raw_name, str) else plugin_root.name
    raw_version = payload.get("version")
    version = raw_version if isinstance(raw_version, str) else None
    publisher_value = payload.get("author")
    publisher_name: str | None = None
    if isinstance(publisher_value, dict):
        author_name = publisher_value.get("name")
        publisher_name = author_name if isinstance(author_name, str) else None
    elif isinstance(publisher_value, str):
        publisher_name = publisher_value

    seed_path = plugin_root / ZCODE_PLUGIN_SEED_FILE
    seed_payload = _json_payload(seed_path)
    metadata: dict[str, object] = {"version": version} if version is not None else {}
    marketplace_name: str | None = None
    if seed_payload:
        append_found_path(found_paths, seed_path)
        marketplace_value = seed_payload.get("marketplace")
        if isinstance(marketplace_value, str):
            marketplace_name = marketplace_value
            metadata["marketplace"] = marketplace_value
        source_value = seed_payload.get("source")
        if isinstance(source_value, str):
            metadata["source"] = source_value
        plugin_version_value = seed_payload.get("pluginVersion")
        if isinstance(plugin_version_value, str):
            metadata["plugin_version"] = plugin_version_value
        seed_hash = seed_payload.get("hash")
        if isinstance(seed_hash, str):
            metadata["provenance_hash"] = seed_hash

    artifact_id = (
        f"{harness}:{scope}:plugin:{marketplace_name}:{plugin_name}"
        if marketplace_name
        else f"{harness}:{scope}:plugin:{plugin_name}"
    )
    artifacts.append(
        GuardArtifact(
            artifact_id=artifact_id,
            name=plugin_name,
            harness=harness,
            artifact_type="plugin",
            source_scope=scope,
            config_path=str(manifest_path),
            publisher=publisher_name,
            metadata=metadata,
        )
    )

    plugin_mcp_path = plugin_root / ZCODE_PLUGIN_MCP_FILE
    plugin_mcp_payload = _json_payload(plugin_mcp_path)
    if isinstance(plugin_mcp_payload, dict):
        servers = plugin_mcp_payload.get("mcpServers")
        if isinstance(servers, dict):
            append_found_path(found_paths, plugin_mcp_path)
            for server_name, server_config in servers.items():
                if not isinstance(server_name, str) or not isinstance(server_config, dict):
                    continue
                command, url = _mcp_endpoint(server_config)
                if command is None and url is None:
                    continue
                args = _string_args(server_config)
                transport = _mcp_transport(server_config)
                artifacts.append(
                    GuardArtifact(
                        artifact_id=f"{harness}:{scope}:plugin:{plugin_name}:mcp:{server_name}",
                        name=server_name,
                        harness=harness,
                        artifact_type="mcp_server",
                        source_scope=scope,
                        config_path=str(plugin_mcp_path),
                        command=command,
                        args=args,
                        url=url,
                        transport=transport,
                        metadata=_mcp_metadata(
                            server_name=server_name,
                            server_config=server_config,
                            command=command,
                            args=args,
                            url=url,
                            transport=transport,
                            additional={"plugin": plugin_name},
                        ),
                    )
                )

    append_hooks_file_artifacts(
        harness=harness,
        artifacts=artifacts,
        found_paths=found_paths,
        hooks_file=plugin_root / ZCODE_PLUGIN_HOOKS_FILE,
        scope=scope,
    )
    append_hooks_file_artifacts(
        harness=harness,
        artifacts=artifacts,
        found_paths=found_paths,
        hooks_file=plugin_root / ZCODE_PLUGIN_HOOKS_CURSOR_FILE,
        scope=scope,
    )
    append_skill_artifacts(
        harness=harness,
        artifacts=artifacts,
        found_paths=found_paths,
        skill_root=plugin_root / ZCODE_PLUGIN_SKILLS_DIR,
        scope=scope,
    )
    append_command_artifacts(
        harness=harness,
        artifacts=artifacts,
        found_paths=found_paths,
        command_root=plugin_root / ZCODE_PLUGIN_COMMANDS_DIR,
        scope=scope,
    )


def append_skill_artifacts(
    *,
    harness: str,
    artifacts: list[GuardArtifact],
    found_paths: list[str],
    skill_root: Path,
    scope: str,
) -> None:
    if not skill_root.is_dir():
        return
    for skill_path in sorted(skill_root.rglob("SKILL.md")):
        append_found_path(found_paths, skill_path)
        relative = skill_path.parent.relative_to(skill_root).as_posix()
        artifacts.append(
            GuardArtifact(
                artifact_id=f"{harness}:{scope}:skill:{relative}",
                name=relative,
                harness=harness,
                artifact_type="skill",
                source_scope=scope,
                config_path=str(skill_path),
            )
        )


def append_command_artifacts(
    *,
    harness: str,
    artifacts: list[GuardArtifact],
    found_paths: list[str],
    command_root: Path,
    scope: str,
) -> None:
    if not command_root.is_dir():
        return
    for command_path in sorted(command_root.glob("*.md")):
        append_found_path(found_paths, command_path)
        artifacts.append(
            GuardArtifact(
                artifact_id=f"{harness}:{scope}:command:{command_path.stem}",
                name=command_path.stem,
                harness=harness,
                artifact_type="command",
                source_scope=scope,
                config_path=str(command_path),
            )
        )


def append_marketplace_artifacts(
    *,
    harness: str,
    artifacts: list[GuardArtifact],
    found_paths: list[str],
    marketplace_file: Path,
    scope: str,
) -> None:
    payload = _json_payload(marketplace_file)
    if not payload:
        return
    append_found_path(found_paths, marketplace_file)
    marketplace_name = payload.get("name")
    name = marketplace_name if isinstance(marketplace_name, str) else marketplace_file.parent.name
    plugins = payload.get("plugins")
    entry_count = len(plugins) if isinstance(plugins, list) else 0
    artifacts.append(
        GuardArtifact(
            artifact_id=f"{harness}:{scope}:marketplace:{name}",
            name=name,
            harness=harness,
            artifact_type="marketplace",
            source_scope=scope,
            config_path=str(marketplace_file),
            metadata={"entries": entry_count},
        )
    )


__all__ = [
    "GUARD_MANAGED_MARKER",
    "ZCODE_BUNDLE_IDENTIFIER",
    "ZCODE_CLI_CONFIG_FILE",
    "ZCODE_CLI_DIR",
    "ZCODE_DIR",
    "ZCODE_ENV_HINTS",
    "ZCODE_MARKETPLACE_FILE",
    "ZCODE_PLUGINS_DIR",
    "ZCODE_PLUGIN_CACHE_DIR",
    "ZCODE_PLUGIN_COMMANDS_DIR",
    "ZCODE_PLUGIN_HOOKS_CURSOR_FILE",
    "ZCODE_PLUGIN_HOOKS_FILE",
    "ZCODE_PLUGIN_MANIFEST_DIR",
    "ZCODE_PLUGIN_MANIFEST_FILE",
    "ZCODE_PLUGIN_MARKETPLACES_DIR",
    "ZCODE_PLUGIN_MCP_FILE",
    "ZCODE_PLUGIN_SEED_FILE",
    "ZCODE_PLUGIN_SKILLS_DIR",
    "ZCODE_PRETOOL_MATCHERS",
    "append_cli_config_artifacts",
    "append_command_artifacts",
    "append_found_path",
    "append_hooks_file_artifacts",
    "append_marketplace_artifacts",
    "append_plugin_manifest_artifacts",
    "append_skill_artifacts",
    "is_guard_managed_hook_command",
]
