"""Grok Build CLI config, hook JSON, and detection helpers for HOL Guard."""

from __future__ import annotations

import json
import re
from pathlib import Path

from ..aibom_detection import enrich_mcp_server_metadata
from ..models import GuardArtifact
from .base import _json_payload

GROK_PRETOOL_HOOK_TIMEOUT_SECONDS = 90
GROK_HOOK_INTERNAL_TIMEOUT_SECONDS = 85
GROK_APPROVAL_WAIT_MAX_SECONDS = 80

GROK_DIR = ".grok"
GROK_CONFIG_FILE = "config.toml"
GROK_MANAGED_CONFIG_FILE = "managed_config.toml"
GROK_REQUIREMENTS_FILE = "requirements.toml"
GROK_HOOKS_DIR = "hooks"
GUARD_MANAGED_BEGIN = "# BEGIN HOL GUARD MANAGED GROK"
GUARD_MANAGED_END = "# END HOL GUARD MANAGED GROK"
GUARD_MANAGED_MARKER = "HOL GUARD MANAGED GROK"
GUARD_HOOK_PRETOOL_FILE = "hol-guard-pretooluse.json"
GUARD_HOOK_PROMPT_FILE = "hol-guard-prompt.json"
# Kept empty: a per-tool matcher list double-fired after Grok aliased Bash→run_terminal_command.
PRETOOL_MATCHERS: tuple[str, ...] = ()
MANAGED_DENY_RULES = (
    "Bash(hol-guard apps disconnect grok*)",
    "Bash(hol-guard apps uninstall*)",
    "Bash(rm -rf **/.grok/hooks/hol-guard*)",
    "Edit(**/.grok/hooks/hol-guard*)",
    "Edit(**/.grok/managed_config.toml)",
    "Read(**/.grok/auth/**)",
    "Read(**/.grok/auth.json)",
    "Read(**/.env)",
    "Read(**/.npmrc)",
    "Read(**/.ssh/**)",
    "Read(**/.hol-guard/secrets/**)",
    "Read(**/.hol-guard/totp-secrets/**)",
    "Read(**/.hol-guard/daemon-auth-token)",
)
OBSERVE_HOOK_EVENTS = ("UserPromptSubmit", "SubagentStart", "SessionStart")
GROK_SURFACE_RELATIVES = (
    "skills",
    "plugins",
    "plugins/marketplaces",
    "plugins/known_marketplaces.json",
    "sessions",
    "agents",
    "personas",
    "workflows",
    "sandbox.toml",
    "trusted_folders.toml",
)
GROK_PROJECT_SURFACE_RELATIVES = (
    "skills",
    "plugins",
    "hooks",
    "agents",
    "personas",
    "workflows",
    "sandbox.toml",
)
SYSTEM_MANAGED_CONFIG = Path("/etc/grok/managed_config.toml")
SYSTEM_REQUIREMENTS = Path("/etc/grok/requirements.toml")
DEGRADED_MODE_MARKERS = (
    "always-approve",
    "bypasspermissions",
    "bypass_permissions",
    'defaultmode = "bypasspermissions"',
    'defaultMode": "bypassPermissions"',
    'sandbox = "off"',
    'sandbox="off"',
)


def _command_hook_entry(hook_command: str, *, timeout: int) -> dict[str, object]:
    return {
        "hooks": [
            {
                "type": "command",
                "command": hook_command,
                "timeout": timeout,
            }
        ]
    }


def build_pretool_hook_json(hook_command: str) -> dict[str, object]:
    """Install one catch-all PreToolUse handler.

    Grok matchers are regexes against the native tool name and also expand
    aliases, so listing both ``Bash`` and ``run_terminal_command`` ran Guard
    twice. An omitted matcher covers current and future tools, including
    ``spawn_subagent``, ``list_dir``, and ``server__tool`` MCP names.
    """

    return {"hooks": {"PreToolUse": [_command_hook_entry(hook_command, timeout=GROK_PRETOOL_HOOK_TIMEOUT_SECONDS)]}}


def build_observe_hook_json(hook_command: str) -> dict[str, object]:
    """Install observe-only lifecycle hooks.

    Grok ignores deny/stdout on these events. Guard still records prompt and
    subagent inventory; enforcement stays on PreToolUse.
    """

    return {
        "hooks": {event_name: [_command_hook_entry(hook_command, timeout=15)] for event_name in OBSERVE_HOOK_EVENTS}
    }


def _toml_inline_command_hook(hook_command: str, *, timeout: int) -> str:
    return '{ type = "command", command = ' + json.dumps(hook_command) + f", timeout = {timeout} }}"


def build_managed_config_block(hook_command: str = "") -> str:
    deny_lines = ",\n".join(f'  "{rule}"' for rule in MANAGED_DENY_RULES)
    lines = [
        GUARD_MANAGED_BEGIN,
        "# Permission rules below are managed by HOL Guard. Do not edit manually.",
        "[permission]",
        "deny = [",
        deny_lines,
        "]",
    ]
    if hook_command.strip():
        command_hook = _toml_inline_command_hook(hook_command, timeout=GROK_PRETOOL_HOOK_TIMEOUT_SECONDS)
        observe_hook = _toml_inline_command_hook(hook_command, timeout=15)
        lines.extend(
            [
                "",
                "[[hooks.PreToolUse]]",
                f"hooks = [{command_hook}]",
                "",
                "[[hooks.UserPromptSubmit]]",
                f"hooks = [{observe_hook}]",
                "",
                "[[hooks.SubagentStart]]",
                f"hooks = [{observe_hook}]",
                "",
                "[[hooks.SessionStart]]",
                f"hooks = [{observe_hook}]",
            ]
        )
    lines.append(GUARD_MANAGED_END)
    return "\n".join(lines)


def remove_managed_block(text: str) -> str:
    pattern = re.compile(
        rf"^\s*{re.escape(GUARD_MANAGED_BEGIN)}.*?{re.escape(GUARD_MANAGED_END)}\s*\n?",
        re.MULTILINE | re.DOTALL,
    )
    cleaned = pattern.sub("", text)
    cleaned = re.sub(rf"^\s*#.*{re.escape(GUARD_MANAGED_MARKER)}.*$\n?", "", cleaned, flags=re.MULTILINE)
    return cleaned


def append_hooks_dir_artifacts(
    *,
    harness: str,
    artifacts: list[GuardArtifact],
    found_paths: list[str],
    hooks_dir: Path,
    scope: str,
) -> None:
    if not hooks_dir.is_dir():
        return
    for hook_file in sorted(hooks_dir.glob("*.json")):
        payload = _json_payload(hook_file)
        if not payload:
            continue
        append_found_path(found_paths, hook_file)
        hooks = payload.get("hooks")
        if not isinstance(hooks, dict):
            continue
        for event_name, entries in hooks.items():
            if not isinstance(event_name, str) or not isinstance(entries, list):
                continue
            for index, entry in enumerate(entries):
                if not isinstance(entry, dict):
                    continue
                nested = entry.get("hooks")
                matcher = entry.get("matcher")
                if isinstance(nested, list):
                    for nested_index, hook_entry in enumerate(nested):
                        if not isinstance(hook_entry, dict):
                            continue
                        command = hook_entry.get("command")
                        if not isinstance(command, str) or not command.strip():
                            continue
                        artifacts.append(
                            GuardArtifact(
                                artifact_id=f"{harness}:{scope}:hook:{event_name.lower()}:{index}:{nested_index}",
                                name=f"{event_name}:{matcher}" if isinstance(matcher, str) else event_name,
                                harness=harness,
                                artifact_type="hook",
                                source_scope=scope,
                                config_path=str(hook_file),
                                command=command,
                                metadata={"event": event_name, "matcher": matcher},
                            )
                        )


def append_permission_artifacts(
    *,
    harness: str,
    artifacts: list[GuardArtifact],
    payload: dict[str, object],
    config_path: Path,
    scope: str,
) -> None:
    permission = payload.get("permission")
    if not isinstance(permission, dict):
        return
    for key in ("allow", "deny", "ask", "rules"):
        value = permission.get(key)
        if isinstance(value, list) and value:
            artifacts.append(
                GuardArtifact(
                    artifact_id=f"{harness}:{scope}:permission:{key}",
                    name=f"permission:{key}",
                    harness=harness,
                    artifact_type="policy",
                    source_scope=scope,
                    config_path=str(config_path),
                    metadata={"entries": len(value)},
                )
            )


def _mcp_env_keys(server_config: dict[str, object]) -> list[str]:
    return sorted(_mcp_environment(server_config))


def _mcp_environment(server_config: dict[str, object]) -> dict[str, str]:
    environment: dict[str, str] = {}
    for field in ("environment", "env"):
        value = server_config.get(field)
        if isinstance(value, dict):
            environment.update(
                {
                    key.strip(): item
                    for key, item in value.items()
                    if isinstance(key, str) and key.strip() and isinstance(item, str)
                }
            )
    return environment


def _mcp_headers(server_config: dict[str, object]) -> dict[str, str]:
    headers = server_config.get("headers")
    if not isinstance(headers, dict):
        return {}
    return {
        key.strip(): item
        for key, item in headers.items()
        if isinstance(key, str) and key.strip() and isinstance(item, str)
    }


def _mcp_headers_keys(server_config: dict[str, object]) -> list[str]:
    return sorted(_mcp_headers(server_config))


def append_mcp_artifacts(
    *,
    harness: str,
    artifacts: list[GuardArtifact],
    payload: dict[str, object],
    config_path: Path,
    scope: str,
) -> None:
    servers: dict[str, object] = {}
    nested = payload.get("mcp_servers")
    if isinstance(nested, dict):
        servers.update(nested)
    for key, value in payload.items():
        if not isinstance(key, str) or not key.startswith("mcp_servers."):
            continue
        if isinstance(value, dict):
            servers[key.split(".", 1)[1]] = value
    for server_name, server_config in servers.items():
        if not isinstance(server_name, str) or not isinstance(server_config, dict):
            continue
        command = server_config.get("command")
        url = server_config.get("url")
        if not isinstance(command, str) and not isinstance(url, str):
            continue
        raw_args = server_config.get("args")
        args = tuple(str(item) for item in raw_args) if isinstance(raw_args, list) else ()
        transport = "http" if isinstance(url, str) else "stdio"
        environment = _mcp_environment(server_config)
        headers = _mcp_headers(server_config)
        metadata = enrich_mcp_server_metadata(
            {
                "name": server_name,
                "env_keys": _mcp_env_keys(server_config),
                "headers_keys": _mcp_headers_keys(server_config),
            },
            command=command if isinstance(command, str) else None,
            args=args,
            url=url if isinstance(url, str) else None,
            transport=transport,
            configured_environment=environment,
            configured_headers=headers,
        )
        artifacts.append(
            GuardArtifact(
                artifact_id=f"{harness}:{scope}:mcp:{server_name}",
                name=server_name,
                harness=harness,
                artifact_type="mcp_server",
                source_scope=scope,
                config_path=str(config_path),
                command=command if isinstance(command, str) else None,
                args=args,
                url=url if isinstance(url, str) else None,
                transport=transport,
                metadata=metadata,
            )
        )


def degraded_mode_warnings(config_path: Path, payload: dict[str, object]) -> list[str]:
    warnings: list[str] = []
    serialized = json.dumps(payload, sort_keys=True).lower()
    raw_text = config_path.read_text(encoding="utf-8").lower() if config_path.is_file() else ""
    for marker in DEGRADED_MODE_MARKERS:
        marker_lower = marker.lower()
        if marker_lower in serialized or marker_lower in raw_text:
            warnings.append(
                f"Degraded Grok protection signal in {config_path.name}: {marker}. "
                "Guard hooks still run, but Grok may auto-approve some actions."
            )
    sandbox = payload.get("sandbox")
    if isinstance(sandbox, str) and sandbox.strip().lower() == "off":
        warnings.append(
            f"Degraded Grok protection signal in {config_path.name}: sandbox off. "
            "Guard hooks still run, but Grok may auto-approve some actions."
        )
    return warnings


def append_found_path(found_paths: list[str], path: Path) -> None:
    candidate = str(path)
    if candidate not in found_paths:
        found_paths.append(candidate)
