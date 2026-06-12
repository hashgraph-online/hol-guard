"""Grok Build CLI config, hook JSON, and detection helpers for HOL Guard."""

from __future__ import annotations

import json
import re
from pathlib import Path

from ..aibom_detection import enrich_mcp_server_metadata
from ..models import GuardArtifact
from .base import _json_payload

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
PRETOOL_MATCHERS = (
    "Bash",
    "Read",
    "Edit",
    "Grep",
    "MCPTool",
    "WebFetch",
    "run_terminal_command",
    "read_file",
    "grep",
    "web_fetch",
    "web_search",
    "write",
    "search_replace",
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


def build_pretool_hook_json(hook_command: str) -> dict[str, object]:
    entries: list[dict[str, object]] = []
    for matcher in PRETOOL_MATCHERS:
        entries.append(
            {
                "matcher": matcher,
                "hooks": [
                    {
                        "type": "command",
                        "command": hook_command,
                        "timeout": 30,
                    }
                ],
            }
        )
    return {"hooks": {"PreToolUse": entries}}


def build_managed_config_block() -> str:
    home = "~"
    lines = [
        GUARD_MANAGED_BEGIN,
        "# Permission rules below are managed by HOL Guard. Do not edit manually.",
        "[permission]",
        "deny = [",
        '  "Bash(hol-guard apps disconnect grok*)",',
        f'  "Bash(rm -rf {home}/.grok/hooks/hol-guard*)",',
        f'  "Read({home}/.grok/auth/**)",',
        f'  "Read({home}/.env)",',
        '  "Read(**/.env)",',
        '  "Read(**/.npmrc)",',
        f'  "Read({home}/.ssh/**)",',
        "]",
        GUARD_MANAGED_END,
    ]
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
    keys: set[str] = set()
    for field in ("env", "environment"):
        value = server_config.get(field)
        if isinstance(value, dict):
            keys.update(key for key in value if isinstance(key, str))
    return sorted(keys)


def _mcp_headers_keys(server_config: dict[str, object]) -> list[str]:
    headers = server_config.get("headers")
    if not isinstance(headers, dict):
        return []
    return sorted(key for key in headers if isinstance(key, str))


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
        metadata = enrich_mcp_server_metadata(
            {
                "env_keys": _mcp_env_keys(server_config),
                "headers_keys": _mcp_headers_keys(server_config),
            },
            command=command if isinstance(command, str) else None,
            args=args,
            url=url if isinstance(url, str) else None,
            transport=transport,
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
