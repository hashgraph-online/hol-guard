"""MCP identity primitives used by Guard runtime protections."""

from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import PurePath


@dataclass(frozen=True, slots=True)
class McpServerIdentity:
    """Stable identity for a local MCP server definition."""

    config_path: str
    command: str
    args_hash: str
    package_name: str | None
    package_version: str | None
    transport: str
    env_keys: tuple[str, ...]
    identity_hash: str


@dataclass(frozen=True, slots=True)
class McpToolIdentity:
    """Stable identity for a tool exposed by an MCP server."""

    server_hash: str
    tool_name: str
    schema_hash: str
    description_hash: str
    identity_hash: str


def build_mcp_server_identity(
    *,
    config_path: str,
    command: str,
    args: tuple[str, ...],
    transport: str,
    env: dict[str, str] | None = None,
    env_keys: tuple[str, ...] = (),
) -> McpServerIdentity:
    """Build a stable server identity using env key names only."""

    package_name, package_version = _package_identity(command, args)
    env_key_set = {key.strip() for key in env_keys if key.strip()}
    if env is not None:
        env_key_set.update(key.strip() for key in env if key.strip())
    env_keys = tuple(sorted(env_key_set))
    args_hash = _stable_digest(list(args))
    payload = {
        "command": _command_name(command),
        "args_hash": args_hash,
        "package_name": package_name,
        "package_version": package_version,
        "transport": transport,
        "env_keys": list(env_keys),
    }
    return McpServerIdentity(
        config_path=config_path,
        command=command,
        args_hash=args_hash,
        package_name=package_name,
        package_version=package_version,
        transport=transport,
        env_keys=env_keys,
        identity_hash=_stable_digest(payload),
    )


def build_mcp_tool_identity(
    *,
    server_hash: str,
    tool_name: str,
    schema: object | None = None,
    description: str | None = None,
) -> McpToolIdentity:
    """Build a stable identity for one MCP tool definition."""

    schema_hash = _stable_digest(_normalize_json_value(schema))
    description_hash = _stable_digest((description or "").strip())
    payload = {
        "server_hash": server_hash,
        "tool_name": tool_name,
        "schema_hash": schema_hash,
        "description_hash": description_hash,
    }
    return McpToolIdentity(
        server_hash=server_hash,
        tool_name=tool_name,
        schema_hash=schema_hash,
        description_hash=description_hash,
        identity_hash=_stable_digest(payload),
    )


def mcp_server_identity_metadata(identity: McpServerIdentity) -> dict[str, object]:
    """Serialize an MCP server identity into non-secret Guard metadata."""

    return {
        "config_path": identity.config_path,
        "command": identity.command,
        "args_hash": identity.args_hash,
        "package_name": identity.package_name,
        "package_version": identity.package_version,
        "transport": identity.transport,
        "env_keys": list(identity.env_keys),
        "identity_hash": identity.identity_hash,
    }


def mcp_tool_identity_metadata(identity: McpToolIdentity) -> dict[str, object]:
    """Serialize an MCP tool identity into Guard metadata."""

    return {
        "server_hash": identity.server_hash,
        "tool_name": identity.tool_name,
        "schema_hash": identity.schema_hash,
        "description_hash": identity.description_hash,
        "identity_hash": identity.identity_hash,
    }


def _package_identity(command: str, args: tuple[str, ...]) -> tuple[str | None, str | None]:
    command_name = _command_name(command)
    if command_name not in {"bunx", "npx", "pnpm", "uvx", "yarn", "pipx"}:
        return None, None
    package_token = _package_token(command_name=command_name, args=args)
    if package_token is None:
        return None, None
    return _split_package_token(package_token)


def _package_token(*, command_name: str, args: tuple[str, ...]) -> str | None:
    index = 0
    positional_index = 0
    while index < len(args):
        value = args[index].strip()
        if not value:
            index += 1
            continue
        if positional_index == 0 and value in _launcher_non_package_subcommands(command_name):
            return None
        if positional_index == 0 and value in _launcher_subcommands(command_name):
            index += 1
            positional_index += 1
            continue
        if value in {"--package", "-p"} and index + 1 < len(args):
            return args[index + 1].strip() or None
        if value.startswith("--package="):
            package = value.partition("=")[2].strip()
            return package or None
        if value in {"--spec", "--from"} and index + 1 < len(args):
            package = args[index + 1].strip()
            return package or None
        if value.startswith("--spec=") or value.startswith("--from="):
            package = value.partition("=")[2].strip()
            return package or None
        if _option_takes_value(command_name=command_name, option=value):
            index += 2
            continue
        if value.startswith("-"):
            index += 1
            continue
        if _looks_like_runtime_path(value):
            index += 1
            positional_index += 1
            continue
        return value
    return None


def _split_package_token(value: str) -> tuple[str | None, str | None]:
    if value.startswith("@"):
        scope, slash, remainder = value.partition("/")
        if not slash or not remainder:
            return value, None
        name, at_sign, version = remainder.rpartition("@")
        if not at_sign or not name:
            return value, None
        return f"{scope}/{name}", version or None
    name, at_sign, version = value.rpartition("@")
    if not at_sign or not name:
        return value, None
    return name, version or None


def _command_name(value: str) -> str:
    command_name = PurePath(value.replace("\\", "/")).name.lower()
    if command_name.endswith((".cmd", ".exe", ".bat", ".ps1")):
        command_name = PurePath(command_name).stem
    return command_name


def _option_takes_value(*, command_name: str, option: str) -> bool:
    option_name = option.strip()
    if not option_name.startswith("-"):
        return False
    if option_name.startswith("--") and "=" in option_name:
        return False
    return option_name in _value_options_for_command(command_name)


def _launcher_subcommands(command_name: str) -> set[str]:
    command_specific: dict[str, set[str]] = {
        "pipx": {"run"},
        "pnpm": {"dlx"},
        "yarn": {"dlx"},
    }
    return command_specific.get(command_name, set())


def _launcher_non_package_subcommands(command_name: str) -> set[str]:
    command_specific: dict[str, set[str]] = {
        "pnpm": {"exec"},
        "yarn": {"exec"},
    }
    return command_specific.get(command_name, set())


def _value_options_for_command(command_name: str) -> set[str]:
    common = {
        "--cache",
        "--cache-dir",
        "--call",
        "--cwd",
        "--prefix",
        "--python",
        "--registry",
        "--userconfig",
    }
    command_specific: dict[str, set[str]] = {
        "bunx": {"-c", "--config", "--package"},
        "npx": {"-c", "-w", "--workspace"},
        "pipx": {"--index-url", "--pip-args", "--suffix"},
        "pnpm": {"-c", "-C", "--dir", "--filter"},
        "uvx": {"--extra-index-url", "--find-links", "--index-url", "--project"},
        "yarn": {"--cwd", "--use-yarnrc"},
    }
    return common | command_specific.get(command_name, set())


def _looks_like_runtime_path(value: str) -> bool:
    normalized = value.strip().replace("\\", "/")
    if normalized.startswith(("./", "../", "~/", "/")):
        return True
    suffix = PurePath(normalized).suffix.lower()
    return suffix in {".cjs", ".js", ".json", ".mjs", ".py", ".ts"}


def _stable_digest(value: object) -> str:
    payload = json.dumps(
        _normalize_json_value(value),
        sort_keys=True,
        separators=(",", ":"),
    )
    return sha256(payload.encode()).hexdigest()


def _normalize_json_value(value: object) -> object:
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, tuple | list):
        return [_normalize_json_value(item) for item in value]
    if isinstance(value, set | frozenset):
        return [_normalize_json_value(item) for item in sorted(value, key=str)]
    if isinstance(value, dict):
        return {
            str(key): _normalize_json_value(item) for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, PurePath):
        return str(value)
    return repr(value)


__all__ = [
    "McpServerIdentity",
    "McpToolIdentity",
    "build_mcp_server_identity",
    "build_mcp_tool_identity",
    "mcp_server_identity_metadata",
    "mcp_tool_identity_metadata",
]
