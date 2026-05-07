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
    if command_name not in {"bunx", "npm", "npx", "pnpm", "uvx", "yarn", "pipx"}:
        return None, None
    package_token = _package_token(command_name=command_name, args=args)
    if package_token is None:
        return None, None
    return _split_package_token(package_token)


def _package_token(*, command_name: str, args: tuple[str, ...]) -> str | None:
    index = 0
    positional_index = 0
    package_selector_flags = _package_selector_flags(command_name)
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
        if value in package_selector_flags and index + 1 < len(args):
            return args[index + 1].strip() or None
        if "--package" in package_selector_flags and value.startswith("--package="):
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
    pip_style_name, pip_style_version = _split_pip_style_specifier(value)
    if pip_style_name is not None:
        return pip_style_name, pip_style_version
    if value.startswith("@"):
        scope, slash, remainder = value.partition("/")
        if not slash or not remainder:
            return value, None
        name, at_sign, version = remainder.rpartition("@")
        if not at_sign or not name:
            return value, None
        return f"{scope}/{name}", version or None
    if _url_authority_contains_userinfo(value):
        return _redact_url_userinfo(value), None
    name, at_sign, version = value.rpartition("@")
    if not at_sign or not name:
        return value, None
    return name, version or None


def _command_name(value: str) -> str:
    command_name = PurePath(value.replace("\\", "/")).name.lower()
    if command_name.endswith((".cmd", ".exe", ".bat", ".ps1")):
        command_name = PurePath(command_name).stem
    return command_name


def _split_pip_style_specifier(value: str) -> tuple[str | None, str | None]:
    if "://" in value:
        return None, None
    for separator in ("===", "==", "~=", "!=", "<=", ">=", "<", ">"):
        name, matched, version = value.partition(separator)
        if not matched:
            continue
        normalized_name = name.strip()
        normalized_version = version.strip()
        if not normalized_name or not normalized_version:
            continue
        if separator in {"==", "==="}:
            return normalized_name, normalized_version
        return normalized_name, f"{separator}{normalized_version}"
    return None, None


def _url_authority_contains_userinfo(value: str) -> bool:
    authority_bounds = _url_authority_bounds(value)
    if authority_bounds is None:
        return False
    authority_start, authority_end = authority_bounds
    authority = value[authority_start:authority_end]
    return "@" in authority


def _redact_url_userinfo(value: str) -> str:
    authority_bounds = _url_authority_bounds(value)
    if authority_bounds is None:
        return value
    authority_start, authority_end = authority_bounds
    authority = value[authority_start:authority_end]
    at_index = authority.rfind("@")
    if at_index < 0:
        return value
    redacted_authority = authority[at_index + 1 :]
    return f"{value[:authority_start]}{redacted_authority}{value[authority_end:]}"


def _url_authority_bounds(value: str) -> tuple[int, int] | None:
    scheme_index = value.find("://")
    if scheme_index < 0:
        return None
    authority_start = scheme_index + 3
    authority_end = len(value)
    for delimiter in ("/", "?", "#"):
        delimiter_index = value.find(delimiter, authority_start)
        if delimiter_index >= 0:
            authority_end = min(authority_end, delimiter_index)
    return authority_start, authority_end


def _option_takes_value(*, command_name: str, option: str) -> bool:
    option_name = option.strip()
    if not option_name.startswith("-"):
        return False
    if option_name.startswith("--") and "=" in option_name:
        return False
    return option_name in _value_options_for_command(command_name)


def _launcher_subcommands(command_name: str) -> set[str]:
    command_specific: dict[str, set[str]] = {
        "npm": {"exec", "x"},
        "pipx": {"run"},
        "pnpm": {"dlx"},
        "yarn": {"dlx"},
    }
    return command_specific.get(command_name, set())


def _launcher_non_package_subcommands(command_name: str) -> set[str]:
    command_specific: dict[str, set[str]] = {
        "npm": {"run"},
        "pnpm": {"exec", "run"},
        "yarn": {"exec", "run"},
    }
    return command_specific.get(command_name, set())


def _package_selector_flags(command_name: str) -> set[str]:
    command_specific: dict[str, set[str]] = {
        "bunx": {"--package", "-p"},
        "npm": {"--package"},
        "npx": {"--package", "-p"},
        "pnpm": {"--package"},
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
        "npm": {"-c", "-w", "--workspace"},
        "npx": {"-c", "-w", "--workspace"},
        "pipx": {"-i", "--index-url", "--pip-args", "--suffix", "--with"},
        "pnpm": {"-c", "-C", "--allow-build", "--dir", "--filter"},
        "uvx": {
            "-b",
            "-c",
            "-f",
            "-i",
            "-p",
            "-w",
            "--default-index",
            "--build-constraints",
            "--constraints",
            "--directory",
            "--env-file",
            "--extra-index-url",
            "--find-links",
            "--index",
            "--index-url",
            "--keyring-provider",
            "--overrides",
            "--project",
            "--with",
            "--with-editable",
            "--with-requirements",
        },
        "yarn": {"--cwd", "--use-yarnrc"},
    }
    return common | command_specific.get(command_name, set())


def _looks_like_runtime_path(value: str) -> bool:
    normalized = value.strip().replace("\\", "/")
    if normalized.startswith(("./", "../", "~/", "/")):
        return True
    suffix = PurePath(normalized).suffix.lower()
    if suffix not in {".cjs", ".js", ".json", ".mjs", ".py", ".ts"}:
        return False
    return "/" in normalized and not normalized.startswith("@")


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
