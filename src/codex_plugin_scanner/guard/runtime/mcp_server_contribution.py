"""Validate and load Guard MCP server contribution files."""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Final, cast

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from ..native_cli_runtime_support import cli_runtime_support
from .extension_contribution import frozen_package_data

_SCHEMA_VERSION: Final = "guard.mcp-server-contribution.v1"
_ALLOWED_ICON_NAMES: Final = frozenset(
    {
        "HiMiniBolt",
        "HiMiniCommandLine",
        "HiMiniCube",
        "HiMiniFolder",
        "HiMiniGlobeAlt",
        "HiMiniCloud",
    }
)
_ALLOWED_LAUNCHERS: Final = frozenset({"bunx", "npx", "npm", "pnpm", "uvx", "yarn", "pipx"})
_TOOL_STATES: Final = frozenset({"inherit", "allow", "review", "block"})
_REMOTE_TOOL_STATES: Final = frozenset({"inherit", "review", "block"})


def _bound_grammar(operation: str, value: object) -> str | None:
    """Ask the resident for one contributed-MCP grammar answer.

    The grammar itself lives in the native runtime; a value that is not a
    string cannot be one of its inputs, so it is rejected here rather than
    sent. Nothing about the answer is recomputed or repaired locally.
    """
    if not isinstance(value, str):
        return None
    result = cli_runtime_support(operation, {"value": value})
    if result is not None and not isinstance(result, str):
        raise ValueError("native_cli_runtime_support_result_invalid")
    return result


def contributions_dir() -> Path:
    return Path(__file__).resolve().parents[4] / "contributions" / "mcp-servers"


def catalog_id_for_mcp_id(mcp_id: str) -> str:
    return f"command.mcp-{mcp_id.removeprefix('mcp.')}"


def direct_mcp_command_name(value: object) -> str | None:
    """Recognize a portable executable basename for tightening-only MCP defaults.

    Paths may be POSIX or Windows, independent of the host running Guard.
    Backslashes are treated as path separators on every host, including POSIX,
    so matching follows portable configured-command syntax rather than host
    filesystem basename semantics. This is catalog selection, never executable
    authentication or saved approval.
    """
    return _bound_grammar("direct_command_name", value)


def _normalized_tool_name(name: object) -> str:
    compact = "".join(ch.lower() if ch.isalnum() else "-" for ch in str(name).strip()).strip("-")
    return "-".join(part for part in compact.split("-") if part)


def normalized_remote_mcp_url(value: object) -> str | None:
    """Normalize a configured remote MCP URL, keeping its validated query."""
    return _bound_grammar("remote_url", value)


def remote_mcp_endpoint_identity(value: object) -> str | None:
    """Identify the launch endpoint a configured remote MCP URL points at."""
    return _bound_grammar("remote_endpoint_identity", value)


def normalized_remote_server_name(value: object) -> str | None:
    """Fold a contributed remote server name to its comparison form."""
    return _bound_grammar("remote_server_name", value)


def validate_mcp_contribution(payload: Mapping[str, object], *, filename: str = "contribution") -> None:
    try:
        _validator().validate(dict(payload))
    except ValidationError as exc:
        raise ValueError(f"{filename} failed MCP contribution schema: {exc.message}") from exc
    if payload.get("trustClass") != "external":
        raise ValueError(f"{filename} cannot self-declare a non-external trust class")
    if payload.get("activation") != "opt-in":
        raise ValueError(f"{filename} must use opt-in activation")
    mcp_id = payload.get("id")
    if not isinstance(mcp_id, str) or not mcp_id.startswith("mcp."):
        raise ValueError(f"{filename} has invalid id")
    icon = payload.get("icon")
    if isinstance(icon, dict) and icon.get("kind") == "react-icon" and icon.get("name") not in _ALLOWED_ICON_NAMES:
        raise ValueError(f"{filename} uses an icon name that is not allowlisted")
    launch = payload.get("launch")
    if not isinstance(launch, dict):
        raise ValueError(f"{filename} launch metadata is invalid")
    launch_kind = launch.get("kind")
    if launch_kind == "package-launcher":
        if launch.get("command") not in _ALLOWED_LAUNCHERS:
            raise ValueError(f"{filename} launch command is not an allowlisted package launcher")
    elif launch_kind == "direct-command":
        command = launch.get("command")
        if not isinstance(command, str) or direct_mcp_command_name(command) != command:
            raise ValueError(
                f"{filename} direct command must be a canonical lowercase executable basename, not a generic launcher"
            )
    elif launch_kind == "remote-http":
        if normalized_remote_mcp_url(launch.get("url")) is None:
            raise ValueError(
                f"{filename} remote launch URL must be a public HTTPS endpoint without credentials or a custom port"
            )
        server_names = launch.get("serverNames")
        normalized_names = (
            [normalized_remote_server_name(item) for item in server_names] if isinstance(server_names, list) else []
        )
        if (
            not normalized_names
            or any(item is None for item in normalized_names)
            or len(normalized_names) != len(set(normalized_names))
        ):
            raise ValueError(f"{filename} remote launch server names are invalid or duplicate")
    else:
        raise ValueError(f"{filename} launch kind is unsupported")
    tools = payload.get("tools")
    if not isinstance(tools, list) or not tools:
        raise ValueError(f"{filename} must declare tools")
    names = [
        _normalized_tool_name(item.get("name"))
        for item in tools
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    ]
    if not names or len(names) != len(set(names)):
        raise ValueError(f"{filename} declares duplicate tool names")
    for item in tools:
        if not isinstance(item, dict):
            continue
        state = item.get("state")
        if state not in _TOOL_STATES:
            raise ValueError(f"{filename} declares unsupported MCP tool state {state!r}")
        if launch_kind == "remote-http" and state not in _REMOTE_TOOL_STATES:
            raise ValueError(f"{filename} remote HTTP contributions cannot declare allow defaults")
        if launch_kind == "direct-command" and state == "allow":
            raise ValueError(f"{filename} direct-command contributions cannot declare allow defaults")


def _frozen_runtime() -> bool:
    return bool(getattr(sys, "frozen", False))


@lru_cache(maxsize=1)
def _validator() -> Draft202012Validator:
    schema = json.loads(_schema_bytes().decode("utf-8"))
    if not isinstance(schema, dict):
        raise ValueError("invalid MCP contribution schema")
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(cast(dict[str, object], schema))


def _schema_bytes() -> bytes:
    try:
        root = resources.files("codex_plugin_scanner.guard.contracts.data.mcp_servers")
        return (root / "contribution.v1.schema.json").read_bytes()
    except (FileNotFoundError, ModuleNotFoundError, OSError):
        frozen = frozen_package_data("mcp_servers", "contribution.v1.schema.json")
        if frozen is not None and frozen.is_file():
            return frozen.read_bytes()
        if _frozen_runtime():
            raise FileNotFoundError("frozen Guard is missing packaged MCP server contribution schema") from None
        repo_schema = Path(__file__).resolve().parents[4] / "contracts" / "mcp-servers" / "contribution.v1.schema.json"
        return repo_schema.read_bytes()
