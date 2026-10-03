"""Validate and load Guard MCP server contribution files."""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from functools import lru_cache
from importlib import resources
from ipaddress import IPv6Address, ip_address
from pathlib import Path
from typing import Final, cast
from urllib.parse import urlsplit, urlunsplit

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

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
_REMOTE_MCP_URL_MAX_LENGTH: Final = 260
_HEX_DIGITS: Final = frozenset("0123456789abcdefABCDEF")
_UNRESERVED_PATH_CHARS: Final = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
_SUB_DELIMITERS: Final = frozenset("!$&'()*+,;=")
_REMOTE_PATH_CHARS: Final = _UNRESERVED_PATH_CHARS | _SUB_DELIMITERS | frozenset(":@/")
_REMOTE_QUERY_CHARS: Final = _REMOTE_PATH_CHARS | frozenset("?")


def contributions_dir() -> Path:
    return Path(__file__).resolve().parents[4] / "contributions" / "mcp-servers"


def catalog_id_for_mcp_id(mcp_id: str) -> str:
    return f"command.mcp-{mcp_id.removeprefix('mcp.')}"


def _normalized_tool_name(name: object) -> str:
    compact = "".join(ch.lower() if ch.isalnum() else "-" for ch in str(name).strip()).strip("-")
    return "-".join(part for part in compact.split("-") if part)


def _valid_dns_hostname(host: str) -> bool:
    if len(host) > 253 or not host.isascii():
        return False
    labels = host.split(".")
    return all(
        1 <= len(label) <= 63
        and label[0].isalnum()
        and label[-1].isalnum()
        and all(ch.isalnum() or ch == "-" for ch in label)
        for label in labels
    )


def _normalized_remote_component(
    value: str,
    *,
    allowed_chars: frozenset[str],
    empty_default: str,
) -> str | None:
    candidate = value or empty_default
    output: list[str] = []
    index = 0
    while index < len(candidate):
        character = candidate[index]
        if character != "%":
            if character not in allowed_chars:
                return None
            output.append(character)
            index += 1
            continue
        if index + 2 >= len(candidate):
            return None
        escape = candidate[index + 1 : index + 3]
        if any(character not in _HEX_DIGITS for character in escape):
            return None
        decoded = chr(int(escape, 16))
        if ord(decoded) < 0x20 or ord(decoded) == 0x7F:
            return None
        if decoded in _UNRESERVED_PATH_CHARS:
            output.append(decoded)
        else:
            output.append(f"%{escape.upper()}")
        index += 3
    return "".join(output)


def _remove_remote_dot_segments(path: str) -> str:
    segments = path.split("/")
    resolved: list[str] = []
    for segment in segments:
        if segment == "..":
            if resolved:
                resolved.pop()
        elif segment != ".":
            resolved.append(segment)
    if segments[-1] in {".", ".."}:
        resolved.append("")
    normalized = "/".join(resolved) or "/"
    if path.startswith("/") and not normalized.startswith("/"):
        normalized = f"/{normalized}"
    return normalized


def _normalized_remote_path(path: str) -> str | None:
    normalized = _normalized_remote_component(path, allowed_chars=_REMOTE_PATH_CHARS, empty_default="/")
    if normalized is None:
        return None
    return _remove_remote_dot_segments(normalized)


def _normalized_remote_query(query: str) -> str | None:
    return _normalized_remote_component(query, allowed_chars=_REMOTE_QUERY_CHARS, empty_default="")


def normalized_remote_mcp_url(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    if not value or value != value.strip() or not value.isascii():
        return None
    if any(ord(character) <= 0x20 or ord(character) == 0x7F for character in value):
        return None
    candidate = value
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return None
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    if port not in {None, 443}:
        return None
    raw_host = parsed.hostname.lower()
    if raw_host.endswith(".."):
        return None
    host = raw_host[:-1] if raw_host.endswith(".") else raw_host
    if not host:
        return None
    try:
        address = ip_address(host)
    except ValueError:
        if all(ch.isdigit() or ch == "." for ch in host):
            return None
        if host == "localhost" or host.endswith(".localhost") or "." not in host or not _valid_dns_hostname(host):
            return None
    else:
        if isinstance(address, IPv6Address) and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        if not address.is_global:
            return None
        host = str(address)
    netloc = f"[{host}]" if ":" in host else host
    path = _normalized_remote_path(parsed.path)
    query = _normalized_remote_query(parsed.query)
    if path is None or query is None:
        return None
    endpoint = urlunsplit(("https", netloc, path, "", ""))
    if len(endpoint) > _REMOTE_MCP_URL_MAX_LENGTH:
        return None
    return urlunsplit(("https", netloc, path, query, ""))


def remote_mcp_endpoint_identity(value: object) -> str | None:
    normalized = normalized_remote_mcp_url(value)
    if normalized is None:
        return None
    return normalized.partition("?")[0]


def normalized_remote_server_name(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = " ".join(value.strip().casefold().split())
    return normalized or None


def load_mcp_contribution_payloads(root: Path | None = None) -> tuple[dict[str, object], ...]:
    if root is not None:
        return _load_from_directory(root)
    packaged = _load_packaged_payloads()
    if packaged:
        return packaged
    return _load_from_directory(contributions_dir())


def validate_mcp_contribution_file(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path.name} must contain an object")
    validate_mcp_contribution(payload, filename=path.name)
    return payload


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


def mcp_catalog_ids(root: Path | None = None) -> frozenset[str]:
    return frozenset(catalog_id_for_mcp_id(str(item["id"])) for item in load_mcp_contribution_payloads(root))


def mcp_tool_state(payload: Mapping[str, object], tool_name: str) -> str:
    tools = payload.get("tools")
    if not isinstance(tools, list):
        return "inherit"
    wanted = _normalized_tool_name(tool_name)
    fallback = "inherit"
    for item in tools:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        state = item.get("state")
        normalized = _normalized_tool_name(name) if isinstance(name, str) else ""
        if normalized == "other" and state in _TOOL_STATES:
            fallback = cast(str, state)
        if normalized == wanted and state in _TOOL_STATES:
            return cast(str, state)
    return fallback


def mcp_payload_for_catalog_id(extension_id: str) -> dict[str, object] | None:
    return _contribution_index().get(extension_id)


def catalog_mcp_fields(extension_id: str) -> dict[str, object] | None:
    payload = _contribution_index().get(extension_id)
    if payload is None:
        return None
    launch = payload.get("launch")
    tools = payload.get("tools")
    if not isinstance(launch, dict) or not isinstance(tools, list):
        return None
    return {
        "surface": "mcp",
        "mcp_launch": dict(launch),
        "mcp_tools": [dict(item) for item in tools if isinstance(item, dict)],
    }


def reset_mcp_contribution_cache() -> None:
    _contribution_index.cache_clear()
    _validator.cache_clear()


def _load_from_directory(directory: Path) -> tuple[dict[str, object], ...]:
    if not directory.is_dir():
        return ()
    files = sorted(directory.glob("mcp.*.json"))
    return _finalize_payloads(tuple(validate_mcp_contribution_file(path) for path in files))


def _frozen_runtime() -> bool:
    return bool(getattr(sys, "frozen", False))


def _load_packaged_payloads() -> tuple[dict[str, object], ...]:
    try:
        root = resources.files("codex_plugin_scanner.guard.contracts.data.mcp_servers") / "contributions"
        names = [item for item in root.iterdir() if item.name.startswith("mcp.") and item.name.endswith(".json")]
    except (FileNotFoundError, ModuleNotFoundError, OSError, AttributeError):
        frozen = frozen_package_data("mcp_servers", "contributions")
        if frozen is None or not frozen.is_dir():
            if _frozen_runtime():
                raise FileNotFoundError("frozen Guard is missing packaged MCP server contributions") from None
            return ()
        names = [item for item in frozen.iterdir() if item.name.startswith("mcp.") and item.name.endswith(".json")]
    if not names:
        if _frozen_runtime():
            raise FileNotFoundError("frozen Guard is missing packaged MCP server contributions")
        return ()
    payloads: list[dict[str, object]] = []
    for item in sorted(names, key=lambda entry: entry.name):
        payload = json.loads(item.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError(f"{item.name} must contain an object")
        validate_mcp_contribution(payload, filename=item.name)
        payloads.append(payload)
    return _finalize_payloads(tuple(payloads))


def _finalize_payloads(payloads: tuple[dict[str, object], ...]) -> tuple[dict[str, object], ...]:
    packages: dict[str, str] = {}
    remote_urls: dict[str, str] = {}
    remote_names: dict[str, str] = {}
    ids: set[str] = set()
    for payload in payloads:
        mcp_id = payload.get("id")
        if not isinstance(mcp_id, str):
            raise ValueError("MCP contribution is missing id")
        if mcp_id in ids:
            raise ValueError(f"duplicate MCP contribution id {mcp_id}")
        ids.add(mcp_id)
        launch = payload.get("launch")
        if not isinstance(launch, dict):
            raise ValueError(f"{mcp_id} is missing launch metadata")
        if launch.get("kind") == "package-launcher":
            package = launch.get("package")
            if not isinstance(package, str) or not package.strip():
                raise ValueError(f"{mcp_id} is missing a launch package")
            key = package.strip().lower()
            previous = packages.get(key)
            if previous is not None:
                raise ValueError(f"duplicate MCP launch package {package} for {previous} and {mcp_id}")
            packages[key] = mcp_id
            continue
        if launch.get("kind") != "remote-http":
            raise ValueError(f"{mcp_id} has unsupported launch metadata")
        remote_url = normalized_remote_mcp_url(launch.get("url"))
        if remote_url is None:
            raise ValueError(f"{mcp_id} is missing a valid remote URL")
        remote_endpoint = remote_mcp_endpoint_identity(remote_url)
        if remote_endpoint is None:
            raise ValueError(f"{mcp_id} is missing a valid remote endpoint")
        previous_url = remote_urls.get(remote_endpoint)
        if previous_url is not None:
            raise ValueError(f"duplicate MCP remote endpoint {remote_endpoint} for {previous_url} and {mcp_id}")
        remote_urls[remote_endpoint] = mcp_id
        server_names = launch.get("serverNames")
        if not isinstance(server_names, list):
            raise ValueError(f"{mcp_id} is missing remote server names")
        for raw_name in server_names:
            server_name = normalized_remote_server_name(raw_name)
            if server_name is None:
                raise ValueError(f"{mcp_id} has invalid remote server name")
            previous_name = remote_names.get(server_name)
            if previous_name is not None:
                raise ValueError(f"duplicate MCP remote server name {raw_name} for {previous_name} and {mcp_id}")
            remote_names[server_name] = mcp_id
    return payloads


@lru_cache(maxsize=1)
def _contribution_index() -> dict[str, dict[str, object]]:
    index: dict[str, dict[str, object]] = {}
    for payload in load_mcp_contribution_payloads():
        mcp_id = payload.get("id")
        if isinstance(mcp_id, str):
            index[catalog_id_for_mcp_id(mcp_id)] = payload
    return index


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
