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


def contributions_dir() -> Path:
    return Path(__file__).resolve().parents[4] / "contributions" / "mcp-servers"


def catalog_id_for_mcp_id(mcp_id: str) -> str:
    return f"command.mcp-{mcp_id.removeprefix('mcp.')}"


def _normalized_tool_name(name: object) -> str:
    compact = "".join(ch.lower() if ch.isalnum() else "-" for ch in str(name).strip()).strip("-")
    return "-".join(part for part in compact.split("-") if part)


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
    if not isinstance(launch, dict) or launch.get("command") not in _ALLOWED_LAUNCHERS:
        raise ValueError(f"{filename} launch command is not an allowlisted package launcher")
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
        if normalized == "other" and state in {"inherit", "allow", "block"}:
            fallback = state
        if normalized == wanted and state in {"inherit", "allow", "block"}:
            return state
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
    ids: set[str] = set()
    for payload in payloads:
        mcp_id = payload.get("id")
        if not isinstance(mcp_id, str):
            raise ValueError("MCP contribution is missing id")
        if mcp_id in ids:
            raise ValueError(f"duplicate MCP contribution id {mcp_id}")
        ids.add(mcp_id)
        launch = payload.get("launch")
        package = launch.get("package") if isinstance(launch, dict) else None
        if not isinstance(package, str) or not package.strip():
            raise ValueError(f"{mcp_id} is missing a launch package")
        key = package.strip().lower()
        previous = packages.get(key)
        if previous is not None:
            raise ValueError(f"duplicate MCP launch package {package} for {previous} and {mcp_id}")
        packages[key] = mcp_id
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
