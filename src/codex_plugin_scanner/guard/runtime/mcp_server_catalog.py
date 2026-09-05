"""Build command-extension catalog values from MCP server contributions."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

from .command_extension_specs import CommandExtensionValues
from .command_permission_catalog import permissions_for_action_classes
from .mcp_server_contribution import catalog_id_for_mcp_id, load_mcp_contribution_payloads


def _string_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, str) and item.strip())


def _action_class_for(mcp_id: str) -> str:
    suffix = mcp_id.removeprefix("mcp.").replace(".", "-dot-").strip()
    return f"mcp {suffix} tool"


def _values_for_payload(payload: Mapping[str, object]) -> CommandExtensionValues:
    mcp_id = payload.get("id")
    if not isinstance(mcp_id, str):
        raise ValueError("MCP contribution is missing id")
    launch = payload.get("launch")
    if not isinstance(launch, dict):
        raise ValueError(f"{mcp_id} is missing launch metadata")
    command = launch.get("command")
    package = launch.get("package")
    if not isinstance(command, str) or not command.strip():
        raise ValueError(f"{mcp_id} launch command is invalid")
    if not isinstance(package, str) or not package.strip():
        raise ValueError(f"{mcp_id} launch package is invalid")
    name = payload.get("name")
    description = payload.get("description")
    version = payload.get("version")
    if not isinstance(name, str) or not isinstance(description, str) or not isinstance(version, str):
        raise ValueError(f"{mcp_id} is missing catalog metadata")
    safer = _string_tuple(payload.get("saferAlternatives"))
    if not safer:
        raise ValueError(f"{mcp_id} requires safer alternatives")
    risk_classes = _string_tuple(payload.get("riskClasses"))
    if not risk_classes:
        raise ValueError(f"{mcp_id} requires risk classes")
    extension_id = catalog_id_for_mcp_id(mcp_id)
    action_classes = (_action_class_for(mcp_id),)
    example = f"{command} -y {package}"
    return {
        "extension_id": extension_id,
        "version": version,
        "name": name,
        "description": description,
        "action_classes": action_classes,
        "risk_classes": risk_classes,
        "safer_alternatives": safer,
        "rules": (),
        "permissions": permissions_for_action_classes(
            extension_id,
            version,
            action_classes,
            safer,
            configurable=False,
            example_command=example,
        ),
        "reference_urls": _string_tuple(payload.get("referenceUrls")),
        "source": "built-in",
        "required": False,
        "delegated_protection": None,
        "ecosystem_ids": (),
        "executables": (command,),
        "project_markers": (),
    }


def mcp_command_extension_values() -> tuple[CommandExtensionValues, ...]:
    return tuple(_values_for_payload(payload) for payload in load_mcp_contribution_payloads())


MCP_COMMAND_EXTENSION_VALUES: Final[tuple[CommandExtensionValues, ...]] = mcp_command_extension_values()
