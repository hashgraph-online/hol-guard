from __future__ import annotations

from pathlib import Path
from typing import Literal

InventoryItemKind = Literal[
    "agent",
    "daemon_plugin",
    "harness",
    "model_provider",
    "package",
    "prompt_pack",
    "skill",
    "mcp_server",
    "mcp_tool",
    "plugin",
    "channel",
    "hook",
    "overlay",
    "repository",
    "container_image",
    "policy",
    "secret_reference",
    "network_endpoint",
]

_DESCRIPTION_METADATA_KEYS = (
    "description",
    "summary",
    "pluginDescription",
    "displayDescription",
)


def resolve_inventory_item_description(
    *,
    harness: str,
    item_kind: InventoryItemKind,
    display_name: str,
    metadata: dict[str, object],
    publisher: str | None = None,
    explicit_description: str | None = None,
    home_dir: Path | None = None,
    workspace_dir: Path | None = None,
) -> str:
    """The description an exported inventory item carries.

    The native ``inventory_export_redaction`` kind redacts the item's own text
    and builds the kind's fallback sentence; this only gathers the inputs.
    """
    from .inventory_contract_redaction import _native_export_redaction
    from .native_inventory_url_redaction import NativeInventoryUrlRedactionError, _cwd

    answer = _native_export_redaction(
        {
            "op": "item_description",
            "harness": harness,
            "item_kind": item_kind,
            "display_name": display_name,
            "publisher": publisher,
            "explicit_description": explicit_description,
            "metadata_descriptions": [
                value if isinstance(value, str) else None
                for value in (metadata.get(key) for key in _DESCRIPTION_METADATA_KEYS)
            ],
            "home_dir": None if home_dir is None else str(home_dir),
            "workspace_dir": None if workspace_dir is None else str(workspace_dir),
            "cwd": _cwd(),
        }
    )
    description = answer.get("description")
    if not isinstance(description, str):
        raise NativeInventoryUrlRedactionError("native_inventory_url_redaction_unavailable")
    return description
