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
            "harness": _wire_text(harness),
            "item_kind": _wire_text(item_kind),
            "display_name": _wire_text(display_name),
            "publisher": _wire_text(publisher),
            "explicit_description": _wire_text(explicit_description),
            "metadata_descriptions": [
                _wire_text(value) if isinstance(value, str) else None
                for value in (metadata.get(key) for key in _DESCRIPTION_METADATA_KEYS)
            ],
            "home_dir": None if home_dir is None else _wire_text(str(home_dir)),
            "workspace_dir": None if workspace_dir is None else _wire_text(str(workspace_dir)),
            "cwd": _wire_text(_cwd()),
        }
    )
    description = answer.get("description")
    if not isinstance(description, str):
        raise NativeInventoryUrlRedactionError("native_inventory_url_redaction_unavailable")
    return description


def _wire_text(value: str | None) -> str | None:
    """The text with each lone surrogate as U+FFFD, the way the JSON transport reads one.

    A surrogate-escaped name or path cannot be encoded as UTF-8, so sending it
    unchanged would refuse the whole export.
    """
    if value is None:
        return None
    return value.encode("utf-16", "surrogatepass").decode("utf-16", "replace")
