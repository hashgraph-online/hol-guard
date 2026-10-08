"""Check executable hook conflicts before any installation writes."""

from collections.abc import Sequence

from .codex_hook_inventory import CodexHookInventory
from .codex_hook_registration import require_codex_hook_owner


def require_codex_inventory_owners(inventories: Sequence[CodexHookInventory]) -> None:
    """Preserve inactive handlers, including when the global feature is enabled.

    Inventory activation describes group and handler flags independently of
    the current global feature switch. Installation enables that switch, so
    otherwise active commands still require verified ownership beforehand.
    """
    for inventory in inventories:
        for record in inventory.records:
            if record.active and record.command is not None:
                require_codex_hook_owner(record.command, ownership=record.ownership)
