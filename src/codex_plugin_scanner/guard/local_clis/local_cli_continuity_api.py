"""Dashboard projection for local custom Extension continuity."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..local_cli_trust import utc_now
from ..managed_controls.feature_flags import ManagedControlsFeatureFlags
from ..runtime.custom_extension_continuity import continuity_state_for_local_items

if TYPE_CHECKING:
    from ..store import GuardStore


def decorate_local_cli_continuity(
    store: GuardStore,
    items: list[dict[str, object]],
) -> dict[str, object]:
    flags = ManagedControlsFeatureFlags.from_environment()
    enabled = flags.allows_custom_extension_continuity()
    continuity = continuity_state_for_local_items(store, now=utc_now()) if enabled else {}
    for item in items:
        cli_id = item.get("cli_id")
        item["continuity"] = continuity.get(cli_id) if isinstance(cli_id, str) else None
    return {
        "sync_local_only": not enabled,
        "continuity_enabled": enabled,
        "summary": (
            "Custom extensions stay on this device. Guard Cloud can keep the same extension on your other machines."
        ),
    }
