"""Whether the configured protection posture is actually in effect.

``protection`` names the posture the user chose; it says nothing about whether
any harness is still wired to Guard. Status and doctor print that posture at the
top of their panel, so an install whose hook registration has fallen out reads as
"Protected" while nothing is being checked. These helpers let the renderers say
so instead.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

PROTECTION_NOT_IN_EFFECT_DETAIL = "not in effect: no app has Guard hooks registered"
_ENFORCING_SETUP_STATUS = "active"


def _artifact_count(value: object) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return 0
    return 0


def _harness_is_enforcing(entry: Mapping[str, object]) -> bool | None:
    """Judge one harness row, or ``None`` when the row has no coverage evidence.

    Doctor rows carry ``setup_status`` straight from the adapter. A scanned
    status row carries ``guard_registered``, which is true only when a detected
    artifact is a Guard hook or launcher, not merely because the host still has
    skills or MCP servers. ``artifact_count`` remains the fallback for payloads
    that predate that flag. A row built without scanning (``artifacts_scanned``
    false) hardcodes a zero count and is not evidence of a lapse.
    """

    setup_status = entry.get("setup_status")
    if isinstance(setup_status, str) and setup_status.strip():
        return setup_status.strip() == _ENFORCING_SETUP_STATUS
    if entry.get("artifacts_scanned") is False:
        return None
    if "guard_registered" in entry:
        return bool(entry.get("managed")) and entry.get("guard_registered") is True
    if "artifact_count" not in entry:
        return None
    return bool(entry.get("managed")) and _artifact_count(entry.get("artifact_count")) > 0


def protection_is_in_effect(entries: Iterable[object]) -> bool:
    """Report whether at least one harness could act on the posture.

    An empty sequence returns ``True``: a payload that carries no harness rows is
    missing the evidence, not proof that protection has lapsed, and a renderer
    must not raise an alarm it cannot support. The same holds when every row is
    present but none of them were scanned.
    """

    rows = [entry for entry in entries if isinstance(entry, Mapping)]
    if not rows:
        return True
    judgments = [_harness_is_enforcing(row) for row in rows]
    if any(judgment is True for judgment in judgments):
        return True
    return not any(judgment is False for judgment in judgments)


__all__ = ["PROTECTION_NOT_IN_EFFECT_DETAIL", "protection_is_in_effect"]
