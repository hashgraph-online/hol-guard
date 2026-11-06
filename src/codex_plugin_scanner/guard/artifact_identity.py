"""Shared artifact identity normalization helpers."""

from __future__ import annotations

from collections.abc import Collection


def artifact_family_key(
    artifact_id: str | None,
    *,
    allowed_families: Collection[str],
) -> str | None:
    """Normalize an artifact identity to its permitted ``family:<name>`` key."""

    if artifact_id is None or not artifact_id.strip():
        return None
    if artifact_id.startswith("family:"):
        family = artifact_id.removeprefix("family:").strip().lower()
        return artifact_id if family in allowed_families else None
    parts = artifact_id.split(":")
    if len(parts) < 3:
        return None
    family = parts[2].strip().lower()
    if family not in allowed_families:
        return None
    return f"family:{family}"
