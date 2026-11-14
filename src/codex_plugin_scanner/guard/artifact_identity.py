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


# The command risk groups a Guard Cloud rule may name. They match the groups
# the native compiler accepts (`policy_document_risk_groups::RISK_GROUPS`).
RISK_GROUPS = frozenset(
    {
        "deletes",
        "bulk_changes",
        "sending_and_sharing",
        "secrets",
        "code_and_deploys",
        "packages_and_scripts",
    }
)
RISK_GROUP_PREFIX = "risk-group:"


def scoped_policy_artifact_key(
    artifact_id: str | None,
    *,
    allowed_families: Collection[str],
) -> str | None:
    """The artifact key a harness- or global-scoped policy row is stored under.

    A risk-group rule keeps its ``risk-group:<group>`` id: the hook looks the
    row up by that id, and the same row without an id would read as a rule for
    every action in the harness. An id that names no known group is refused for
    the same reason rather than stored without one.
    """

    candidate = (artifact_id or "").strip()
    prefix = candidate[: len(RISK_GROUP_PREFIX)]
    if prefix.isascii() and prefix.lower() == RISK_GROUP_PREFIX:
        group = candidate[len(RISK_GROUP_PREFIX) :].strip().lower()
        if group in RISK_GROUPS:
            return f"{RISK_GROUP_PREFIX}{group}"
        msg = "unsupported_scoped_policy_risk_group"
        raise ValueError(msg)
    return artifact_family_key(artifact_id, allowed_families=allowed_families)
