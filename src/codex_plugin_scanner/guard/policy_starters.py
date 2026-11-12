"""Starter policies for ``hol-guard policy init``.

The starters mirror the Policy Studio starter gallery so a policy begun in the browser and one begun
with ``policy init`` read the same. The native runtime owns them (``policy_document_starters.rs``);
``docs/policy/STARTERS.md`` lists the cross-reference.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

# The schema's ``$id`` stays https://guard.hashgraphonline.com/schema/policy/v1alpha1; this is where it is served.
POLICY_SCHEMA_URL = "https://hol.org/schema/policy/v1alpha1"
POLICY_MODELINE = f"# yaml-language-server: $schema={POLICY_SCHEMA_URL}"
# Modelines written by earlier releases; ``policy fmt --check`` still accepts them.
LEGACY_POLICY_MODELINES = ("# yaml-language-server: $schema=https://guard.hashgraphonline.com/schema/policy/v1alpha1",)
DEFAULT_STARTER = "safe-defaults"


def with_modeline(text: str) -> str:
    """Prefix canonical policy YAML with the editor schema modeline unless it is already there."""

    return text if text.startswith(POLICY_MODELINE) else f"{POLICY_MODELINE}\n{text}"


def policy_starters() -> list[dict[str, str]]:
    """``{"id", "name", "summary"}`` for every starter, in gallery order."""

    from .native_policy_document import NativePolicyDocumentError, policy_query

    listing: Any = policy_query("starters", {})
    if not isinstance(listing, list) or not all(
        isinstance(item, dict)
        and set(item) == {"id", "name", "summary"}
        and all(isinstance(value, str) for value in item.values())
        for item in listing
    ):
        raise NativePolicyDocumentError("native_policy_starters_invalid")
    return listing


def render_starter_yaml(starter_id: str, *, now: datetime | None = None) -> str | None:
    """The text of a new ``guard-policy.yaml`` for ``starter_id``, or ``None`` for an unknown starter."""

    from .native_policy_document import NativePolicyDocumentError, policy_query

    created_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    text: Any = policy_query("starter", {"id": starter_id, "created_at": created_at})
    if text is not None and not isinstance(text, str):
        raise NativePolicyDocumentError("native_policy_starters_invalid")
    return text


__all__ = [
    "DEFAULT_STARTER",
    "LEGACY_POLICY_MODELINES",
    "POLICY_MODELINE",
    "POLICY_SCHEMA_URL",
    "policy_starters",
    "render_starter_yaml",
    "with_modeline",
]
