"""Which extension governs which step of a paused command, for the review screen.

This is the advisory half of the Extensions affordance. The recommendation says
"allowing these permissions settles this command" and the resident has to agree
before it is shown. Coverage says only "this step matched this extension", so
it is a projection of evidence Guard already recorded onto the catalog labels
the dashboard needs, with no decision in it: it changes nothing about what Guard
allows, denies or asks, and the card it feeds has no approve button.

Keeping it here rather than in the resident keeps it out of the decision path.
The only thing it adds to a stored hint is a label and a deep link per catalog
id. Catalog identifiers are the contract, so an id this build no longer carries
is dropped rather than labelled from a neighbouring entry, and a step that loses
every id that way disappears with it.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Final, cast

from ..runtime.command_extensions import CommandSafetyExtensionRegistry
from ..runtime.extension_coverage_hint import validated_extension_coverage_hint

_LOGGER = logging.getLogger(__name__)
COVERAGE_SCHEMA: Final = "guard.approval-extension-coverage.v1"
# The dashboard renders this many steps; delivering more would store and send a
# payload whose tail nothing shows.
MAX_DELIVERED_SEGMENTS: Final = 12


def _covered_segment(
    segment: Mapping[str, object],
    *,
    registry: CommandSafetyExtensionRegistry,
) -> dict[str, object] | None:
    extension_ids = cast("list[str]", segment["extension_ids"])
    rule_ids = cast("list[str]", segment["rule_ids"])
    permission_ids = cast("list[str]", segment["permission_ids"])
    rules: list[dict[str, object]] = []
    for rule_id in rule_ids:
        rule = registry.get_rule(rule_id)
        if rule is not None:
            rules.append({"rule_id": rule_id, "title": rule.title, "severity": rule.severity})
    permissions: list[dict[str, object]] = []
    for permission_id in permission_ids:
        permission = registry.permission(permission_id)
        if permission is not None:
            permissions.append(
                {
                    "permission_id": permission_id,
                    "label": permission.label,
                    "configurable": permission.configurable,
                }
            )
    extensions: list[dict[str, object]] = []
    for extension_id in extension_ids:
        extension = registry.get(extension_id)
        if extension is None:
            continue
        owned = {rule.rule_id for rule in extension.rules}
        # The first rule this extension matched is what the link should open on.
        focus = next((rule_id for rule_id in rule_ids if rule_id in owned), None)
        # The dashboard builds the link itself from these two identifiers, so
        # no daemon-built URL ever reaches a href attribute.
        extensions.append({"extension_id": extension_id, "name": extension.name, "focus_rule_id": focus})
    if not extensions:
        # Every id in this segment came from a catalog this build does not have.
        return None
    return {
        "index": segment["index"],
        "executable": segment["executable"],
        "extensions": extensions,
        "rules": rules,
        "permissions": permissions,
    }


def _is_compound(total: object, segments: list[dict[str, object]]) -> bool:
    """Whether steps other than the covered ones are still waiting on review."""

    if isinstance(total, int):
        # The review counted the steps, so this is the whole answer: a command
        # of one step is settled by its one covered step, and any other is not.
        return total > 1
    # Without a count, a later step that no extension matched is invisible, so
    # only what the covered steps themselves prove can be claimed.
    return len(segments) > 1 or any(cast("int", segment["index"]) > 0 for segment in segments)


def build_approval_extension_coverage(
    approval: Mapping[str, object],
    *,
    registry: CommandSafetyExtensionRegistry,
) -> dict[str, object] | None:
    """Return the coverage payload for a pending request, or None when not applicable."""

    if approval.get("status") != "pending":
        return None
    coverage = validated_extension_coverage_hint(approval.get("extension_allow_hint"))
    if coverage is None:
        return None
    segments = [
        covered
        for segment in cast("list[Mapping[str, object]]", coverage["segments"])
        if (covered := _covered_segment(segment, registry=registry)) is not None
    ]
    if not segments:
        return None
    compound = _is_compound(coverage.get("segment_total"), segments)
    return {
        "schema": COVERAGE_SCHEMA,
        "catalog_digest": registry.catalog_digest or coverage["catalog_digest"],
        "segments": segments[:MAX_DELIVERED_SEGMENTS],
        # A single-step command needs no "the other steps still need review" line.
        "compound": compound or len(segments) > MAX_DELIVERED_SEGMENTS,
    }


def with_approval_extension_coverage(
    payload: dict[str, object],
    approval: Mapping[str, object],
    *,
    registry: CommandSafetyExtensionRegistry | None,
    include: bool,
) -> dict[str, object]:
    """Add the coverage payload to a delivered approval; never fails the read."""

    if not include or registry is None:
        return payload
    try:
        coverage = build_approval_extension_coverage(approval, registry=registry)
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        _LOGGER.warning("Extension coverage unavailable (%s)", type(error).__name__)
        return payload
    if coverage is not None:
        payload["extension_coverage"] = coverage
    return payload


__all__ = [
    "COVERAGE_SCHEMA",
    "MAX_DELIVERED_SEGMENTS",
    "build_approval_extension_coverage",
    "with_approval_extension_coverage",
]
