"""Published generic matcher, effect, and lifetime representability."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Final

GENERIC_LANE: Final = "generic-local-sqlite"
MANAGED_LANE: Final = "managed-extension-controls"
NATIVE_LANE: Final = "native-intrinsic"

GENERIC_MATCH_KEYS: Final = frozenset({"artifacts", "harnesses", "publishers", "tools", "workspaces", "exactCommand"})
GENERIC_EFFECTS: Final = frozenset({"allow", "block", "review"})
GENERIC_LIFETIMES: Final = frozenset({"permanent", "until"})
GENERIC_INERT_EFFECTS: Final = frozenset({"ignore"})
DEVICE_TARGETING_LANE: Final = "signed-bundle-device-id"

GENERIC_RUNTIME_MATCHER_CAPABILITY: Final[dict[str, object]] = {
    "capability": "generic-matchers.v1",
    "lanes": {
        GENERIC_LANE: {
            "match_keys": sorted(GENERIC_MATCH_KEYS),
            "effects": sorted(GENERIC_EFFECTS),
            "inert_effects": sorted(GENERIC_INERT_EFFECTS),
            "lifetimes": sorted(GENERIC_LIFETIMES),
            "device_selectors": "unsupported_in_local_compile",
            "unknown_matchers": "reject",
            "empty_match": "global",
        },
        DEVICE_TARGETING_LANE: {
            "match_keys": ["devices"],
            "identity": "installation_id",
            "human_name": "display_only",
        },
        MANAGED_LANE: {
            "effects": ["enable", "disable"],
            "disable_dominance": True,
        },
        NATIVE_LANE: {
            "intrinsic_blocks": "never_weakened",
        },
    },
}


def published_generic_matcher_capability() -> dict[str, object]:
    return deepcopy(GENERIC_RUNTIME_MATCHER_CAPABILITY)


def unsupported_matcher_reason(match: Mapping[str, object], *, rule_id: str) -> dict[str, object] | None:
    unsupported = sorted(
        str(key)
        for key, value in match.items()
        if not str(key).startswith("x-") and key not in GENERIC_MATCH_KEYS and value not in (None, [])
    )
    if not unsupported:
        return None
    return {
        "code": "unsupported_policy_match",
        "rule_id": rule_id,
        "field_path": f"spec.rules[{rule_id}].match",
        "unsupported_keys": unsupported,
        "remediation": (
            "Use supported artifacts, harnesses, publishers, tools, workspaces, and exactCommand intersections. "
            + "Unknown matchers cannot become global rules."
        ),
        "supported": sorted(GENERIC_MATCH_KEYS),
    }


__all__ = [
    "GENERIC_EFFECTS",
    "GENERIC_LIFETIMES",
    "GENERIC_MATCH_KEYS",
    "GENERIC_RUNTIME_MATCHER_CAPABILITY",
    "published_generic_matcher_capability",
    "unsupported_matcher_reason",
]
