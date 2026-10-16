"""Present native business-selector draft bounds without their contents."""

from __future__ import annotations

from .native_policy_document import NativePolicyDocumentError, policy_query

MAX_BUSINESS_SELECTOR_BYTES = 64 * 1024


def oversized_business_selector_path(value: dict[str, object]) -> tuple[str | int, ...] | None:
    result = policy_query("bounds", {"value": value})
    if result is None:
        return None
    if (
        not isinstance(result, list)
        or len(result) != 5
        or result[:2] != ["spec", "rules"]
        or type(result[2]) is not int
        or result[2] < 0
        or result[3:] != ["match", "business"]
    ):
        raise NativePolicyDocumentError("native_policy_document_bounds_malformed")
    return tuple(result)
