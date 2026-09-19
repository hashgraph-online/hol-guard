"""Reuse live consent for delivery recovery while preserving explicit renewal."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from .exact_cloud_review import (
    EXACT_CLOUD_REVIEW_DEFAULT_TTL_SECONDS,
    EXACT_CLOUD_REVIEW_MAX_TTL_SECONDS,
    ExactCloudReviewError,
    exact_cloud_review_status,
)

if TYPE_CHECKING:
    from ..store import GuardStore


def reuse_or_issue_cloud_review_consent(
    store: GuardStore,
    *,
    issue: Callable[[], dict[str, object]],
    renew: bool = False,
    ttl_seconds: int = EXACT_CLOUD_REVIEW_DEFAULT_TTL_SECONDS,
) -> dict[str, object]:
    """Call under the OAuth credential lock after the surface's required proof."""

    current = exact_cloud_review_status(store)
    if current.get("enabled") is True and not renew:
        return current
    if type(ttl_seconds) is not int or not 0 < ttl_seconds <= EXACT_CLOUD_REVIEW_MAX_TTL_SECONDS:
        raise ExactCloudReviewError("cloud_review_capability_ttl_invalid")
    return issue()
