"""Bounded Cloud Review worker configuration with safe startup defaults."""

from __future__ import annotations

import logging
import math
import os
from dataclasses import dataclass

_LOGGER = logging.getLogger(__name__)
MINIMUM_WAIT_SECONDS = 0.1
MAXIMUM_WAIT_SECONDS = 3600.0


def _interval(name: str, explicit: float | None, default: float) -> float:
    raw = explicit if explicit is not None else os.environ.get(name, default)
    try:
        value = float(raw)
    except (TypeError, ValueError, OverflowError):
        value = math.nan
    if not math.isfinite(value) or not MINIMUM_WAIT_SECONDS <= value <= MAXIMUM_WAIT_SECONDS:
        _LOGGER.warning("Invalid %s; using the default interval of %s seconds.", name, default)
        return default
    return value


@dataclass(frozen=True, slots=True)
class CloudReviewWorkerTiming:
    poll_interval: float
    error_backoff: float
    error_backoff_base: float


def cloud_review_worker_timing(
    *,
    poll_interval: float | None,
    error_backoff: float | None,
    default_poll: float,
    default_backoff: float,
    default_base: float,
) -> CloudReviewWorkerTiming:
    maximum = _interval("GUARD_CLOUD_REVIEW_ERROR_BACKOFF", error_backoff, default_backoff)
    initial = _interval("GUARD_CLOUD_REVIEW_ERROR_BACKOFF_BASE", None, default_base)
    return CloudReviewWorkerTiming(
        poll_interval=_interval("GUARD_CLOUD_REVIEW_POLL_INTERVAL", poll_interval, default_poll),
        error_backoff=maximum,
        error_backoff_base=min(initial, maximum),
    )
