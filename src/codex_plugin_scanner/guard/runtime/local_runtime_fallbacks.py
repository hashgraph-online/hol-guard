"""Logged, fail-safe fallbacks for optional local runtime inputs."""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path

from ..config import VALID_RECEIPT_REDACTION_LEVELS, load_guard_config

_LOGGER = logging.getLogger(__name__)


def best_effort_access_token(
    resolver: Callable[[], dict[str, object]],
) -> str | None:
    try:
        auth_context = resolver()
    except Exception as error:
        _LOGGER.info("Optional runtime context unavailable: error_type=%s", type(error).__name__)
        return None
    token = auth_context.get("access_token")
    return token if isinstance(token, str) and token else None


def local_receipt_redaction_level(guard_home: Path) -> str:
    try:
        level = load_guard_config(guard_home).receipt_redaction_level
    except (OSError, ValueError) as error:
        _LOGGER.warning("Unable to load local receipt redaction level: %s", type(error).__name__)
        return "full"
    return level if level in VALID_RECEIPT_REDACTION_LEVELS else "full"
