"""Fail-closed activation policy for the Guard Cloud command queue."""

from __future__ import annotations

import logging
import os
from collections.abc import Callable

from ..store import GuardStore

COMMAND_QUEUE_LEASE_WAIT_MS_ENV = "GUARD_CLOUD_COMMAND_QUEUE_LEASE_WAIT_MS"
_DEFAULT_LEASE_WAIT_MS = 25_000


def command_queue_is_enabled(
    store: GuardStore | None,
    environ: dict[str, str] | None,
    *,
    enabled_env: str,
    environment_allows_queue: Callable[[dict[str, str] | None], bool],
    operations: Callable[[GuardStore], tuple[str, ...]],
    logger: logging.Logger,
) -> bool:
    if not environment_allows_queue(environ):
        value = (os.environ if environ is None else environ).get(enabled_env)
        if isinstance(value, str) and value.strip().lower() not in {"", "0", "false", "no", "off", "disabled"}:
            logger.warning("Ignoring unrecognized %s value; command queue disabled.", enabled_env)
        return False
    return store is not None and bool(operations(store))


def nonnegative_env_float(name: str, default: float) -> float:
    value = os.environ.get(name, "").strip()
    if not value:
        return default
    try:
        parsed = float(value)
    except ValueError:
        return default
    return parsed if parsed >= 0 else default


def command_queue_lease_wait_ms(environ: dict[str, str] | None = None) -> int:
    value = (os.environ if environ is None else environ).get(COMMAND_QUEUE_LEASE_WAIT_MS_ENV, "").strip()
    if not value:
        return _DEFAULT_LEASE_WAIT_MS
    try:
        parsed = int(value)
    except ValueError:
        return _DEFAULT_LEASE_WAIT_MS
    return parsed if parsed >= 0 else _DEFAULT_LEASE_WAIT_MS


def command_queue_long_poll_enabled(environ: dict[str, str] | None = None) -> bool:
    return command_queue_lease_wait_ms(environ) > 0


__all__ = [
    "COMMAND_QUEUE_LEASE_WAIT_MS_ENV",
    "command_queue_is_enabled",
    "command_queue_lease_wait_ms",
    "command_queue_long_poll_enabled",
    "nonnegative_env_float",
]
