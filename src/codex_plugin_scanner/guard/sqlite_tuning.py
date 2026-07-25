"""Shared SQLite timing configuration for Guard local storage."""

from __future__ import annotations

import os
from collections.abc import Mapping

_DEFAULT_SQLITE_CONNECT_TIMEOUT_SECONDS = 30.0
_INTERNAL_HOOK_SQLITE_TIMEOUT_ENV = "HOL_GUARD_INTERNAL_HOOK_SQLITE_TIMEOUT_MS"
_MAX_INTERNAL_HOOK_SQLITE_TIMEOUT_MS = 250


def sqlite_connect_timeout_seconds(environment: Mapping[str, str] | None = None) -> float:
    source = os.environ if environment is None else environment
    raw_timeout = source.get(_INTERNAL_HOOK_SQLITE_TIMEOUT_ENV)
    if not isinstance(raw_timeout, str):
        return _DEFAULT_SQLITE_CONNECT_TIMEOUT_SECONDS
    try:
        timeout_ms = int(raw_timeout)
    except ValueError:
        return _DEFAULT_SQLITE_CONNECT_TIMEOUT_SECONDS
    if timeout_ms <= 0:
        return _DEFAULT_SQLITE_CONNECT_TIMEOUT_SECONDS
    return min(timeout_ms, _MAX_INTERNAL_HOOK_SQLITE_TIMEOUT_MS) / 1000


SQLITE_CONNECT_TIMEOUT_SECONDS = sqlite_connect_timeout_seconds()
SQLITE_BUSY_TIMEOUT_MS = int(SQLITE_CONNECT_TIMEOUT_SECONDS * 1000)
SQLITE_WAL_BUSY_TIMEOUT_MS = 1000
