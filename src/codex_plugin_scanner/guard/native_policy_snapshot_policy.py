"""Scope identity and store-sourced action helpers for native policy snapshots.

The effective policy itself is derived and composed by the native runtime; see
``native_policy_effective``.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .config import GuardConfig


def _normalize_scope_text_v3(value: str) -> str:
    """Canonicalize a guard-home identity across Windows path aliases."""
    if os.name == "nt":
        normalized = value.replace("/", "\\")
        folded = normalized.casefold()
        if folded.startswith("\\\\?\\unc\\"):
            normalized = "\\\\" + normalized[8:]
        elif folded.startswith("\\\\?\\"):
            normalized = normalized[4:]
        while len(normalized) > 3 and normalized.endswith("\\"):
            normalized = normalized[:-1]
        return normalized.casefold()
    if value.startswith("/private/"):
        return value[len("/private") :]
    return value


def _scope_digest_v3(guard_home: Path) -> str:
    try:
        canonical = str(guard_home.expanduser().resolve(strict=False))
    except (OSError, RuntimeError, ValueError):
        canonical = str(guard_home)
    canonical = _normalize_scope_text_v3(canonical)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _config_value(config: GuardConfig | Mapping[str, object], name: str, default: object = None) -> object:
    if isinstance(config, Mapping):
        return config.get(name, default)
    return getattr(config, name, default)
