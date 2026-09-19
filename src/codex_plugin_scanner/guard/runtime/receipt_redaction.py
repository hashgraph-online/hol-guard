"""Compose receipt privacy without treating an implicit default as a local floor."""

from __future__ import annotations

import importlib
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..config import GuardConfig

tomllib = importlib.import_module("tomllib" if sys.version_info >= (3, 11) else "tomli")
_LEVELS = {"none": 0, "partial": 1, "full": 2}


def _level(value: object) -> str:
    if type(value) is not str or value not in _LEVELS:
        raise ValueError("receipt_redaction_level_invalid")
    return value


def _explicit_local_level(path: Path) -> str | None:
    try:
        with path.open("rb") as handle:
            payload = tomllib.load(handle)
    except FileNotFoundError:
        # A dangling link is unreadable configuration, not an absent local choice.
        try:
            path.lstat()
        except FileNotFoundError:
            return None
        raise ValueError("receipt_redaction_config_unreadable") from None
    if not isinstance(payload, dict):
        raise ValueError("receipt_redaction_config_invalid")
    if "receipt_redaction_level" not in payload:
        return None
    return _level(payload["receipt_redaction_level"])


def compose_receipt_redaction_level(
    config: GuardConfig, signed: Mapping[str, object] | None, remote_level: str | None
) -> str:
    """Accept verified signed defaults while retaining every explicit privacy floor."""
    local_level = _level(config.receipt_redaction_level)
    if config.managed_policy_status in {"invalid", "inaccessible", "tampered"}:
        raise ValueError("receipt_redaction_managed_policy_unavailable")
    base = local_level
    if signed is not None and "receiptRedactionLevel" in signed:
        base = _level(signed["receiptRedactionLevel"])
    levels = [base]
    # Read the value itself: a newly strengthened setting must not borrow an older
    # loaded value merely because the current file contains an explicit key.
    explicit_local = _explicit_local_level(config.guard_home / "config.toml")
    if explicit_local is not None:
        levels.append(explicit_local)
    if config.managed_policy is not None:
        managed = config.managed_policy.settings
        if "receipt_redaction_level" in managed:
            levels.append(_level(managed["receipt_redaction_level"]))
    if remote_level is not None:
        levels.append(_level(remote_level))
    return max(levels, key=_LEVELS.__getitem__)
