"""Public shapes and tiny helpers for the local approval password gate.

The native resident owns the gate state file, verifier, lockout, cooldown and
grant table. This module keeps only the immutable public snapshot the CLI,
dashboard and daemon present, plus two clock/coercion helpers.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timezone

APPROVAL_GATE_STATE_FILE = "approval-gate.json"


@dataclass(frozen=True, slots=True)
class ApprovalGatePublicConfig:
    """Public approval gate state safe for settings and dashboard responses."""

    enabled: bool
    configured: bool
    cooldown_seconds: int
    cooldown_active: bool
    cooldown_expires_at: str | None
    locked_until: str | None
    fail_closed: bool
    strict_all_decisions: bool
    totp_enabled: bool
    totp_pending: bool
    totp_recent_satisfied: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "enabled": self.enabled,
            "configured": self.configured,
            "cooldown_seconds": self.cooldown_seconds,
            "cooldown_active": self.cooldown_active,
            "cooldown_expires_at": self.cooldown_expires_at,
            "locked_until": self.locked_until,
            "fail_closed": self.fail_closed,
            "strict_all_decisions": self.strict_all_decisions,
            "totp_enabled": self.totp_enabled,
            "totp_pending": self.totp_pending,
            "totp_recent_satisfied": self.totp_recent_satisfied,
        }


def epoch(value: str | None) -> float:
    if value is None:
        return time.time()
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        return datetime.fromisoformat(normalized).timestamp()
    except ValueError:
        return 0.0


def iso_from_epoch(value: float) -> str:
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


def optional_string(value: object) -> str | None:
    if isinstance(value, str) and value:
        return value
    return None


def optional_bool(value: object, fallback: object) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(fallback, bool):
        return fallback
    return None
