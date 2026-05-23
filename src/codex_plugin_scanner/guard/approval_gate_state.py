"""State helpers for the local approval password gate."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

APPROVAL_GATE_STATE_FILE = "approval-gate.json"
APPROVAL_GATE_MAX_COOLDOWN_SECONDS = 3600
APPROVAL_GATE_ALLOWED_COOLDOWNS = (0, 900, APPROVAL_GATE_MAX_COOLDOWN_SECONDS)
APPROVAL_GATE_LOCKOUT_FAILURES = 5
APPROVAL_GATE_LOCKOUT_SECONDS = 300


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
        }


def write_state(guard_home: Path, state: dict[str, object], *, now: str | None) -> None:
    guard_home.mkdir(parents=True, exist_ok=True)
    payload = dict(state)
    payload["updated_at"] = now or iso_from_epoch(time.time())
    path = guard_home / APPROVAL_GATE_STATE_FILE
    tmp_path = path.with_suffix(".json.tmp")
    tmp_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp_path.chmod(0o600)
    tmp_path.replace(path)


def default_state() -> dict[str, object]:
    return {
        "enabled": False,
        "cooldown_seconds": 0,
        "strict_all_decisions": False,
        "failed_attempts": 0,
    }


def verifier(state: dict[str, object]) -> dict[str, object] | None:
    value = state.get("verifier")
    return value if isinstance(value, dict) else None


def verify_password(password: str, verifier_payload: dict[str, object] | None) -> bool:
    if verifier_payload is None:
        return False
    try:
        iterations = int(verifier_payload["iterations"])
        salt = base64.b64decode(str(verifier_payload["salt"]))
        expected = base64.b64decode(str(verifier_payload["hash"]))
    except (KeyError, TypeError, ValueError):
        return False
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(digest, expected)


def enabled(state: dict[str, object]) -> bool:
    return state.get("enabled") is True or state.get("fail_closed") is True


def record_failed_attempt(guard_home: Path, state: dict[str, object], *, now: str | None) -> None:
    now_epoch = epoch(now)
    attempts = int(state.get("failed_attempts", 0)) + 1
    state["failed_attempts"] = attempts
    if attempts >= APPROVAL_GATE_LOCKOUT_FAILURES:
        state["locked_until"] = iso_from_epoch(now_epoch + APPROVAL_GATE_LOCKOUT_SECONDS)
        state["failed_attempts"] = 0
    write_state(guard_home, state, now=now)


def cooldown_active(state: dict[str, object], now_epoch: float) -> bool:
    return is_future(optional_string(state.get("cooldown_expires_at")), now_epoch)


def is_future(value: str | None, now_epoch: float) -> bool:
    if value is None:
        return False
    return epoch(value) > now_epoch


def epoch(value: str | None) -> float:
    if value is None:
        return time.time()
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        return datetime.fromisoformat(normalized).timestamp()
    except ValueError:
        return time.time()


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


def prune_grants(grants: dict[str, dict[str, object]], now_epoch: float) -> None:
    expired = [
        grant_id for grant_id, metadata in grants.items() if float(metadata.get("expires_epoch", 0.0)) <= now_epoch
    ]
    for grant_id in expired:
        grants.pop(grant_id, None)
