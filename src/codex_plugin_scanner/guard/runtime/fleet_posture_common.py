"""Shared constants and helpers for the ``fleet-posture/v1`` builder."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..store import GuardStore

SCHEMA_VERSION = "fleet-posture/v1"
CAPABILITY = "fleet-posture/v1"
MAX_PAYLOAD_BYTES = 65536
MAX_ITEMS_PER_SYNC = 250
MAX_TOOLS = 32
MAX_BLIND_SPOTS = 8
MAX_BLIND_SPOT_LENGTH = 80
STALE_AFTER = timedelta(days=7)
FULL_REFRESH_AFTER = timedelta(days=7)

LAST_SENT_STATE_KEY = "fleet_posture_last"
SETTINGS_STATE_KEY = "fleet_posture_settings"
FORCE_FULL_STATE_KEY = "fleet_posture_force_full"
FOLLOWUP_STATE_KEY = "fleet_posture_bundle_followup"
HASH_KEY_STATE_KEY = "fleet_posture_hash_key"
DIAGNOSTICS_STATE_KEY = "fleet_posture_diagnostics"

HARNESS_IDS = frozenset(
    {
        "antigravity",
        "claude-code",
        "cline",
        "codex",
        "copilot",
        "cursor",
        "devin",
        "gemini",
        "grok",
        "hermes",
        "kimi",
        "omp",
        "openclaw",
        "opencode",
        "paseo",
        "pi",
        "zcode",
    }
)

_SHA256_HEX = re.compile(r"^[a-f0-9]{64}$")


def utc(value: datetime | None) -> datetime:
    resolved = value or datetime.now(timezone.utc)
    if resolved.tzinfo is None:
        resolved = resolved.replace(tzinfo=timezone.utc)
    return resolved.astimezone(timezone.utc)


def iso(value: datetime) -> str:
    return utc(value).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return utc(parsed)


def normalized_timestamp(value: object) -> str | None:
    parsed = parse_timestamp(value)
    return iso(parsed) if parsed is not None else None


def text_digest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def digest_rows(rows: Iterable[Iterable[object]]) -> str:
    """Digest of rows sorted lexicographically, serialized as compact JSON."""

    ordered = sorted(
        ([("" if cell is None else str(cell)) for cell in row] for row in rows),
    )
    return text_digest(json.dumps(ordered, separators=(",", ":"), ensure_ascii=False))


def normalized_hash(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    if text.startswith("sha256:"):
        text = text[len("sha256:") :]
    return f"sha256:{text}" if _SHA256_HEX.match(text) else None


def clip(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[:limit]


def json_size(payload: object) -> int:
    return len(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


def keyed_digest(key: bytes, text: str) -> str:
    """``sha256:`` HMAC of ``text`` under a random per-install secret.

    Host names and config paths are guessable (they contain user names), so a plain
    SHA-256 could be reversed by a dictionary search. The secret never leaves the
    machine; the output keeps the contract's ``sha256:<64 hex>`` shape.
    """

    return "sha256:" + hmac.new(key, text.encode("utf-8"), hashlib.sha256).hexdigest()


def load_hash_key(store: GuardStore, now: str) -> bytes:
    """Read (or create) the per-install secret. Call once per build, not per hash."""

    raw = store.get_sync_payload(HASH_KEY_STATE_KEY)
    existing = raw.get("key") if isinstance(raw, dict) else None
    if isinstance(existing, str) and len(existing) >= 32:
        return existing.encode("utf-8")
    created = secrets.token_hex(32)
    store.set_sync_payload(HASH_KEY_STATE_KEY, {"key": created}, now)
    return created.encode("utf-8")
