"""Shared canonical primitives for execution-bound verified reads."""

from __future__ import annotations

import hashlib
import json


def verified_read_digest(value: object) -> str:
    """Return a length-framed SHA-256 digest of canonical JSON."""

    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(len(payload).to_bytes(8, "big") + payload).hexdigest()


__all__ = ("verified_read_digest",)
