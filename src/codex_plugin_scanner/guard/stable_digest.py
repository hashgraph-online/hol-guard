"""Deterministic keyed digests for Guard identifiers and cache keys."""

from __future__ import annotations

import hashlib

_STABLE_DIGEST_KEY = b"hol-guard-stable-digest.v2"


def stable_digest_hex(payload: bytes, *, length: int | None = None) -> str:
    digest = hashlib.blake2b(payload, key=_STABLE_DIGEST_KEY, digest_size=32).hexdigest()
    if length is None:
        return digest
    return digest[:length]
