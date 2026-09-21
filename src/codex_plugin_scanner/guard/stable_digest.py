"""Deterministic keyed digests for Guard identifiers and cache keys."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Iterable

_STABLE_DIGEST_KEY = b"hol-guard-stable-digest.v3"


def sha256_content_digest(payload: bytes) -> str:
    """Hash public or canonical protocol content, never credentials."""

    # codeql[py/weak-sensitive-data-hashing]
    digest = hashlib.sha256(payload)
    return digest.hexdigest()


def stable_digest_hex(payload: bytes, *, length: int | None = None) -> str:
    # These digests are used for deterministic Guard cache keys and opaque IDs,
    # not for password or credential storage.
    # codeql[py/weak-sensitive-data-hashing]
    digest = hmac.digest(_STABLE_DIGEST_KEY, payload, "sha512").hex()[:64]
    if length is None:
        return digest
    return digest[:length]


def stable_digest_chunks(chunks: Iterable[bytes]) -> str:
    """Hash a bounded-memory byte stream with the same stable content identity."""

    digest = hmac.new(_STABLE_DIGEST_KEY, digestmod="sha512")
    for chunk in chunks:
        digest.update(chunk)
    return digest.hexdigest()[:64]
