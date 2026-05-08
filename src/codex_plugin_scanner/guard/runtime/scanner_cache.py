"""Scanner cache identity helpers."""

from __future__ import annotations

from hashlib import sha256


def scanner_cache_key(*, scanner_name: str, input_content_hash: str, scanner_version: str) -> str:
    payload = "\0".join((scanner_name.strip(), input_content_hash.strip(), scanner_version.strip()))
    return sha256(payload.encode("utf-8")).hexdigest()
