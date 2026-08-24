"""Bounded authenticated identities for Codex hooks loaded before repair."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence

_MAX_COMPATIBLE_BRIDGE_GENERATIONS = 8


def bridge_argv_sha256(argv: Sequence[object]) -> str:
    payload = json.dumps(list(argv), ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def compatible_bridge_argv_hashes(previous_manifest: Mapping[str, object] | None) -> list[str]:
    if previous_manifest is None:
        return []
    candidates: list[str] = []
    previous_hashes = previous_manifest.get("compatible_bridge_argv_sha256")
    if isinstance(previous_hashes, list):
        candidates.extend(value for value in previous_hashes if isinstance(value, str) and len(value) == 64)
    events = previous_manifest.get("events")
    if isinstance(events, list):
        for event in events:
            argv = event.get("argv") if isinstance(event, Mapping) else None
            if isinstance(argv, list) and argv and all(isinstance(value, str) for value in argv):
                candidates.append(bridge_argv_sha256(argv))
    return list(dict.fromkeys(candidates))[-_MAX_COMPATIBLE_BRIDGE_GENERATIONS:]


__all__ = ["bridge_argv_sha256", "compatible_bridge_argv_hashes"]
