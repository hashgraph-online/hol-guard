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


def retained_bridge_generations(previous_manifest: Mapping[str, object] | None) -> list[dict[str, object]]:
    """Carry complete identities under the new manifest's authentication.

    The caller supplies an authenticated predecessor. A digest alone cannot
    authorize an old package path or its interpreter and launch contracts.
    """
    if previous_manifest is None:
        return []
    allowed = set(compatible_bridge_argv_hashes(previous_manifest))
    retained = previous_manifest.get("retained_bridge_generations")
    candidates = [item for item in retained if isinstance(item, dict)] if isinstance(retained, list) else []
    predecessor = {
        key: value
        for key, value in previous_manifest.items()
        if key not in {"authentication", "retained_bridge_generations", "compatible_bridge_argv_sha256"}
    }
    candidates.append(predecessor)
    selected: dict[str, dict[str, object]] = {}
    for candidate in candidates:
        events = candidate.get("events")
        if not isinstance(events, list):
            continue
        for event in events:
            argv = event.get("argv") if isinstance(event, dict) else None
            if isinstance(argv, list):
                digest = bridge_argv_sha256(argv)
                if digest in allowed:
                    selected[digest] = candidate
    return list(selected.values())[-_MAX_COMPATIBLE_BRIDGE_GENERATIONS:]


def retained_launch_generations(manifest: Mapping[str, object]) -> list[dict[str, object]]:
    """Select complete identities from an already authenticated manifest.

    Legacy hash-only compatibility remains constrained to the current layout
    by the launch validator. Never infer a separate artifact from a hash.
    """
    retained = manifest.get("retained_bridge_generations", [])
    allowed = manifest.get("compatible_bridge_argv_sha256", [])
    if (
        not isinstance(retained, list)
        or len(retained) > _MAX_COMPATIBLE_BRIDGE_GENERATIONS
        or not isinstance(allowed, list)
        or len(allowed) > _MAX_COMPATIBLE_BRIDGE_GENERATIONS
        or any(
            not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value)
            for value in allowed
        )
    ):
        raise ValueError("managed Codex hook retained generation identity is invalid")
    result = []
    for candidate in retained:
        if not isinstance(candidate, dict) or any(
            candidate.get(field) != manifest.get(field)
            for field in (
                "schema_version",
                "harness",
                "installation_id",
                "config",
                "context",
            )
        ):
            raise ValueError("managed Codex hook retained generation context is invalid")
        events = candidate.get("events")
        if not isinstance(events, list) or not events:
            raise ValueError("managed Codex hook retained event identity is invalid")
        for event in events:
            argv = event.get("argv") if isinstance(event, dict) else None
            if (
                not isinstance(argv, list)
                or not argv
                or not all(isinstance(value, str) for value in argv)
                or bridge_argv_sha256(argv) not in allowed
            ):
                raise ValueError("managed Codex hook retained argv is not registered")
        result.append(candidate)
    return result


__all__ = ["bridge_argv_sha256", "compatible_bridge_argv_hashes"]
