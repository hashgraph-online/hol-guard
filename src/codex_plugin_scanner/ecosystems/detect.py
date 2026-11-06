"""Ecosystem auto-detection across adapters."""

from __future__ import annotations

from pathlib import Path

from .registry import get_default_adapters
from .types import Ecosystem, PackageCandidate


def _dedupe_candidates(candidates: list[PackageCandidate]) -> list[PackageCandidate]:
    unique: dict[tuple[str, str], PackageCandidate] = {}
    priority = {
        "single-plugin": 0,
        "extension": 0,
        "workspace-bundle": 1,
        "marketplace": 2,
    }
    for candidate in candidates:
        key = (
            candidate.ecosystem.value,
            str(candidate.root_path.resolve()),
        )
        existing = unique.get(key)
        if existing is None:
            unique[key] = candidate
            continue
        existing_priority = priority.get(existing.package_kind, 99)
        next_priority = priority.get(candidate.package_kind, 99)
        if next_priority < existing_priority:
            unique[key] = candidate
    return sorted(
        unique.values(),
        key=lambda candidate: (candidate.ecosystem.value, str(candidate.root_path), candidate.package_kind),
    )


def detect_packages(root: Path, ecosystem: Ecosystem | None = None) -> list[PackageCandidate]:
    """Detect package candidates under a repository root."""

    detected: list[PackageCandidate] = []
    for adapter in get_default_adapters():
        if ecosystem is not None and adapter.ecosystem_id != ecosystem:
            continue
        detected.extend(adapter.detect(root))
    return _dedupe_candidates(detected)
