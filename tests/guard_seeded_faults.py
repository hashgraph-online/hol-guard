"""Curated, deterministic security fault probes for the command parser."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal

FaultExpectation = Literal[
    "exclude_redirect_target",
    "preserve_path_override",
    "preserve_provenance",
    "mark_malformed_uncertain",
    "mark_oversized_uncertain",
]


@dataclass(frozen=True)
class SeededFault:
    """A known security-sensitive parser failure represented as deterministic input."""

    fault_id: str
    command: str
    expectation: FaultExpectation
    guarantee: str


PARSER_SEEDED_FAULTS: Final[tuple[SeededFault, ...]] = (
    SeededFault(
        "SEED-CMD-001",
        "stripe products delete prod_123 2>--help",
        "exclude_redirect_target",
        "A redirection target cannot be interpreted as a safe CLI flag.",
    ),
    SeededFault(
        "SEED-CMD-002",
        "PATH=/usr/bin:/bin npx vitest run && git reset --hard HEAD~1",
        "preserve_path_override",
        "PATH overrides stay visible in the canonical command identity.",
    ),
    SeededFault(
        "SEED-CMD-003",
        "git status --short",
        "preserve_provenance",
        "Canonical shell parse provenance remains available to downstream policy.",
    ),
    SeededFault(
        "SEED-CMD-004",
        "git reset --hard 'unterminated",
        "mark_malformed_uncertain",
        "Malformed shell quoting remains uncertain rather than silently exact.",
    ),
    SeededFault(
        "SEED-CMD-005",
        "x" * 32_769,
        "mark_oversized_uncertain",
        "Oversized commands remain uncertain rather than partially parsed.",
    ),
)
