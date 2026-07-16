"""Dependency-neutral contracts shared by command matchers and rules."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .command_model import CanonicalCommand


@dataclass(frozen=True, slots=True)
class MatcherEvidence:
    """Redaction-safe location emitted by one structured matcher."""

    segment_index: int
    executable: str | None
    detail: str

    def to_dict(self) -> dict[str, object]:
        return {
            "segment_index": self.segment_index,
            "executable": self.executable,
            "detail": self.detail,
        }


class CommandMatcher(Protocol):
    """Side-effect-free structured command matcher."""

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]: ...
