"""Write outcome used by the bounded MCP evidence fallback."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class McpEvidenceWriteResult:
    accepted: bool
    committed: bool

    def __bool__(self) -> bool:
        return self.accepted
