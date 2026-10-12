"""Command redirect structures and complete executable identities."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Literal, Protocol

from ..native_rich_command_model import request
from .shell_structure import ShellHeredoc


@dataclass(frozen=True, slots=True)
class CommandRedirect:
    """One non-heredoc shell redirect with normalized source spans."""

    operator: str
    target: str
    start: int
    end: int

    def to_dict(self) -> dict[str, object]:
        return {
            "operator": self.operator,
            "target": self.target,
            "span": {"source": "normalized", "start": self.start, "end": self.end},
        }


@dataclass(frozen=True, slots=True)
class EmbeddedCommand:
    """Command text executed from substitution or an interpreter heredoc."""

    kind: Literal["substitution", "heredoc"]
    text: str
    execution_context: str
    start: int
    end: int

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "execution_context": self.execution_context,
            "span": {"source": "normalized", "start": self.start, "end": self.end},
        }


class IdentitySegment(Protocol):
    @property
    def tokens(self) -> tuple[str, ...]: ...

    @property
    def environment_names(self) -> tuple[str, ...]: ...

    @property
    def wrapper_chain(self) -> tuple[str, ...]: ...

    @property
    def execution_context(self) -> str: ...

    @property
    def pipeline_index(self) -> int: ...


def build_command_security_identity(
    *,
    normalized_text: str,
    dialect: str,
    transport: str,
    wrapper_chain: tuple[str, ...],
    segments: tuple[IdentitySegment, ...],
    redirects: tuple[CommandRedirect, ...],
    embedded_commands: tuple[EmbeddedCommand, ...],
) -> str:
    """Ask the native owner to bind the complete executable structure."""
    return request(
        "identity",
        {
            "normalized_text": normalized_text,
            "dialect": dialect,
            "transport": transport,
            "wrapper_chain": wrapper_chain,
            "segments": [
                {
                    name: getattr(s, name)
                    for name in ("tokens", "environment_names", "wrapper_chain", "execution_context", "pipeline_index")
                }
                for s in segments
            ],
            "redirects": [asdict(item) for item in redirects],
            "embedded_commands": [asdict(item) for item in embedded_commands],
        },
    )


def extract_command_redirects(command: str, heredocs: tuple[ShellHeredoc, ...]) -> tuple[CommandRedirect, ...]:
    """Present native redirects with their original normalized spans."""
    return tuple(
        CommandRedirect(**value)
        for value in request("redirects", {"command": command, "heredocs": [asdict(item) for item in heredocs]})
    )
