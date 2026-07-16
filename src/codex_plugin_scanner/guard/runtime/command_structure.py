"""Command redirect structures and complete executable identities."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Literal, Protocol

from .shell_structure import ShellHeredoc, ShellScanState

_REDIRECT_PATTERN = re.compile(
    r"(?<![<>])(?P<operator>(?:\d*)>>?|(?:\d*)<)(?![<>&])\s*(?P<target>\"[^\"]+\"|'[^']+'|[^ \t\r\n;&|<>]+)"
)


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
    """Return a versioned identity over the complete executable structure."""

    payload = {
        "version": 2,
        "normalized_text": normalized_text,
        "dialect": dialect,
        "transport": transport,
        "wrapper_chain": wrapper_chain,
        "segments": [
            {
                "tokens": segment.tokens,
                "environment_names": segment.environment_names,
                "wrapper_chain": segment.wrapper_chain,
                "execution_context": segment.execution_context,
                "pipeline_index": segment.pipeline_index,
            }
            for segment in segments
        ],
        "redirects": [(item.operator, item.target) for item in redirects],
        "embedded": [(item.kind, item.text, item.execution_context) for item in embedded_commands],
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"command-security-v2:{hashlib.sha256(encoded).hexdigest()}"


def extract_command_redirects(
    command: str,
    heredocs: tuple[ShellHeredoc, ...],
) -> tuple[CommandRedirect, ...]:
    """Extract redirects while preserving normalized source spans."""

    redirects: list[CommandRedirect] = []
    heredoc_operator_starts = {item.operator_start for item in heredocs}
    state = ShellScanState()
    index = 0
    while index < len(command):
        next_index = state.advance(command, index)
        if next_index != index + 1:
            index = next_index
            continue
        if not state.is_top_level:
            index += 1
            continue
        match = _REDIRECT_PATTERN.match(command, index)
        if match is None or match.start() in heredoc_operator_starts:
            index += 1
            continue
        redirects.append(
            CommandRedirect(
                operator=match.group("operator"),
                target=_strip_quotes(match.group("target")),
                start=match.start(),
                end=match.end(),
            )
        )
        index = match.end()
    redirects.extend(
        CommandRedirect(
            operator="<<-" if heredoc.strip_tabs else "<<",
            target=heredoc.delimiter,
            start=heredoc.operator_start,
            end=heredoc.declaration_end,
        )
        for heredoc in heredocs
    )
    return tuple(sorted(redirects, key=lambda item: item.start))


def _strip_quotes(value: str) -> str:
    stripped = value.strip()
    if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in {"'", '"'}:
        return stripped[1:-1]
    return stripped
