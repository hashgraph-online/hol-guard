"""Source-faithful shell structures supplied by the native owner."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Literal

from ..native_shell_helpers import call, runtime_key


@dataclass(frozen=True, slots=True)
class ShellHeredoc:
    delimiter: str
    body: str
    operator_start: int
    declaration_end: int
    body_start: int
    body_end: int
    end: int
    quoted: bool
    strip_tabs: bool


@dataclass(frozen=True, slots=True)
class ShellCommandSubstitution:
    kind: Literal["dollar", "backtick"]
    body: str
    start: int
    body_start: int
    body_end: int
    end: int


def extract_heredocs(command: str) -> tuple[ShellHeredoc, ...]:
    return tuple(ShellHeredoc(**row) for row in call("heredocs", command))


def extract_command_substitution_spans(command: str) -> tuple[ShellCommandSubstitution, ...]:
    return tuple(ShellCommandSubstitution(**row) for row in call("substitutions", command))


def extract_expanded_heredoc_substitution_spans(command: str) -> tuple[ShellCommandSubstitution, ...]:
    return tuple(ShellCommandSubstitution(**row) for row in call("expanded_substitutions", command))


def extract_command_substitutions(command: str) -> tuple[str, ...]:
    return tuple(row.body for row in extract_command_substitution_spans(command))


def mask_heredoc_bodies(command: str, heredocs: tuple[ShellHeredoc, ...]) -> str:
    return call("masked_bodies", command, heredocs=[asdict(h) for h in heredocs])


def mask_complete_heredocs(command: str, heredocs: tuple[ShellHeredoc, ...]) -> str:
    return call("masked_complete", command, heredocs=[asdict(h) for h in heredocs])


class ShellScanState:
    """Mutable public scan DTO; transitions are computed together in Rust."""

    def __init__(self) -> None:
        self.quote: str | None = None
        self.subshell_depth = 0
        self.in_backtick = False
        self._top_level = True
        self._key: tuple[object, ...] | None = None
        self._rows: dict[int, list[Any]] = {}
        self._expected: tuple[object, ...] = (None, 0, False)
        self._next_index = 0

    @property
    def is_top_level(self) -> bool:
        if (self.quote, self.subshell_depth, self.in_backtick) != self._expected:
            return call("top_level", "", state=[self.quote, self.subshell_depth, self.in_backtick])
        return self._top_level

    def advance(self, command: str, index: int) -> int:
        key = (command, *runtime_key())
        state = (self.quote, self.subshell_depth, self.in_backtick)
        if key != self._key or state != self._expected or index != self._next_index or index not in self._rows:
            rows = call("trace", command, state=list(state), index=index)
            self._rows = {row[0]: row for row in rows}
            self._key = key
        row = self._rows[index]
        self.quote, self.subshell_depth, self.in_backtick, self._top_level = row[2:]
        self._expected = (self.quote, self.subshell_depth, self.in_backtick)
        self._next_index = row[1]
        return row[1]
