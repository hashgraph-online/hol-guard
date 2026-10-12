"""Source-faithful shell structures supplied by the native owner."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, cast

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
    return call(
        "masked_bodies", command, spans=[(h.operator_start, h.declaration_end, h.body_start, h.end) for h in heredocs]
    )


def mask_complete_heredocs(command: str, heredocs: tuple[ShellHeredoc, ...]) -> str:
    return call(
        "masked_complete", command, spans=[(h.operator_start, h.declaration_end, h.body_start, h.end) for h in heredocs]
    )


class ShellScanState:
    """Mutable public scan DTO; transitions are computed together in Rust."""

    def __init__(self) -> None:
        self.quote: str | None = None
        self.subshell_depth = 0
        self.in_backtick = False
        self._top_level: bool | None = None
        self._top_level_runtime: tuple[object, ...] | None = None
        self._key: tuple[object, ...] | None = None
        self._rows: dict[int, tuple[tuple[object, ...], list[Any]]] = {}
        self._expected: tuple[object, ...] = (None, 0, False)

    @property
    def is_top_level(self) -> bool:
        if self._top_level is None or (self.quote, self.subshell_depth, self.in_backtick) != self._expected:
            identity = runtime_key()
            self._top_level = call("top_level", "", state=[self.quote, self.subshell_depth, self.in_backtick])
            self._top_level_runtime = identity
            self._expected = (self.quote, self.subshell_depth, self.in_backtick)
        return cast(bool, self._top_level)

    def advance(self, command: str, index: int) -> int:
        state = (self.quote, self.subshell_depth, self.in_backtick)
        cached = self._rows.get(index)
        if self._key is None or command != self._key[0] or cached is None or cached[0] != state or index == 0:
            key = (command, *runtime_key())
            rows = call("trace", command, state=list(state), index=index)
            self._rows = {}
            preceding = state
            for row in rows:
                self._rows[row[0]] = (preceding, row)
                preceding = tuple(row[2:5])
            self._key = key
        row = self._rows[index][1]
        self.quote, self.subshell_depth, self.in_backtick, self._top_level = row[2:]
        self._expected = (self.quote, self.subshell_depth, self.in_backtick)
        self._top_level_runtime = self._key[1:]
        return row[1]
