"""Public data-flow structures projected by the native shell owner."""

from __future__ import annotations

from dataclasses import dataclass

from ..native_shell_helpers import call
from .shell_structure import (
    ShellCommandSubstitution as ShellCommandSubstitution,
)
from .shell_structure import (
    ShellHeredoc as ShellHeredoc,
)
from .shell_structure import (
    ShellScanState as _ShellScanState,  # noqa: F401
)
from .shell_structure import (
    extract_command_substitution_spans as extract_command_substitution_spans,
)
from .shell_structure import (
    extract_command_substitutions as extract_command_substitutions,
)
from .shell_structure import (
    extract_expanded_heredoc_substitution_spans as extract_expanded_heredoc_substitution_spans,
)
from .shell_structure import (
    extract_heredocs as extract_heredocs,
)
from .shell_structure import (
    mask_complete_heredocs as mask_complete_heredocs,
)
from .shell_structure import (
    mask_heredoc_bodies as mask_heredoc_bodies,
)


@dataclass(frozen=True, slots=True)
class ShellPipe:
    left: str
    right: str


def extract_input_redirects(command: str) -> tuple[str, ...]:
    return tuple(call("redirects", command))


def extract_pipes(command: str) -> tuple[ShellPipe, ...]:
    return tuple(ShellPipe(**row) for row in call("pipes", command))


def extract_command_segments(command: str) -> tuple[str, ...]:
    return tuple(call("segments", command))


def _split_top_level_pipes(command: str) -> tuple[str, ...]:
    return tuple(call("pipe_segments", command))
