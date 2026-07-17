"""Shared token helpers for canonical command segments."""

from __future__ import annotations

from .command_structure import CommandRedirect
from .command_tokens import shell_tokens


def shell_tokens_without_redirects(
    command: str,
    *,
    source_offset: int,
    redirects: tuple[CommandRedirect, ...],
) -> tuple[str, ...]:
    """Tokenize a command after masking redirects owned by its segment."""

    masked = list(command)
    for redirect in redirects:
        local_start = redirect.start - source_offset
        local_end = redirect.end - source_offset
        if local_start < 0 or local_end > len(masked):
            continue
        masked[local_start:local_end] = " " * (local_end - local_start)
    return shell_tokens("".join(masked))[0]
