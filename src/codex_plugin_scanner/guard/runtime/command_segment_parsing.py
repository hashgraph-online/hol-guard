"""Native tokenization with model-owned redirects removed."""

from __future__ import annotations

from dataclasses import asdict

from ..native_rich_command_model import request, string_tuple
from .command_structure import CommandRedirect


def shell_tokens_without_redirects(
    command: str,
    *,
    source_offset: int,
    redirects: tuple[CommandRedirect, ...],
) -> tuple[str, ...]:
    return string_tuple(
        request(
            "segment_tokens",
            {"command": command, "source_offset": source_offset, "redirects": [asdict(item) for item in redirects]},
        )
    )
