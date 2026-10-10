"""Shared safety classifiers for Codex command and tool output."""

from __future__ import annotations

import re


def output_uses_placeholder_private_key_fixture(
    response_text: str,
    *,
    fixture_pattern: re.Pattern[str],
    fixture_body_pattern: re.Pattern[str],
) -> bool:
    """Return true only when every PEM-looking match is the known placeholder fixture."""

    matches = list(fixture_pattern.finditer(response_text))
    if not matches:
        return False
    return all(
        fixture_body_pattern.search(
            " ".join(line.strip() for line in match.group("body").splitlines() if line.strip())
            .replace("\\n", " ")
            .replace("\\r", " ")
        )
        is not None
        for match in matches
    )
