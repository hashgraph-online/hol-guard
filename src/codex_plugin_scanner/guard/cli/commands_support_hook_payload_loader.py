"""Raw hook payload loading. The native runtime prepares each harness payload."""

from __future__ import annotations

import json
from pathlib import Path

from ..adapters.hook_input_reader import read_stdin_text


def load_hook_payload(
    event_file: str | None,
    *,
    input_text: str | None = None,
) -> dict[str, object]:
    """Load one bounded hook payload exactly as the harness sent it."""

    if event_file:
        raw = Path(event_file).read_text(encoding="utf-8")
    else:
        raw = input_text.strip() if isinstance(input_text, str) else read_stdin_text()[0].strip()
    if not raw:
        return {}
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        return {}
    return payload


_load_hook_payload = load_hook_payload
