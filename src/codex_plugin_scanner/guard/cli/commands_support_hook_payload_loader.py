"""Raw hook payload loading. The native runtime prepares each harness payload."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def read_stdin_text(limit: int | None = None) -> tuple[str, bool]:
    """Read hook stdin as UTF-8, whatever the console code page is.

    Harnesses send UTF-8 JSON. Text-mode ``sys.stdin`` decodes with the locale
    encoding, which on Windows (cp1252) turns ``café`` into ``cafÃ©`` before
    Guard reviews it. Returns the text and whether it exceeded ``limit`` bytes.
    """

    stream = getattr(sys.stdin, "buffer", None)
    if stream is None:
        text = sys.stdin.read() if limit is None else sys.stdin.read(limit + 1)
        size = len(text.encode("utf-8", errors="replace"))
        return text, limit is not None and size > limit
    raw = stream.read() if limit is None else stream.read(limit + 1)
    oversized = limit is not None and len(raw) > limit
    return raw.decode("utf-8-sig", errors="replace"), oversized


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
