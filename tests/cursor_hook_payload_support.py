"""Hook payload preparation through the native adapter, for tests."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

from codex_plugin_scanner.guard.native_hook_adapter import (
    _INVALID,
    NativeHookAdapterError,
    _Built,
    _call,
    _tagged,
    _Tagger,
)


def native_prepare_payload(
    harness: str,
    payload: Mapping[str, object],
    *,
    guard_home: Path | str | None = None,
) -> dict[str, object]:
    """Return the resident's prepared copy of one harness hook payload."""

    def build(shrunk: bool) -> _Built | None:
        if shrunk:
            return None  # the prepared copy echoes the payload; nothing is safely elidable
        tagger = _Tagger()
        query: dict[str, object] = {
            "kind": "prepare_payload",
            "harness": harness,
            "payload": _tagged(tagger, payload),
            "devin_project_dir": os.environ.get("DEVIN_PROJECT_DIR") or None,
        }
        return query, tagger

    result = _call(build, guard_home=guard_home, deadline=None, shape="prepare")
    if not isinstance(result, dict):
        raise NativeHookAdapterError(_INVALID)
    return result


def prepare_cursor_hook_payload(payload: Mapping[str, object]) -> dict[str, object]:
    """Map Cursor hook stdin JSON into Guard hook normalization shape."""

    return native_prepare_payload("cursor", payload)
