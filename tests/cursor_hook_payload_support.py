"""Cursor hook payload mapping through the native adapter, for tests."""

from __future__ import annotations

from collections.abc import Mapping

from codex_plugin_scanner.guard.native_hook_adapter import native_prepare_payload


def prepare_cursor_hook_payload(payload: Mapping[str, object]) -> dict[str, object]:
    """Map Cursor hook stdin JSON into Guard hook normalization shape."""

    return native_prepare_payload("cursor", payload)
