"""Cline hook payload entry points answered by the native runtime."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING

from ....native_hook_adapter import ClinePayloadError, native_prepare_payload

if TYPE_CHECKING:
    pass


def prepare_cline_hook_payload(payload: Mapping[str, object]) -> dict[str, object]:
    """Return a Guard-generic Cline payload without mutating the original."""

    return native_prepare_payload("cline", payload)


__all__ = ["ClinePayloadError", "prepare_cline_hook_payload"]
