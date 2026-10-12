"""Cline hook payload entry points answered by the native runtime."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING

from ..native_hook_adapter import ClinePayloadError, native_prepare_payload

if TYPE_CHECKING:
    from ..runtime.actions import GuardActionEnvelope


def prepare_cline_hook_payload(payload: Mapping[str, object]) -> dict[str, object]:
    """Return a Guard-generic Cline payload without mutating the original."""

    return native_prepare_payload("cline", payload)


def normalize_cline_payload(
    payload: Mapping[str, object],
    *,
    workspace: Path | str | None = None,
    home_dir: Path | str | None = None,
    guard_home: Path | str | None = None,
    deadline: float | None = None,
) -> GuardActionEnvelope:
    """Normalize Cline onto Guard's canonical typed action envelope."""

    from ..runtime.actions import normalize_harness_payload

    return normalize_harness_payload(
        "cline",
        "",
        payload,
        workspace=workspace,
        home_dir=home_dir,
        guard_home=guard_home,
        deadline=deadline,
    )


__all__ = ["ClinePayloadError", "normalize_cline_payload", "prepare_cline_hook_payload"]
