"""Cursor hook payload normalization."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from ....native_hook_adapter import native_prepare_payload


def prepare_cursor_hook_payload(payload: Mapping[str, object]) -> dict[str, object]:
    """Map Cursor hook stdin JSON into Guard hook normalization shape."""

    return native_prepare_payload("cursor", payload)


def _validated_hol_guard_src_path(path_str: str) -> str | None:
    """Accept only directories that look like a hol-guard source tree."""

    try:
        if not isinstance(path_str, str) or not path_str.strip():
            return None
        candidate = Path(path_str.strip()).expanduser().resolve()
    except (OSError, RuntimeError, ValueError, TypeError):
        return None
    if not candidate.is_dir():
        return None
    if not (candidate / "codex_plugin_scanner").is_dir():
        return None
    return str(candidate)


def cursor_hook_would_prompt_user(
    *,
    policy_action: str,
    guard_payload: Mapping[str, object] | None = None,
) -> bool:
    """Return True when Guard maps this hook result to Cursor permission ask."""

    del guard_payload
    return policy_action in {"require-reapproval", "review"}
