"""Codex uninstall: the main config the uninstall writes.

The native ``uninstall_config`` harness-adapter op reads both payloads,
strips Guard's hooks, carries each remaining hook's saved state to its new
position, puts back what the install changed and renders the result. This
module only sends it the captured bytes.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping, Sequence
from pathlib import Path

from .base import HarnessContext


def render_without_guard(
    context: HarnessContext,
    config_path: Path,
    current_bytes: bytes,
    original: bytes | None,
    owned_bindings: Sequence[Mapping[str, object]],
    *,
    hooks_json_path: Path,
) -> tuple[bool, bytes | None]:
    """Whether the config goes, and its new bytes; None bytes keep the current ones."""

    import json

    from ..codex_hook_self_binding import install_fields, settle_short_paths, short_path_fields
    from .codex import _codex, _legacy_fields, _runtime_guard_home

    def encoded(data: bytes | None) -> str | None:
        return None if data is None else base64.b64encode(data).decode("ascii")

    request: dict[str, object] = {
        "config": str(config_path),
        "hooks_json": str(hooks_json_path),
        "current": encoded(current_bytes),
        "original": encoded(original),
        "owned": json.dumps(list(owned_bindings), separators=(",", ":")),
        **_legacy_fields(context),
        **install_fields(_runtime_guard_home(context), None),
        **short_path_fields(),
    }
    answer = settle_short_paths(lambda: _codex("uninstall_config", context, **request), request, "uninstall_config")
    text = answer.get("text")
    return answer.get("delete") is True, text.encode("utf-8") if isinstance(text, str) else None
