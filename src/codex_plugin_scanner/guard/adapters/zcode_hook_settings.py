"""Ask the native ``zcode_hook_settings`` kind for one ZCode hook surface's new text.

The native runtime reads the file text, plans Guard's hook groups, and renders
the whole file the way ``json.dumps(indent=2)`` does; this module only sends
the request and checks the answer.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

from .zcode_config import ZCODE_PRETOOL_MATCHERS

_MALFORMED = "ZCode hook settings answer is malformed"


def _ask(request: dict[str, object], keys: set[str]) -> dict[str, object]:
    # Imported here so the hook bridges stay off the native runtime at import time.
    from ..native_runner_authority import native_runner_authority

    try:
        answer = native_runner_authority("zcode_hook_settings", request)
    except ValueError as error:
        raise ValueError(f"ZCode hook settings plan failed: {error}") from error
    if not isinstance(answer, dict) or (answer.keys() != keys and answer.keys() != {"refusal"}):
        raise ValueError(_MALFORMED)
    return answer


def _base(op: str, text: str | None, path: Path, state: Mapping[str, object]) -> dict[str, object]:
    return {
        "op": op,
        "text": text,
        "path": str(path),
        "history": state.get("hooks_enabled_before"),
        "managed_config_path": state.get("managed_config_path"),
    }


def install_hook_surface(
    text: str | None,
    *,
    path: Path,
    desktop: bool,
    state: Mapping[str, object],
    command: str,
    timeouts: Mapping[str, int],
) -> tuple[str, dict[str, object]]:
    """The surface's new text and its pre-install ``enabled`` record; ``ValueError`` on a refusal."""

    request = _base("install", text, path, state)
    request.update(
        desktop=desktop,
        matchers=list(ZCODE_PRETOOL_MATCHERS),
        command=command,
        timeouts=dict(timeouts),
    )
    answer = _ask(request, {"text", "enabled"})
    refusal = answer.get("refusal")
    if refusal == "not_object":
        raise ValueError(f"ZCode config must be a JSON object: {path.name}")
    if refusal == "hooks_disabled":
        raise ValueError(
            f"ZCode user hooks are disabled in {path.name}; explicitly enable them before installing Guard."
        )
    rendered, enabled_text = answer.get("text"), answer.get("enabled")
    if not isinstance(rendered, str) or not isinstance(enabled_text, str):
        raise ValueError(_MALFORMED)
    try:
        enabled = json.loads(enabled_text)
    except json.JSONDecodeError as error:
        raise ValueError(_MALFORMED) from error
    if (
        not isinstance(enabled, dict)
        or enabled.keys() != {"present", "value"}
        or not isinstance(enabled["present"], bool)
    ):
        raise ValueError(_MALFORMED)
    return rendered, enabled


def uninstall_hook_surface(text: str, *, path: Path, state: Mapping[str, object]) -> str | None:
    """The surface's new text with Guard's hooks removed, ``None`` when it stays as it is."""

    answer = _ask(_base("uninstall", text, path, state), {"text"})
    rendered = answer.get("text")
    if "refusal" in answer or (rendered is not None and not isinstance(rendered, str)):
        raise ValueError(_MALFORMED)
    return rendered


__all__ = ["install_hook_surface", "uninstall_hook_surface"]
