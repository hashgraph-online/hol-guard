"""Migration and removal of Guard-owned Grok settings."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, cast

from .base import HarnessContext, _ensure_path_within_root
from .grok_user_config import remove_user_config_settings

if TYPE_CHECKING:
    from .grok import GrokHarnessAdapter


def parse_install_state(raw: bytes | None) -> dict[str, object]:
    payload = json.loads(raw.decode("utf-8")) if raw is not None else {}
    if not isinstance(payload, dict):
        raise ValueError("Grok managed state must be a JSON object.")
    return payload


def remove_legacy_settings(raw: bytes | None, state: Mapping[str, object]) -> bytes | None:
    """Strip Guard's block from the legacy managed config and restore the compat hooks it replaced."""
    if raw is None:
        return None
    from ..native_runner_authority import native_runner_authority

    prior = state.get("prior_compat_hooks")
    # Pairs keep the recorded vendor order, which the restoration follows.
    pairs = [[key, value] for key, value in cast(dict[str, object], prior).items()] if isinstance(prior, dict) else []
    answer = native_runner_authority("grok_legacy_settings", {"text": raw.decode("utf-8"), "prior_compat_hooks": pairs})
    text = answer.get("text") if isinstance(answer, dict) and len(answer) == 1 else None
    if not isinstance(text, str):
        raise ValueError("Grok legacy settings answer is malformed")
    return text.encode("utf-8")


def uninstall_settings(adapter: GrokHarnessAdapter, context: HarnessContext) -> list[str]:
    state_path = adapter._state_path(context)
    state = parse_install_state(state_path.read_bytes() if state_path.is_file() else None)
    durable = adapter._protection_config_path(context)
    owned = state.get("user_config_settings")
    notes = (
        ["Guard settings may remain in .grok/config.toml because ownership records are missing; review them manually."]
        if durable.is_file() and not isinstance(owned, Mapping)
        else []
    )
    changes: list[tuple[Path, bytes]] = []
    if durable.is_file() and isinstance(owned, Mapping):
        _ensure_path_within_root(adapter._grok_home_dir(context), durable, label="Grok")
        restored = remove_user_config_settings(durable.read_text(encoding="utf-8"), owned)
        changes.append((durable, (restored.rstrip() + "\n").encode("utf-8")))
    legacy = adapter._managed_config_path(context)
    if legacy.is_file():
        _ensure_path_within_root(adapter._grok_home_dir(context), legacy, label="Grok")
        before = legacy.read_bytes()
        after = remove_legacy_settings(before, state)
        if after is not None and after != before:
            changes.append((legacy, after))
    for path, content in changes:
        path.write_bytes(content)
    return notes
