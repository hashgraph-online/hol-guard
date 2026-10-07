"""Migration and removal of Guard-owned Grok settings."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING

from .base import HarnessContext, _ensure_path_within_root
from .grok_config import GUARD_MANAGED_BEGIN, remove_managed_block, restore_compat_hooks
from .grok_state import _prior_compat_hooks_from_state
from .grok_user_config import remove_user_config_settings

if TYPE_CHECKING:
    from .grok import GrokHarnessAdapter


def parse_install_state(raw: bytes | None) -> dict[str, object]:
    payload = json.loads(raw.decode("utf-8")) if raw is not None else {}
    if not isinstance(payload, dict):
        raise ValueError("Grok managed state must be a JSON object.")
    return payload


def remove_legacy_settings(raw: bytes | None, state_path: Path, state: dict[str, object]) -> bytes | None:
    if raw is None:
        return None
    text = raw.decode("utf-8")
    if GUARD_MANAGED_BEGIN not in text:
        return raw
    prior = _prior_compat_hooks_from_state(state_path, payload=state)
    return restore_compat_hooks(remove_managed_block(text), prior).encode("utf-8")


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
        after = remove_legacy_settings(before, state_path, state)
        if after is not None and after != before:
            changes.append((legacy, after))
    for path, content in changes:
        path.write_bytes(content)
    return notes
