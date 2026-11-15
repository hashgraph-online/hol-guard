"""Codex uninstall: undo the install's changes to the config and keep the user's later ones.

The native ``uninstall_restore`` harness-adapter op decides what to put back.
This module reads the two payloads, strips Guard's hooks with the adapter's
existing helper, carries each remaining hook's saved state to its new
position, and writes the answer.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path

from ..codex_config import dump_toml, read_config_bytes
from ..codex_hook_integrity import atomic_write_text
from ..codex_hook_sources import parse_json_object, parse_toml_object
from ..codex_hook_trust import remap_hook_state
from .base import HarnessContext


def follow_hook_state(before: Mapping[str, object], cleaned: dict[str, object], config_path: Path) -> None:
    """Move ``[hooks.state]`` with the hooks that stay once Guard's groups are gone.

    Codex keys hook state by position, so removing Guard's groups moves every
    later hook up. Without this, a hook the user trusted would keep its trusted
    hash at its old key and Codex would skip it. State left only for removed
    handlers is dropped, and an emptied table goes with it.
    """

    remap_hook_state(before, cleaned, config_path)
    if cleaned.get("state") == {}:
        cleaned.pop("state")


def _snapshot(config_path: Path) -> bytes:
    """The config's bytes, or a stop: an unreadable file must not read as empty and be deleted."""

    try:
        return config_path.read_bytes()
    except OSError as exc:
        raise RuntimeError(
            f"codex_uninstall_config_unreadable: Guard could not read the Codex config at {config_path}, "
            "so it left the file and the install backup in place. Repair the file's permissions and run "
            "`hol-guard uninstall codex` again."
        ) from exc


def _json_bytes(hooks_json_path: Path) -> bytes | None:
    """The hooks file's bytes, None when it is absent, or a stop when it exists and cannot be read."""

    if not hooks_json_path.exists():
        return None
    try:
        return hooks_json_path.read_bytes()
    except OSError as exc:
        raise RuntimeError(
            f"codex_uninstall_config_unreadable: Guard could not read the Codex hooks file at {hooks_json_path}, "
            "so it left the config and the install backup in place. Repair the file's permissions and run "
            "`hol-guard uninstall codex` again."
        ) from exc


def _user_json_hooks(
    context: HarnessContext,
    hooks_json_path: Path,
    data: bytes | None,
    owned_bindings: Sequence[Mapping[str, object]],
) -> dict[str, object] | None:
    """The hooks left in ``hooks.json``, which uninstall keeps, without any Guard handler."""

    from .codex import _strip_owned_hooks

    try:
        payload = parse_json_object(data, path=hooks_json_path, label="Codex hooks file")
    except RuntimeError:
        # Codex cannot run hooks from a file it cannot parse, and uninstall
        # leaves the file as it is, so it holds no hook that needs the feature.
        return None
    hooks = payload.get("hooks")
    return _strip_owned_hooks(context, hooks, owned_bindings) if isinstance(hooks, dict) else None


def restore_without_guard(
    context: HarnessContext,
    config_path: Path,
    original_text: str,
    owned_bindings: Sequence[Mapping[str, object]],
    *,
    hooks_json_path: Path,
) -> None:
    """Write the config back without what the install added, keeping every later edit."""

    from .codex import _codex, _reply_text, _strip_owned_hooks, _Wire

    current_bytes = _snapshot(config_path)
    current = parse_toml_object(current_bytes, path=config_path, label="Codex config file")
    backup = (
        parse_toml_object(original_text.encode("utf-8"), path=config_path, label="Codex config backup")
        if original_text
        else None
    )
    hooks = current.get("hooks")
    cleaned: dict[str, object] | None = None
    if isinstance(hooks, dict):
        cleaned = _strip_owned_hooks(context, hooks, owned_bindings)
        follow_hook_state(hooks, cleaned, config_path)
    json_bytes = _json_bytes(hooks_json_path)
    json_hooks = _user_json_hooks(context, hooks_json_path, json_bytes, owned_bindings)
    wire = _Wire(current, *(part for part in (backup, cleaned, json_hooks) if part is not None))
    answer = _codex(
        "uninstall_restore",
        context,
        payload=wire.text(current),
        backup=None if backup is None else wire.text(backup),
        hooks=None if cleaned is None else wire.text(cleaned),
        json_hooks=None if json_hooks is None else wire.text(json_hooks),
        tokens=wire.meanings,
    )
    # The answer describes the snapshot of both files. An edit made meanwhile
    # is not overwritten with it; the user runs uninstall again.
    if read_config_bytes(config_path) != current_bytes or _json_bytes(hooks_json_path) != json_bytes:
        raise RuntimeError(
            f"codex_uninstall_config_changed: the Codex config at {config_path} or its hooks file changed while "
            "Guard was uninstalling, so Guard left them and the install backup in place. Run "
            "`hol-guard uninstall codex` again."
        )
    if answer.get("delete") is True:
        config_path.unlink()
    elif answer.get("changed") is True:
        rendered = wire.decode(_reply_text(answer, "rendered"))
        # Nothing changed since install: put back the user's exact bytes.
        text = original_text if rendered == backup else dump_toml(rendered, original=current_bytes)
        atomic_write_text(config_path, text, mode=0o600)
