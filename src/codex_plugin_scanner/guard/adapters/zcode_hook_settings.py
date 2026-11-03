"""Apply the native ``zcode_hook_settings`` plan to a ZCode ``hooks`` mapping.

The answer names entries of the caller's own lists by index, so every user
object (and its key order) is kept; this module only checks and applies it.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .zcode_config import ZCODE_HOOKS_EVENTS_KEY, ZCODE_PRETOOL_MATCHERS

_SOURCES = ("events", "hooks")
_GROUP_MATCHERS: dict[str, frozenset[str | None]] = {
    "PreToolUse": frozenset(ZCODE_PRETOOL_MATCHERS),
    "UserPromptSubmit": frozenset({None}),
}
_MALFORMED = "ZCode hook settings answer is malformed"
_Plans = tuple[tuple[str, "list[object] | None"], ...]


@dataclass(frozen=True)
class HookSettingsPlan:
    """A checked plan whose lists already hold the caller's own entries."""

    install: bool
    enabled: dict[str, object]
    has_handlers: bool
    drop: tuple[str, ...]
    events: _Plans
    flat: _Plans

    def apply(self, hooks: dict[str, object]) -> None:
        events_value = hooks.get(ZCODE_HOOKS_EVENTS_KEY)
        if self.install:
            events: dict[str, object] = dict(events_value) if isinstance(events_value, dict) else {}
            for name in self.drop:
                hooks.pop(name, None)
            events.update(self.events)
            hooks[ZCODE_HOOKS_EVENTS_KEY] = events
            return
        if isinstance(events_value, dict):
            _assign(events_value, self.events)
            if not events_value:
                hooks.pop(ZCODE_HOOKS_EVENTS_KEY, None)
        _assign(hooks, self.flat)
        # Guard's opt-in goes back to the pre-install flag.
        if hooks.get("enabled") is True:
            if self.enabled["present"]:
                hooks["enabled"] = self.enabled["value"]
            else:
                hooks.pop("enabled")


def _assign(target: dict[str, object], plans: _Plans) -> None:
    for name, entries in plans:
        if entries is None:
            target.pop(name, None)
        else:
            target[name] = entries


def plan_hook_settings(
    op: Literal["install", "uninstall"],
    hooks: dict[str, object],
    *,
    path: Path,
    state: Mapping[str, object],
    handlers: Mapping[str, dict[str, object]] | None = None,
) -> HookSettingsPlan:
    """Ask the native runtime for one surface's plan; raise ``ValueError`` on a refusal."""

    # Imported here so the hook bridges stay off the native runtime at import time.
    from ..native_runner_authority import native_runner_authority

    install = op == "install"
    request: dict[str, object] = {
        "op": op,
        # JSON text keeps the mapping's key order, which decides event order.
        "hooks": json.dumps(hooks, ensure_ascii=False),
        "path": str(path),
        "history": state.get("hooks_enabled_before"),
        "managed_config_path": state.get("managed_config_path"),
    }
    if install:
        request["matchers"] = list(ZCODE_PRETOOL_MATCHERS)
    try:
        answer = native_runner_authority("zcode_hook_settings", request)
    except ValueError as error:
        raise ValueError(f"ZCode hook settings plan failed: {error}") from error
    keys = {"enabled", "has_handlers", "drop", "events"} if install else {"enabled", "events", "hooks"}
    if not isinstance(answer, dict) or answer.keys() != keys:
        raise ValueError(_MALFORMED)
    enabled = answer["enabled"]
    if enabled is None:
        enabled = {"present": "enabled" in hooks, "value": hooks.get("enabled")}
    elif (
        not isinstance(enabled, dict)
        or enabled.keys() != {"present", "value"}
        or not isinstance(enabled["present"], bool)
        or (enabled["present"] and not isinstance(enabled["value"], bool))
    ):
        raise ValueError(_MALFORMED)
    # Flat lists, legacy on install, named in the mapping's own order.
    flat_names = [name for name, value in hooks.items() if name != ZCODE_HOOKS_EVENTS_KEY and isinstance(value, list)]
    if not install:
        events_value = hooks.get(ZCODE_HOOKS_EVENTS_KEY)
        event_names = list(events_value) if isinstance(events_value, dict) else []
        events = _plans(answer["events"], hooks, event_names, lambda _name: ("events",))
        flat = _plans(answer["hooks"], hooks, flat_names, lambda _name: ("hooks",))
        return HookSettingsPlan(False, enabled, False, (), events, flat)
    has_handlers, drop = answer["has_handlers"], answer["drop"]
    if not isinstance(has_handlers, bool) or not isinstance(drop, list) or drop != [n for n in flat_names if n in drop]:
        raise ValueError(_MALFORMED)
    names = [*drop, *(name for name in _GROUP_MATCHERS if name not in drop)]
    events = _plans(
        answer["events"],
        hooks,
        names,
        lambda name: _SOURCES if name in drop else ("events",),
        handlers=handlers or {},
    )
    return HookSettingsPlan(True, enabled, has_handlers, tuple(drop), events, ())


def _plans(
    value: object,
    hooks: Mapping[str, object],
    names: list[str],
    sources: Callable[[str], tuple[str, ...]],
    *,
    handlers: Mapping[str, dict[str, object]] | None = None,
) -> _Plans:
    """Check one answer's lists: exactly ``names``, in order; uninstall drops with ``null``."""

    if not isinstance(value, list) or len(value) != len(names):
        raise ValueError(_MALFORMED)
    plans: list[tuple[str, list[object] | None]] = []
    for pair, name in zip(value, names, strict=True):
        if not isinstance(pair, list) or len(pair) != 2 or pair[0] != name:
            raise ValueError(_MALFORMED)
        items = pair[1]
        if handlers is None and items is None:
            plans.append((name, None))
            continue
        if not isinstance(items, list) or (handlers is None and not items):
            raise ValueError(_MALFORMED)
        plans.append((name, _entries(items, hooks, name, sources(name), (handlers or {}).get(name))))
    return tuple(plans)


def _index(value: object, size: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < size:
        raise ValueError(_MALFORMED)
    return value


def _entries(
    items: list[object],
    hooks: Mapping[str, object],
    name: str,
    sources: tuple[str, ...],
    handler: dict[str, object] | None,
) -> list[object]:
    """Build one event list from references and new groups."""

    built: list[object] = []
    for item in items:
        if isinstance(item, dict) and item.keys() == {"group"}:
            matcher = item["group"]
            if handler is None or matcher not in _GROUP_MATCHERS.get(name, frozenset()):
                raise ValueError(_MALFORMED)
            group: dict[str, object] = {"hooks": [handler]}
            if matcher is not None:
                group["matcher"] = matcher
            built.append(group)
            continue
        copy = isinstance(item, dict) and item.keys() == {"copy", "hooks"}
        reference = item["copy"] if copy and isinstance(item, dict) else item
        if not isinstance(reference, list) or len(reference) != 2 or reference[0] not in sources:
            raise ValueError(_MALFORMED)
        container = hooks.get(ZCODE_HOOKS_EVENTS_KEY) if reference[0] == "events" else hooks
        source = container.get(name) if isinstance(container, dict) else None
        if not isinstance(source, list):
            raise ValueError(_MALFORMED)
        entry = source[_index(reference[1], len(source))]
        if not copy:
            built.append(entry)
            continue
        if not isinstance(entry, dict) or not isinstance(item, dict):
            raise ValueError(_MALFORMED)
        built.append({**entry, "hooks": _handlers(item["hooks"], entry.get("hooks"), handler)})
    return built


def _handlers(value: object, own: object, handler: dict[str, object] | None) -> list[object]:
    if not isinstance(value, list):
        raise ValueError(_MALFORMED)
    kept: list[object] = []
    for item in value:
        if item == "guard" and handler is not None:
            kept.append(handler)
            continue
        if not isinstance(own, list):
            raise ValueError(_MALFORMED)
        kept.append(own[_index(item, len(own))])
    return kept


__all__ = ["HookSettingsPlan", "plan_hook_settings"]
