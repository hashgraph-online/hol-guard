"""Guard's hook groups in the Muse and Devin user settings.

The native ``harness_hook_settings`` kind validates a settings ``hooks`` value,
prunes the handlers an earlier Guard install wrote, sets each managed group's
timeout and merges Guard's handler back in. serde_json does not keep object
order, so it answers with index plans over the caller's own lists; this module
rebuilds ``hooks`` from them, keeping the user's objects and key order.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal, cast

if TYPE_CHECKING:
    from ..native_runner_authority import NativeRunnerAuthorityError

HookHarness = Literal["muse", "devin"]
_TIMING_KEYS = {"muse": "bridge_seconds", "devin": "wait_seconds"}
_NOT_OBJECT = "harness_hook_settings_hooks_not_object"
_NOT_LIST = "harness_hook_settings_event_not_list"
_Guard = tuple[int, str | None]


class HookSettingsRefusedError(ValueError):
    """Guard will not rewrite this ``hooks`` value; ``event`` names the first non-list event."""

    def __init__(self, code: str, event: str | None) -> None:
        super().__init__(code)
        self.event: str | None = event


def _as_list(value: object) -> list[object] | None:
    return cast("list[object]", value) if isinstance(value, list) else None


def _as_dict(value: object) -> dict[str, object] | None:
    return cast("dict[str, object]", value) if isinstance(value, dict) else None


def _malformed() -> NativeRunnerAuthorityError:
    from ..native_runner_authority import NativeRunnerAuthorityError

    return NativeRunnerAuthorityError("Harness hook settings answer is malformed")


def _ask(harness: HookHarness, op: str, **fields: object) -> list[list[object]]:
    """The ``[event, ...]`` rows of one answer, events distinct; only an install can be refused."""

    # Imported here so the hook bridges stay off the native runtime at import time.
    from ..native_runner_authority import native_runner_authority

    request = {"op": op, "harness": harness, **fields}
    answer: dict[str, object] = native_runner_authority("harness_hook_settings", request)
    error = answer.get("error")
    if error is not None:
        event = answer.get("event")
        if (
            op == "install"
            and set(answer) == {"error", "event"}
            and ((error == _NOT_OBJECT and event is None) or (error == _NOT_LIST and isinstance(event, str)))
        ):
            raise HookSettingsRefusedError(str(error), event if isinstance(event, str) else None)
        raise _malformed()
    rows = _as_list(answer.get("hooks"))
    if set(answer) != {"hooks"} or rows is None:
        raise _malformed()
    width = 3 if op == "install" else 2
    checked = [row for row in map(_as_list, rows) if row is not None and len(row) == width]
    if len(checked) != len(rows) or len({row[0] for row in checked if isinstance(row[0], str)}) != len(rows):
        raise _malformed()
    return checked


def _index(value: object, size: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < size:
        raise _malformed()
    return value


def _rebuild(entries: object, plan: object, handler: dict[str, object] | None) -> list[object]:
    """Apply one list plan to the caller's own entries; ``None`` items are Guard's handler."""

    own = _as_list(entries) or []
    steps = _as_list(plan)
    if steps is None:
        raise _malformed()
    rebuilt: list[object] = []
    for value in steps:
        step = _as_dict(value)
        items = _as_list(step.get("hooks")) if step is not None else None
        if step is None:
            rebuilt.append(own[_index(value, len(own))])
        elif set(step) == {"entry", "hooks"} and items is not None:
            entry = _as_dict(own[_index(step["entry"], len(own))])
            if entry is None:
                raise _malformed()
            nested = _as_list(entry.get("hooks")) or []
            copy = dict(entry)
            copy["hooks"] = [
                handler if item is None and handler is not None else nested[_index(item, len(nested))] for item in items
            ]
            rebuilt.append(copy)
        elif handler is not None and set(step) == {"matcher"} and isinstance(step["matcher"], str | None):
            group: dict[str, object] = {"hooks": [handler]}
            if step["matcher"] is not None:
                group["matcher"] = step["matcher"]
            rebuilt.append(group)
        else:
            raise _malformed()
    return rebuilt


def _guard(value: object) -> _Guard | None:
    if value is None:
        return None
    guard = _as_dict(value)
    if guard is None or set(guard) != {"timeout", "status"}:
        raise _malformed()
    timeout, status = guard["timeout"], guard["status"]
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not isinstance(status, str | None):
        raise _malformed()
    return timeout, status


class GuardHooksPlan:
    """Guard's install rewrite of one ``hooks`` object, waiting for the bridge command."""

    def __init__(self, hooks: dict[str, object], rows: list[list[object]]) -> None:
        self._hooks: dict[str, object] = hooks
        self._rows: list[tuple[str, object, _Guard | None]] = []
        for event, plan, guard_value in rows:
            guard = _guard(guard_value)
            if not isinstance(event, str) or (plan is None and (guard is not None or event not in hooks)):
                raise _malformed()
            self._rows.append((event, plan, guard))
        # Rebuilding once here refuses a malformed plan before the caller renders anything.
        _ = self.apply("")

    def apply(self, command: str) -> dict[str, object]:
        """The rewritten ``hooks``: user values kept, Guard's handlers running ``command``."""

        rebuilt: dict[str, object] = {}
        for event, plan, guard in self._rows:
            if plan is None:
                rebuilt[event] = self._hooks[event]
                continue
            handler: dict[str, object] | None = None
            if guard is not None:
                handler = {"type": "command", "command": command, "timeout": guard[0]}
                if guard[1] is not None:
                    handler["statusMessage"] = guard[1]
            rebuilt[event] = _rebuild(self._hooks.get(event), plan, handler)
        return rebuilt


def plan_guard_hooks(harness: HookHarness, hooks: object, timing_seconds: int) -> GuardHooksPlan:
    """Validate ``hooks`` and plan Guard's groups; raises ``HookSettingsRefusedError`` for a value Guard won't rewrite.

    ``timing_seconds`` is Muse's bridge deadline or Devin's configured approval wait.
    """

    known = _as_dict(hooks)
    fields: dict[str, object] = {
        "hooks": hooks,
        "hooks_keys": None if known is None else list(known),
        _TIMING_KEYS[harness]: timing_seconds,
    }
    return GuardHooksPlan(known or {}, _ask(harness, "install", **fields))


def prune_guard_hooks(harness: HookHarness, hooks: dict[str, object]) -> dict[str, object]:
    """``hooks`` without Guard's handlers; events left without entries are dropped."""

    pruned: dict[str, object] = {}
    for event, plan in _ask(harness, "prune", hooks=hooks, hooks_keys=list(hooks)):
        if not isinstance(event, str) or event not in hooks:
            raise _malformed()
        pruned[event] = hooks[event] if plan is None else _rebuild(hooks[event], plan, None)
    return pruned
