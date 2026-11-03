"""Copilot hook entry plans from the native ``copilot_hook_config`` kind.

Which hook entries Guard wrote, the bash and PowerShell spellings of Guard's
hook command, and how the workspace hook file is normalized are decided
natively. Python keeps the file I/O and Guard's hook argv. Answers are index
plans into the caller's own lists, so user entries keep their objects and key
order.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path


class CopilotHookOwnershipError(RuntimeError):
    """The native runtime could not say which Copilot hook commands Guard wrote."""


_UNANSWERED = (
    "Guard could not read which Copilot hooks it installed; the native Guard runtime did not answer. "
    "Run `hol-guard doctor copilot` and try again."
)


@dataclass(frozen=True)
class CopilotHookPlan:
    """Guard's command for one hooks object and the user entries each managed event keeps."""

    bash: str
    powershell: str
    hooks: dict[str, object]
    kept: tuple[tuple[str, list[object]], ...]
    payload: dict[str, object] | None = None

    def install(self, entry: dict[str, object]) -> None:
        """Keep the user's entries of each managed event and append Guard's *entry*."""

        for event, entries in self.kept:
            self.hooks[event] = [*entries, entry]

    def uninstall(self) -> None:
        """Keep the user's entries of each managed event; drop events left empty."""

        for event, entries in self.kept:
            if entries:
                self.hooks[event] = list(entries)
            else:
                self.hooks.pop(event, None)


# The events Guard manages, in the order the native runtime answers them.
_MANAGED_EVENTS = ("userPromptSubmitted", "preToolUse", "postToolUse", "permissionRequest", "permissionRequestV2")


def _malformed() -> CopilotHookOwnershipError:
    return CopilotHookOwnershipError(_UNANSWERED)


def _isolated_bridge(guard_home: Path) -> tuple[str | None, str | None]:
    from .bounded_cli_hook_bridge import bounded_hook_script_path
    from .cursor_hook_config import isolated_cursor_hook_python

    script = bounded_hook_script_path(guard_home, "copilot")
    return isolated_cursor_hook_python(), None if script is None else str(script)


def _ask(request: dict[str, object]) -> dict[str, object]:
    # Imported here so adapter imports stay off the native runtime.
    from ..native_runner_authority import native_runner_authority

    try:
        answer: dict[str, object] = native_runner_authority("copilot_hook_config", request)
    except ValueError as error:
        # `NativeRunnerAuthorityError`, or user JSON the request cannot carry.
        raise CopilotHookOwnershipError(_UNANSWERED) from error
    return answer


def _indices(value: object, size: int) -> list[int]:
    """Strictly increasing indices below *size*."""

    if not isinstance(value, list):
        raise _malformed()
    previous = -1
    for index in value:
        if isinstance(index, bool) or not isinstance(index, int) or not previous < index < size:
            raise _malformed()
        previous = index
    return value


def _text(answer: dict[str, object], key: str) -> str:
    value = answer.get(key)
    if not isinstance(value, str):
        raise _malformed()
    return value


def _normalized(payload: dict[str, object], keys: list[str], answer: dict[str, object]) -> dict[str, object]:
    """`{"version", "hooks"}` of the workspace hook file, from the caller's own objects."""

    keep_version, lists = answer.get("version"), answer.get("hooks")
    if not isinstance(keep_version, bool) or (keep_version and "version" not in payload):
        raise _malformed()
    if lists is None:
        nested = payload.get("hooks")
        if not isinstance(nested, dict):
            raise _malformed()
        hooks = {str(name): list(entries) if isinstance(entries, list) else entries for name, entries in nested.items()}
    else:
        hooks = {}
        for index in _indices(lists, len(keys)):
            entries = payload[keys[index]]
            if not isinstance(entries, list):
                raise _malformed()
            hooks[keys[index]] = list(entries)
    return {"version": payload["version"] if keep_version else 1, "hooks": hooks}


def _plan(
    answer: object, hooks: dict[str, object] | None, workspace: tuple[dict[str, object], list[str]] | None
) -> CopilotHookPlan:
    if not isinstance(answer, dict) or set(answer) != (
        {"bash", "powershell", "events"} | ({"version", "hooks"} if workspace is not None else set())
    ):
        raise _malformed()
    payload = None if workspace is None else _normalized(*workspace, answer)
    target = hooks if payload is None else payload["hooks"]
    events = answer["events"]
    if not isinstance(target, dict) or not isinstance(events, list):
        raise _malformed()
    if len(events) != len(_MANAGED_EVENTS):
        raise _malformed()
    kept: list[tuple[str, list[object]]] = []
    for expected, event in zip(_MANAGED_EVENTS, events, strict=True):
        if not isinstance(event, list) or len(event) != 2 or event[0] != expected:
            raise _malformed()
        name, indices = event
        entries = target.get(name)
        source = entries if isinstance(entries, list) else []
        kept.append((name, [source[index] for index in _indices(indices, len(source))]))
    return CopilotHookPlan(_text(answer, "bash"), _text(answer, "powershell"), target, tuple(kept), payload)


def plan_copilot_hooks(
    guard_home: Path,
    config: tuple[dict[str, object], Sequence[str]],
    workspace: tuple[dict[str, object], Sequence[str]] | None,
) -> tuple[CopilotHookPlan, CopilotHookPlan | None]:
    """Plan the config's inline *hooks* and the raw workspace hook file in one native call.

    Each pair carries Guard's hook argv for that file. Raises
    `CopilotHookOwnershipError` when the runtime cannot answer, so an install
    never duplicates Guard's entries and an uninstall never leaves them behind.
    """

    interpreter, script = _isolated_bridge(guard_home)
    config_hooks, config_parts = config
    jobs: list[dict[str, object]] = [{"parts": list(config_parts), "hooks": config_hooks}]
    keys: list[str] = []
    if workspace is not None:
        keys = list(workspace[0])
        jobs.append({"parts": list(workspace[1]), "payload": workspace[0], "keys": keys})
    answer = _ask({"op": "plan", "interpreter": interpreter, "script": script, "jobs": jobs})
    plans = answer.get("jobs")
    if set(answer) != {"jobs"} or not isinstance(plans, list) or len(plans) != len(jobs):
        raise _malformed()
    config_plan = _plan(plans[0], config_hooks, None)
    if workspace is None:
        return config_plan, None
    return config_plan, _plan(plans[1], None, (workspace[0], keys))


__all__ = ["CopilotHookOwnershipError", "CopilotHookPlan", "plan_copilot_hooks"]
