"""Preserve user TOML while owning only Guard's durable protection settings.

The native runtime owns the format-preserving merge and removal. This module
ships the typed request, names the generated hook clients that no longer exist,
and raises the runtime's refusal text as a ``ValueError``.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TypeVar, cast

from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

_STATE_KEYS = frozenset({"added_deny_rules", "added_hook_events", "hook_command", "prior_compat_hooks", "created_keys"})
_Field = TypeVar("_Field")


def _malformed() -> NativeRunnerAuthorityError:
    return NativeRunnerAuthorityError("Grok user config answer is malformed")


def _ask(request: Mapping[str, object]) -> dict[str, object]:
    answer: dict[str, object] = native_runner_authority("grok_user_config", request)
    if "error" in answer:
        message = answer["error"]
        if not isinstance(message, str) or len(answer) != 1:
            raise _malformed()
        raise ValueError(message)
    return answer


def _field(answer: Mapping[str, object], key: str, kind: type[_Field]) -> _Field:
    value = answer.get(key)
    if not isinstance(value, kind):
        raise _malformed()
    return value


def prepare_user_config_text(
    existing_text: str, hook_command: str, *, previous_state: Mapping[str, object]
) -> tuple[str, dict[str, object]]:
    """Merge permissions, compatibility and identical backup hooks without table duplication."""
    # A different Guard home has its own ownership record, but shares Grok's
    # user config. Retire only missing generated clients for the same user.
    from ..cli.grok_hook_validation import is_missing_grok_hook_command

    read: dict[str, object] = {"existing_text": existing_text, "previous_state": dict(previous_state)}
    commands = cast(list[object], _field(_ask({**read, "mode": "candidates"}), "commands", list))
    if not all(isinstance(command, str) for command in commands):
        raise _malformed()
    retired = [command for command in cast(list[str], commands) if is_missing_grok_hook_command(command, hook_command)]
    answer = _ask({**read, "hook_command": hook_command, "mode": "merge", "retired_commands": retired})
    state = cast(dict[str, object], _field(answer, "state", dict))
    if state.keys() != _STATE_KEYS:
        raise _malformed()
    return _field(answer, "merged", str), state


def remove_user_config_settings(existing_text: str, state: Mapping[str, object]) -> str:
    request = {"existing_text": existing_text, "mode": "remove", "previous_state": dict(state)}
    return _field(_ask(request), "text", str)
