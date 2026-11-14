"""Thin client for the native ``transition_files`` kind.

The resident compares, writes and publishes transition files; see
``rust/crates/guard-runtime/src/transition_files``. Two facts stay here: the
Codex mutation journal belongs to the process that owns the install
transaction, so each identity record the resident hands back is appended in
order, and whether a POSIX group is private to its owner is answered from
this process's account database when the resident asks.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .runtime_transition import TransitionFile

_TIMEOUT_SECONDS = 60.0
_MAX_ROUNDS = 8
_INVALID = "native_transition_invalid"


def _remaining_ms(deadline: float | None) -> int | None:
    if deadline is None:
        return None
    return max(0, int((deadline - time.monotonic()) * 1000))


def _budget() -> dict[str, int | None]:
    from .codex_hook_file_integrity import active_hook_validation_deadline
    from .runtime_transition import _ACTIVE_TRANSITION, _INVERSE_DEADLINE

    active = _ACTIVE_TRANSITION.get()
    return {
        "inverse_ms": _remaining_ms(_INVERSE_DEADLINE.get()),
        "forward_ms": _remaining_ms(active[2] if active is not None else None),
        "hook_ms": _remaining_ms(active_hook_validation_deadline()),
    }


def _package_files(files: Sequence[object]) -> list[str]:
    from .codex_hook_file_integrity import _is_installed_python_package_file

    paths: list[str] = []
    for change in files:
        path = change.get("path") if isinstance(change, Mapping) and "artifact_identity" in change else None
        if isinstance(path, str) and _is_installed_python_package_file(Path(path)):
            paths.append(path)
    return paths


def _exception(fault: object) -> BaseException:
    from .codex_hook_file_integrity import CodexHookIntegrityError
    from .runtime_transition import TransitionError

    if not isinstance(fault, Mapping):
        return TransitionError(_INVALID)
    if isinstance(fault.get("transition"), str):
        return TransitionError(fault["transition"])
    if isinstance(fault.get("integrity"), str) and isinstance(fault.get("message"), str):
        return CodexHookIntegrityError(fault["integrity"], fault["message"])
    if isinstance(fault.get("os"), str):
        number = fault.get("errno")
        if isinstance(number, int) and not isinstance(number, bool):
            return OSError(number, fault["os"])
        return OSError(fault["os"])
    return TransitionError(_INVALID)


def _replay(
    events: object,
    files: Sequence[TransitionFile] | None,
    on_write: Callable[[TransitionFile], None] | None,
) -> None:
    from .codex_install_transaction import record_codex_mutation_identity
    from .runtime_transition import TransitionError

    if not isinstance(events, list):
        raise TransitionError(_INVALID)
    for event in events:
        mutation = event.get("mutation") if isinstance(event, dict) else None
        if isinstance(mutation, dict):
            record_codex_mutation_identity(
                str(mutation.get("operation")),
                Path(str(mutation.get("path"))),
                before_present=mutation.get("before_present") is True,
                after_present=mutation.get("after_present") is True,
                before_digest=mutation.get("before_digest") if isinstance(mutation.get("before_digest"), str) else None,
                after_digest=mutation.get("after_digest") if isinstance(mutation.get("after_digest"), str) else None,
            )
            continue
        index = event.get("written") if isinstance(event, dict) else None
        if files is None or not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < len(files):
            raise TransitionError(_INVALID)
        if on_write is not None:
            on_write(files[index])


def _ask(
    request: dict[str, object],
    *,
    plan: Sequence[object],
    files: Sequence[TransitionFile] | None = None,
    on_write: Callable[[TransitionFile], None] | None = None,
) -> None:
    from .codex_hook_file_integrity import _owner_is_only_group_member
    from .native_runner_authority import native_runner_authority
    from .runtime_transition import TransitionError

    answers: list[dict[str, object]] = []
    request = {**request, "package_files": _package_files(plan)}
    for _ in range(_MAX_ROUNDS):
        request["budget"] = _budget()
        request["private_groups"] = answers
        answer = native_runner_authority("transition_files", request, timeout_seconds=_TIMEOUT_SECONDS)
        reply = answer.get("reply")
        if reply is not None:
            question = reply.get("private_group") if isinstance(reply, dict) else None
            owner_uid = question.get("owner_uid") if isinstance(question, dict) else None
            group_gid = question.get("group_gid") if isinstance(question, dict) else None
            asked = {(item["owner_uid"], item["group_gid"]) for item in answers}
            if not isinstance(owner_uid, int) or not isinstance(group_gid, int) or (owner_uid, group_gid) in asked:
                raise TransitionError("artifact_permissions_invalid")
            private = _owner_is_only_group_member(owner_uid, group_gid) is True
            answers.append({"owner_uid": owner_uid, "group_gid": group_gid, "private": private})
            continue
        _replay(answer.get("events"), files, on_write)
        error, restore_error = answer.get("error"), answer.get("restore_error")
        if restore_error is not None:
            raise _exception(restore_error) from _exception(error)
        if error is not None:
            raise _exception(error)
        if answer.get("ok") is not True:
            raise TransitionError(_INVALID)
        return
    raise TransitionError("artifact_permissions_invalid")


def compare_files(files: list[object], generation: str, *, inverse: bool = False) -> None:
    """``RuntimeTransition._compare``: every file still holds ``generation``."""

    request = {"op": "compare", "files": files, "generation": generation, "inverse": inverse}
    _ask(request, plan=files)


def write_file(change: dict[str, object], generation: str) -> None:
    """``RuntimeTransition._write_file``: publish one generation of one file."""

    _ask({"op": "write", "change": change, "generation": generation}, plan=[change])


def publish_files(
    files: Sequence[TransitionFile],
    *,
    removals: bool,
    rollback: bool,
    on_write: Callable[[TransitionFile], None] | None,
) -> None:
    """``PreparedHarnessInstall.publish``: the whole plan, restored on failure."""

    payloads = [change.payload() for change in files]
    request = {"op": "publish", "files": payloads, "removals": removals, "rollback": rollback}
    _ask(request, plan=payloads, files=files, on_write=on_write)


__all__ = ["compare_files", "publish_files", "write_file"]
