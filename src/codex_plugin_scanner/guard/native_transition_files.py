"""Thin client for the native ``transition_files`` kind.

The resident compares, writes and publishes transition files; see
``rust/crates/guard-runtime/src/transition_files``. Each identity record the
resident hands back goes to the owner's journal (``native_owned``), in order,
for the install transaction this process owns. Whether a POSIX group is private to its
owner is answered from this process's account database when the resident asks.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .runtime_transition import TransitionFile

_TIMEOUT_SECONDS = 60.0
# The budget a harness install or uninstall that publishes files gets.
PUBLISH_TIMEOUT_SECONDS = _TIMEOUT_SECONDS
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


def _package_roots() -> list[str]:
    from .codex_hook_file_integrity import _python_package_roots

    return [str(root) for root in _python_package_roots()]


def _exception(fault: object) -> BaseException:
    from .codex_hook_file_integrity import CodexHookIntegrityError
    from .runtime_transition import TransitionError

    if not isinstance(fault, Mapping):
        return TransitionError(_INVALID)
    transition, integrity = fault.get("transition"), fault.get("integrity")
    message, os_message = fault.get("message"), fault.get("os")
    runtime = fault.get("runtime")
    if isinstance(runtime, str):
        return RuntimeError(runtime)
    if isinstance(transition, str):
        detail = fault.get("detail")
        return TransitionError(transition, detail) if isinstance(detail, str) else TransitionError(transition)
    if isinstance(integrity, str) and isinstance(message, str):
        return CodexHookIntegrityError(integrity, message)
    if isinstance(os_message, str):
        number = fault.get("errno")
        if isinstance(number, int) and not isinstance(number, bool):
            return OSError(number, os_message)
        return OSError(os_message)
    return TransitionError(_INVALID)


def _replay(
    events: object,
    files: Sequence[TransitionFile] | None,
    on_write: Callable[[TransitionFile], None] | None,
) -> None:
    from .native_owned import record_codex_mutation_identities
    from .runtime_transition import TransitionError

    if not isinstance(events, list):
        raise TransitionError(_INVALID)
    pending: list[dict[str, object]] = []
    for event in events:
        mutation = event.get("mutation") if isinstance(event, dict) else None
        if isinstance(mutation, dict):
            pending.append(mutation)
            continue
        # Journal what was written before ``on_write`` sees the file.
        record_codex_mutation_identities(pending)
        pending = []
        index = event.get("written") if isinstance(event, dict) else None
        if files is None or not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < len(files):
            raise TransitionError(_INVALID)
        if on_write is not None:
            on_write(files[index])
    record_codex_mutation_identities(pending)


def _ask(
    request: dict[str, object],
    *,
    files: Sequence[TransitionFile] | None = None,
    on_write: Callable[[TransitionFile], None] | None = None,
    timeout_seconds: float = _TIMEOUT_SECONDS,
    context: bool = True,
) -> Mapping[str, object]:
    from .native_runner_authority import native_runner_authority

    request = {**request, **transition_context()} if context else request
    answer = native_runner_authority("transition_files", request, timeout_seconds=timeout_seconds)
    return _settle(answer, files, on_write)


def transition_context() -> dict[str, object]:
    """The package roots and deadlines a ``transition_files`` request carries."""
    return {"package_roots": _package_roots(), "budget": _budget()}


def settle(answer: object) -> None:
    """Journal and check a ``publish`` answer another native op ran."""
    from .runtime_transition import TransitionError

    if not isinstance(answer, Mapping):
        raise TransitionError(_INVALID)
    _settle(answer, None, None)


def _settle(
    answer: Mapping[str, object],
    files: Sequence[TransitionFile] | None,
    on_write: Callable[[TransitionFile], None] | None,
) -> Mapping[str, object]:
    from .runtime_transition import TransitionError

    _replay(answer.get("events"), files, on_write)
    error, restore_error = answer.get("error"), answer.get("restore_error")
    if restore_error is not None:
        raise _exception(restore_error) from _exception(error)
    if error is not None:
        raise _exception(error)
    if answer.get("ok") is not True:
        raise TransitionError(_INVALID)
    return answer


def publication(op: str, home: Path, *, timeout_seconds: float = _TIMEOUT_SECONDS, **fields: object) -> object:
    """One ``publication_*`` op on the home's Codex publication record."""

    import os

    request: dict[str, object] = {"op": f"publication_{op}", "home": os.path.abspath(home), **fields}
    return _ask(request, timeout_seconds=timeout_seconds).get("value")


def require_deadline(deadline: float) -> None:
    """``deadline_exceeded`` unless ``deadline`` is a finite number still ahead of now."""

    _ask({"op": "publication_deadline", "deadline": deadline, "now": time.monotonic()}, context=False)


def request_policy(stage: str, **fields: object) -> Mapping[str, object]:
    """The review artifact's lifetime policy: ``stamp``, ``plan`` or ``window``.

    The runtime decides; ``plan`` and ``window`` raise ``TransitionError`` on refusal.
    """

    value = _ask({"op": "publication_request_policy", "stage": stage, **fields}, context=False).get("value")
    return value if isinstance(value, Mapping) else {}


def runtime_compare(stage: str, **fields: object) -> None:
    """One comparison of a native-runtime inspection; the runtime raises on a mismatch.

    ``stage`` is ``probe``, ``capabilities``, ``version`` or ``generation``.
    """

    _ask({"op": "publication_runtime_compare", "stage": stage, **fields}, context=False)


def artifact_generation(kind: str, subject: str, *, bound: bool, restored: Sequence[int] | None = None) -> str:
    """The generation a ``repair`` or ``inverse`` is verified under.

    ``bound`` says the plan carries its runtime and workspace; an inverse also
    sends the indexes it ``restored``. The runtime refuses what is not ready.
    """

    request: dict[str, object] = {
        "op": "publication_artifact_generation",
        "kind": kind,
        "subject": subject,
        "bound": bound,
    }
    if restored is not None:
        request["restored"] = list(restored)
    value = _ask(request, context=False).get("value")
    if not isinstance(value, str):
        from .runtime_transition import TransitionError

        raise TransitionError(_INVALID)
    return value


def register_inverse(grant_id: str, deadline: float) -> tuple[str, ...]:
    """Admit the pending inverse of a grant; the grant ids the runtime purged as expired.

    The runtime refuses a grant already pending and a registry at capacity.
    """

    request: dict[str, object] = {
        "op": "publication_inverse_register",
        "grant_id": grant_id,
        "deadline": deadline,
        "now": time.monotonic(),
    }
    value = _ask(request, context=False).get("value")
    purged = value.get("purged") if isinstance(value, Mapping) else None
    if not isinstance(purged, list) or not all(isinstance(item, str) for item in purged):
        from .runtime_transition import TransitionError

        raise TransitionError(_INVALID)
    return tuple(purged)


def authorize_plan(kind: str, expires_at: str, deadline: float) -> Mapping[str, object]:
    """The forward ``deadline`` and grant retirement the runtime allows an authorization.

    The clocks go as facts; ``kind`` is ``repair`` or ``inverse``.
    """

    request: dict[str, object] = {
        "op": "publication_authorize",
        "kind": kind,
        "expires_at": expires_at,
        "deadline": deadline,
        "now": time.monotonic(),
        "wall": time.time(),
    }
    value = _ask(request, context=False).get("value")
    if not isinstance(value, Mapping):
        from .runtime_transition import TransitionError

        raise TransitionError(_INVALID)
    return value


def merge_dependency(previous: dict[str, object], change: dict[str, object]) -> Mapping[str, object]:
    """``merge_transition_dependency``: one pin of a shared artifact, or ``same``."""

    value = _ask({"op": "publication_merge_dependency", "previous": previous, "change": change}).get("value")
    if not isinstance(value, Mapping):
        from .runtime_transition import TransitionError

        raise TransitionError(_INVALID)
    return value


def compare_files(files: list[object], generation: str, *, inverse: bool = False) -> None:
    """``RuntimeTransition._compare``: every file still holds ``generation``."""

    request: dict[str, object] = {"op": "compare", "files": files, "generation": generation, "inverse": inverse}
    _ask(request)


def write_file(change: dict[str, object], generation: str) -> None:
    """``RuntimeTransition._write_file``: publish one generation of one file."""

    _ask({"op": "write", "change": change, "generation": generation})


def publish_files(
    files: Sequence[TransitionFile],
    *,
    removals: bool,
    rollback: bool,
    on_write: Callable[[TransitionFile], None] | None,
) -> None:
    """``PreparedHarnessInstall.publish``: the whole plan, restored on failure."""

    payloads = [change.payload() for change in files]
    request: dict[str, object] = {"op": "publish", "files": payloads, "removals": removals, "rollback": rollback}
    _ask(request, files=files, on_write=on_write)


__all__ = [
    "artifact_generation",
    "authorize_plan",
    "compare_files",
    "publish_files",
    "register_inverse",
    "request_policy",
    "require_deadline",
    "runtime_compare",
    "write_file",
]
