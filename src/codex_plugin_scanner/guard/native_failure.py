"""The exception a native owned-operation answer names when it failed."""

from __future__ import annotations

from collections.abc import Mapping

INVALID_ANSWER = "native_transition_invalid"


def failure_from_answer(answer: Mapping[str, object]) -> BaseException:
    from .codex_hook_file_integrity import CodexHookIntegrityError
    from .native_transition_files import _exception
    from .runtime_transition import TransitionError

    failure = answer.get("failure")
    if not isinstance(failure, Mapping):
        return TransitionError(INVALID_ANSWER)
    kind, message = failure.get("kind"), failure.get("message")
    if kind == "timeout" and isinstance(message, str):
        return TimeoutError(message)
    if kind == "runtime" and isinstance(message, str):
        return RuntimeError(message)
    code = failure.get("code")
    if kind == "integrity" and isinstance(code, str) and isinstance(message, str):
        error = CodexHookIntegrityError(code, message)
        cause = failure.get("cause")
        if isinstance(cause, str):
            error.__cause__ = CodexHookIntegrityError(cause, cause)
        return error
    reason = failure.get("reason")
    if kind == "transition" and isinstance(reason, str):
        return TransitionError(reason)
    if kind == "fault":
        return _exception(failure.get("fault"))
    return TransitionError(INVALID_ANSWER)
