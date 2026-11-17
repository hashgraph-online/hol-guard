"""The native ``hook_failure`` answer a hook gets when review cannot finish."""

from __future__ import annotations

RUNTIME_MISSING = "HOL Guard's native runtime is missing, so Guard blocked this hook. Run `hol-guard repair`."


def native_hook_failure(harness: str, event_name: str, reason: str) -> tuple[str, int] | None:
    """The document and exit status the runtime gives a hook it could not review.

    ``None`` means the runtime did not answer; the caller then blocks with
    ``RUNTIME_MISSING``.
    """

    from ..native_runner_authority import native_runner_authority

    try:
        answer = native_runner_authority(
            "hook_failure", {"harness": harness, "event_name": event_name, "reason": reason}
        )
    except Exception:
        return None
    document, exit_code = answer.get("document"), answer.get("exit_code")
    if isinstance(document, str) and isinstance(exit_code, int) and not isinstance(exit_code, bool):
        return document, exit_code
    return None
