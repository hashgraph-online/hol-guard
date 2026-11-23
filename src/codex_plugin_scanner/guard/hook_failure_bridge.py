"""The native ``hook_failure`` answer a hook gets when review cannot finish."""

from __future__ import annotations

from typing import Any

RUNTIME_MISSING = "HOL Guard's native runtime is missing, so Guard blocked this hook. Run `hol-guard repair`."
# The events that decide whether something runs, taken from the fail-closed
# envelope contract (`guard/contracts/hook-fail-closed-envelopes.v1.json`): every
# spelling the contract files under `pre_tool`, `permission` or `prompt`. The
# runtime reads the same contract (`hook_failure_op::dispatch`), and
# `tests/test_native_hook_failure_detail.py` holds this table to it. A harness
# spelling its pre-tool event `PreToolCall` or its permission event
# `PermissionRequestV2` decides as much as the canonical spelling does, so an
# outage has to refuse it too.
_DECIDING_EVENTS = frozenset(
    {
        "pretool",
        "pretoolcall",
        "pretooluse",
        "copilotpermissionrequest",
        "permissionrequest",
        "permissionrequestv2",
        "userpromptsubmit",
        "userpromptsubmitted",
    }
)
_DECIDING_EVENT_PREFIXES = ("before",)


def outage_stderr_failure(event_name: str) -> tuple[str, str, int]:
    """The runtime's stderr table for the moment it cannot be asked.

    A deciding event is refused with exit 2. An event that only reports on
    finished work stays silent with exit 0: exit 2 on ``Stop`` would keep the
    agent from stopping.
    """

    # The runtime trims the event name before it classifies it, so a harness
    # that writes `" PreToolUse"` is refused there. Classifying the untrimmed
    # name here would let the same spelling pass this table silently, which is
    # the one divergence that decides differently.
    compact = event_name.strip().replace("_", "").replace("-", "").lower()
    if compact in _DECIDING_EVENTS or compact.startswith(_DECIDING_EVENT_PREFIXES):
        return "", RUNTIME_MISSING, 2
    return "", "", 0


def native_hook_failure(
    harness: str,
    event_name: str,
    reason: str,
    *,
    reason_code: str | None = None,
    deadline: float | None = None,
) -> tuple[str, int] | None:
    """The document and exit status the runtime gives a hook it could not review.

    ``None`` means the runtime did not answer; the caller then blocks with
    ``RUNTIME_MISSING``.
    """

    from .native_runner_authority import native_runner_authority

    try:
        args: dict[str, Any] = {"harness": harness, "event_name": event_name, "reason": reason}
        if reason_code is not None:
            args["reason_code"] = reason_code
        answer = native_runner_authority("hook_failure", args, deadline_monotonic=deadline)
    except Exception:
        return None
    document, exit_code = answer.get("document"), answer.get("exit_code")
    if isinstance(document, str) and isinstance(exit_code, int) and not isinstance(exit_code, bool):
        return document, exit_code
    return None


def native_stderr_hook_failure(
    harness: str, event_name: str, reason: str, *, deadline: float | None = None
) -> tuple[str, str, int]:
    """The stdout, stderr and exit status a harness that reads refusals from stderr gets.

    A runtime that does not answer blocks a deciding event with ``RUNTIME_MISSING``
    and leaves an observing event silent.
    """

    from .native_runner_authority import native_runner_authority

    try:
        answer = native_runner_authority(
            "hook_failure",
            {"harness": harness, "event_name": event_name, "reason": reason, "stderr": True},
            deadline_monotonic=deadline,
        )
    except Exception:
        return outage_stderr_failure(event_name)
    document, stderr, exit_code = answer.get("document"), answer.get("stderr"), answer.get("exit_code")
    if (
        isinstance(document, str)
        and isinstance(stderr, str)
        and isinstance(exit_code, int)
        and not isinstance(exit_code, bool)
    ):
        return document, stderr, exit_code
    return outage_stderr_failure(event_name)
