"""Choose the denial text for a Codex hook the local daemon could not review.

The bridge records one fixed reason code per failed daemon attempt. A daemon that
is restarting, slow, or briefly unreachable needs a retry, not a repair; any
answer that fails authentication or validation still points to the repair.

Stdlib only: the bridge imports this module before any heavy Guard code loads.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from .codex_daemon_dead_fastpath import NATIVE_RUNTIME_DEAD_REASON, NATIVE_RUNTIME_DEAD_REASON_CODE

AUTHENTICATION_FAILED_REASON = (
    "HOL Guard could not authenticate the local daemon. Run `hol-guard daemon repair` from a terminal, then retry."
)
DAEMON_UNAVAILABLE_REASON = (
    "HOL Guard's local daemon was not ready before the hook deadline and kept this action blocked. "
    "No approval was requested; retry the action. "
    "If this keeps happening, run `hol-guard daemon repair` from a terminal."
)
DAEMON_DEAD_REASON = (
    "HOL Guard's local daemon is not running and could not be restarted. "
    "Run `hol-guard repair` in a terminal, then retry."
)
OVERLOAD_REASON = (
    "HOL Guard is temporarily saturated and kept this action blocked. No approval was requested; retry the action."
)

# Codes from ``_daemon_failure_reason`` that mean the daemon never answered:
# it had not started, was stopped or restarting, timed out, or refused the
# connection. Any other code means it answered but could not be trusted, so
# the repair text stays.
UNANSWERED_DAEMON_CODES = frozenset(
    {
        "daemon_state_missing",
        "daemon_state_stopped",
        "daemon_transport_timeout",
        "daemon_connection_refused",
        "daemon_transport_unavailable",
        "daemon_generation_changed",
    }
)


def daemon_failure_reason(causes: Sequence[object], *, daemon_overloaded: bool) -> str:
    """Return the denial text that names the actual daemon failure."""

    records = [cause for cause in causes if isinstance(cause, Mapping)]
    if any(cause.get("stage") == "daemon_dead_fast" for cause in records):
        if any(cause.get("reason_code") == NATIVE_RUNTIME_DEAD_REASON_CODE for cause in records):
            return NATIVE_RUNTIME_DEAD_REASON
        return DAEMON_DEAD_REASON
    if daemon_overloaded:
        return OVERLOAD_REASON
    codes = [cause.get("reason_code") for cause in records]
    if codes and all(code in UNANSWERED_DAEMON_CODES for code in codes):
        return DAEMON_UNAVAILABLE_REASON
    return AUTHENTICATION_FAILED_REASON
