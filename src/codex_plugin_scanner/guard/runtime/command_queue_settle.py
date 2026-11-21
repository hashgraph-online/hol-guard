"""Settle one authorized Guard command job into the result its lease posts."""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass

from ..harness_context import HarnessContext
from ..store import GuardStore
from .command_capability import AuthorizedCommandJob, CommandCapabilityError, CommandCapabilityUnavailableError
from .command_queue_http import format_redacted_error

_LOGGER = logging.getLogger("codex_plugin_scanner.guard.runtime.command_queue")


@dataclass(frozen=True)
class SettleCalls:
    """Collaborators the queue module resolves at call time, so test doubles still apply."""

    identity_digest: Callable[..., object]
    consume: Callable[..., bool]
    register: Callable[..., dict[str, object]]
    audit: Callable[..., object]
    native_review: Callable[[dict[str, object]], bool]
    execute: Callable[[dict[str, object], HarnessContext, GuardStore], dict[str, object]]


def settle_authorized_job(
    store: GuardStore,
    context: HarnessContext,
    item: dict[str, object],
    authorized: AuthorizedCommandJob,
    calls: SettleCalls,
) -> dict[str, object]:
    execution: dict[str, object]
    # The job is leased by this point and the lease only closes on a posted
    # result. Matching the approval grant, recording the replay row and
    # registering a pending approval all ask the runtime for a signature or
    # a digest, so each of them can refuse. A refusal is this job's failure
    # and has to reach the posted result; letting it escape the poll would
    # leave the lease open with nothing posted and nothing recorded.
    try:
        # Spending the grant and recording the replay row both name this
        # job by the runtime's digest. Ask for it once, before the grant
        # is deleted: a resident that stopped answering in between would
        # otherwise fail the job with the user's approval already gone.
        needs_replay_row = not calls.native_review(item)
        identity_digest = (
            calls.identity_digest(store, authorized) if authorized.requires_local_approval or needs_replay_row else None
        )
        if not calls.consume(
            store,
            authorized,
            identity_digest=identity_digest,
            record_replay=needs_replay_row,
        ):
            pending = calls.register(store, authorized, item)
            execution = {
                "waitingLocalConfirm": True,
                "operation": authorized.operation,
                "jobId": authorized.identity["id"],
                "approveCommand": pending["approveCommand"],
            }
            calls.audit(store, "cloud_command.waiting_local_approval", job=item, reason="local_approval_required")
        else:
            calls.audit(store, "cloud_command.accepted", job=item, reason="capability_and_job_valid")
            try:
                _LOGGER.info("Guard command leased.")
                execution = calls.execute(item, context, store)
            except Exception as error:
                _LOGGER.warning("Guard command execution failed: error=%s", format_redacted_error(error))
                execution = {
                    "failureCode": "execution_error",
                    "failureMessage": format_redacted_error(error),
                }
    except (CommandCapabilityError, CommandCapabilityUnavailableError) as error:
        reason = error.code if isinstance(error, CommandCapabilityError) else error.reason
        calls.audit(store, "cloud_command.rejected", job=item, reason=reason)
        execution = {
            "failureCode": reason,
            "failureMessage": "The local Guard command capability could not settle this job.",
        }
    return execution


__all__ = ["SettleCalls", "settle_authorized_job"]
