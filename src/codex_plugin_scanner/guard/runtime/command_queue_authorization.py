"""Authorize and settle a leased command job, overlapping the acknowledgement when safe.

An exact Cloud Review job is applied by ``apply_exact_cloud_review``, which
verifies the capability, the receipt's expiry, replay and the request's
pending state again against the clock at the moment it applies. Its
authorization and settlement can therefore run while the acknowledgement is
in flight without letting a job that expired during a slow acknowledgement
through. The acknowledgement still reaches Cloud before the result: Cloud
accepts a result for a delivery that was never acknowledged, re-leases a
stale lease whether or not it was acknowledged, and refuses the result of a
lease it would also have refused to acknowledge.

Every other job, including a native workspace Review job, is authorized only
after the acknowledgement returns, so its verdict is never older than the
acknowledgement round trip.
"""

from __future__ import annotations

import contextvars
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from ..store import GuardStore
from .command_capability import AuthorizedCommandJob
from .exact_cloud_review import EXACT_CLOUD_REVIEW_OPERATION
from .native_workspace_review_queue import is_native_workspace_review_job

Authorize = Callable[[GuardStore, dict[str, object]], AuthorizedCommandJob]


def rechecks_authority_on_apply(job: dict[str, object]) -> bool:
    """Whether executing ``job`` verifies its authority again at that moment."""

    return job.get("operation") == EXACT_CLOUD_REVIEW_OPERATION and not is_native_workspace_review_job(job)


def start_command_authorization(
    store: GuardStore,
    job: dict[str, object],
    *,
    authorize: Authorize,
) -> Callable[[], AuthorizedCommandJob]:
    """Return a call that yields ``job``'s authorization once it is needed.

    For a job that is checked again when it applies, authorization starts now on
    a worker thread in the caller's context; otherwise it runs when the call is
    made, after the acknowledgement.
    """

    if not rechecks_authority_on_apply(job):
        return lambda: authorize(store, job)
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="guard-command-authorize")
    try:
        future = executor.submit(contextvars.copy_context().run, authorize, store, job)
    finally:
        executor.shutdown(wait=False)
    return future.result


def start_overlapped_acknowledgement(
    job: dict[str, object],
    acknowledge: Callable[[], None],
) -> Callable[[], BaseException | None] | None:
    """Send ``job``'s acknowledgement on a worker thread when it may overlap settlement.

    Returns ``None`` when the acknowledgement has to finish before the job
    runs. Otherwise the returned call waits for the acknowledgement and hands
    back its failure, if any, without raising: the job has already settled by
    then, and its result is what tells Cloud how the lease ended.
    """

    if not rechecks_authority_on_apply(job):
        return None
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="guard-command-ack")
    try:
        future = executor.submit(contextvars.copy_context().run, acknowledge)
    finally:
        executor.shutdown(wait=False)
    return future.exception


__all__ = ["rechecks_authority_on_apply", "start_command_authorization", "start_overlapped_acknowledgement"]
