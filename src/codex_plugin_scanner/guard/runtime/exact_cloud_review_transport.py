"""Wire helpers for the isolated Cloud Review exact-command transport."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import TypedDict, cast
from urllib.error import HTTPError

from .exact_cloud_review import EXACT_CLOUD_REVIEW_OPERATION, EXACT_CLOUD_REVIEW_PROTOCOL_VERSION

EXACT_CLOUD_REVIEW_COMMAND_API_BASE = "/api/guard/review/v2/commands"
EXACT_CLOUD_REVIEW_TRANSPORT = "cloud_review"
_TRANSPORT_MARKER = "_guardCommandTransport"


class LeaseOptions(TypedDict):
    operations: tuple[str, ...]
    wait_ms: int
    max_jobs: int


def advertised_lease_batch_limit(response: Mapping[str, object]) -> int | None:
    """The most exact Review jobs Guard Cloud says one lease may return, if it says."""

    value = response.get("maxJobs")
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return None
    return value


def exact_transport_job(job: dict[str, object]) -> dict[str, object]:
    """Attach a local-only route marker to a leased exact-review job."""

    return {**job, _TRANSPORT_MARKER: EXACT_CLOUD_REVIEW_TRANSPORT}


def uses_exact_transport(job: dict[str, object]) -> bool:
    return job.get(_TRANSPORT_MARKER) == EXACT_CLOUD_REVIEW_TRANSPORT


def exact_operation_only(operations: tuple[str, ...]) -> bool:
    return operations == (EXACT_CLOUD_REVIEW_OPERATION,)


def generic_operations(operations: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(operation for operation in operations if operation != EXACT_CLOUD_REVIEW_OPERATION)


def lease_next_job(
    *,
    operations: tuple[str, ...],
    wait_ms: int,
    exact_request: Callable[[LeaseOptions], dict[str, object]],
    queue_request: Callable[[LeaseOptions], dict[str, object]],
    exact_route_failure: Callable[[HTTPError], None] | None = None,
    exact_route_success: Callable[[], None] | None = None,
    observe_response: Callable[[dict[str, object]], object] | None = None,
    max_jobs: int = 1,
    on_extra_jobs: Callable[[list[dict[str, object]]], object] | None = None,
    observe_lease_batch_limit: Callable[[int], object] | None = None,
) -> dict[str, object] | None:
    """Lease the next job, exact Review jobs first.

    With ``max_jobs`` above one, Guard Cloud may lease further exact Review
    jobs in the same response. The first job is returned; the others, already
    leased to this device, go to ``on_extra_jobs``.
    """

    generic = generic_operations(operations)
    if EXACT_CLOUD_REVIEW_OPERATION in operations:
        requested_jobs = max_jobs if on_extra_jobs is not None else 1
        try:
            exact_response = exact_request(
                {
                    "operations": (EXACT_CLOUD_REVIEW_OPERATION,),
                    "wait_ms": wait_ms if exact_operation_only(operations) else 0,
                    "max_jobs": requested_jobs,
                }
            )
        except HTTPError as error:
            if requested_jobs > 1 and error.code == 400 and observe_lease_batch_limit is not None:
                # A Guard Cloud rolled back to one that leases a single job
                # rejects the batch; ask it for one job from the next poll.
                observe_lease_batch_limit(1)
            if error.code == 401 or not generic:
                raise
            if exact_route_failure is not None:
                exact_route_failure(error)
        else:
            if exact_response.get("protocolVersion") != EXACT_CLOUD_REVIEW_PROTOCOL_VERSION:
                raise ValueError("cloud_review_protocol_upgrade_required")
            if exact_route_success is not None:
                exact_route_success()
            if observe_lease_batch_limit is not None:
                observe_lease_batch_limit(advertised_lease_batch_limit(exact_response) or 1)
            if observe_response is not None:
                observe_response(exact_response)
            item = _mapping(exact_response.get("item"))
            if item:
                if item.get("protocolVersion") != EXACT_CLOUD_REVIEW_PROTOCOL_VERSION:
                    raise ValueError("cloud_review_protocol_upgrade_required")
                if on_extra_jobs is not None:
                    extras = _extra_exact_jobs(exact_response, first=item)
                    if extras:
                        on_extra_jobs(extras)
                return exact_transport_job(item)
    if not generic:
        return None
    queue_response = queue_request({"operations": generic, "wait_ms": wait_ms, "max_jobs": 1})
    if observe_response is not None:
        observe_response(queue_response)
    item = _mapping(queue_response.get("item"))
    return item or None


def _extra_exact_jobs(response: dict[str, object], *, first: dict[str, object]) -> list[dict[str, object]]:
    """The exact Review jobs leased beside ``first``, each with a distinct lease."""

    items = response.get("items")
    if not isinstance(items, list):
        return []
    seen = {first.get("leaseId")}
    extras: list[dict[str, object]] = []
    for value in items:
        job = _mapping(value)
        lease = job.get("leaseId")
        if not isinstance(lease, str) or not lease or lease in seen:
            continue
        if job.get("protocolVersion") != EXACT_CLOUD_REVIEW_PROTOCOL_VERSION:
            # Left leased: it goes stale and is leased again, the same as a job
            # whose worker stopped before its result.
            continue
        seen.add(lease)
        extras.append(exact_transport_job(job))
    return extras


def _mapping(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        return {}
    raw = cast(Mapping[object, object], value)
    if any(not isinstance(key, str) for key in raw):
        return {}
    return {cast(str, key): nested for key, nested in raw.items()}


__all__ = [
    "EXACT_CLOUD_REVIEW_COMMAND_API_BASE",
    "advertised_lease_batch_limit",
    "exact_operation_only",
    "exact_transport_job",
    "generic_operations",
    "lease_next_job",
    "uses_exact_transport",
]
