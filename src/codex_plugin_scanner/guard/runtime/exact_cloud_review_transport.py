"""Wire helpers for the isolated Cloud Review exact-command transport."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import NoReturn, TypedDict, cast
from urllib.error import HTTPError

from .cloud_bundle_sync import cloud_failure, sync_failure
from .exact_cloud_review import EXACT_CLOUD_REVIEW_OPERATION

EXACT_CLOUD_REVIEW_COMMAND_API_BASE = "/api/guard/review/v2/commands"
EXACT_CLOUD_REVIEW_TRANSPORT = "cloud_review"
_TRANSPORT_MARKER = "_guardCommandTransport"


class LeaseCall(TypedDict):
    operations: list[str]
    waitMs: int
    maxJobs: int
    collectExtras: bool


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
    lease: Callable[[LeaseCall], Mapping[str, object]],
    lease_url: Callable[[str], str] = lambda route: f"{route}/lease",
    exact_route_failure: Callable[[HTTPError], None] | None = None,
    exact_route_success: Callable[[], None] | None = None,
    observe_response: Callable[[dict[str, object]], object] | None = None,
    max_jobs: int = 1,
    on_extra_jobs: Callable[[list[dict[str, object]]], object] | None = None,
    observe_lease_batch_limit: Callable[[int], object] | None = None,
) -> dict[str, object] | None:
    """Lease the next job, exact Review jobs first, through the native ``lease``.

    The native runtime sends the leases and reports what to record beside the
    leased job: the exact route's health, the batch limit Guard Cloud
    advertised and each response. With ``max_jobs`` above one, Guard Cloud may
    lease further exact Review jobs in the same response; the first job is
    returned and the others, already leased to this device, go to
    ``on_extra_jobs``. A failure is raised after the state is recorded.
    """

    if not operations:
        return None
    answer = lease(
        {
            "operations": list(operations),
            "waitMs": wait_ms,
            "maxJobs": max_jobs if on_extra_jobs is not None else 1,
            "collectExtras": on_extra_jobs is not None,
        }
    )
    leased = _mapping(answer.get("lease"))
    route = leased.get("exactRoute")
    if route == "failed" and exact_route_failure is not None:
        refused = cloud_failure(lease_url(EXACT_CLOUD_REVIEW_COMMAND_API_BASE), {"refusal": leased.get("exactRefusal")})
        if isinstance(refused, HTTPError):
            exact_route_failure(refused)
    elif route == "ok" and exact_route_success is not None:
        exact_route_success()
    limit = leased.get("batchLimit")
    if observe_lease_batch_limit is not None and isinstance(limit, int) and not isinstance(limit, bool):
        observe_lease_batch_limit(limit)
    responses = leased.get("responses")
    if observe_response is not None and isinstance(responses, list):
        for response in responses:
            observe_response(_mapping(response))
    raw_extras = leased.get("extras")
    extras = [job for job in map(_mapping, raw_extras if isinstance(raw_extras, list) else []) if job]
    if on_extra_jobs is not None and extras:
        on_extra_jobs([exact_transport_job(job) for job in extras])
    failure = answer.get("failure")
    if isinstance(failure, Mapping):
        _raise_lease_failure(cast(Mapping[str, object], failure), lease_url)
    item = _mapping(leased.get("item"))
    if not item:
        return None
    return exact_transport_job(item) if leased.get("exact") is True else item


def _raise_lease_failure(failure: Mapping[str, object], lease_url: Callable[[str], str]) -> NoReturn:
    if failure.get("protocol") == "cloud_review_protocol_upgrade_required":
        raise ValueError("cloud_review_protocol_upgrade_required")
    sync = failure.get("sync")
    if isinstance(sync, Mapping):
        raise sync_failure(cast(Mapping[str, object], sync), "Guard command lease")
    route = failure.get("route")
    raise cloud_failure(lease_url(route if isinstance(route, str) else "/api/guard/commands"), failure)


def _mapping(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        return {}
    raw = cast(Mapping[object, object], value)
    if any(not isinstance(key, str) for key in raw):
        return {}
    return {cast(str, key): nested for key, nested in raw.items()}


__all__ = [
    "EXACT_CLOUD_REVIEW_COMMAND_API_BASE",
    "exact_operation_only",
    "exact_transport_job",
    "generic_operations",
    "lease_next_job",
    "uses_exact_transport",
]
