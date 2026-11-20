"""Lease and report Guard Cloud command jobs with the native ``cloud-event-sync`` command.

The native runtime builds each lease body, sends it signed, checks the Cloud
Review protocol and picks the extra exact jobs a batch returned. It also picks
the route, path and ack body of each job's ack and result. Python keeps the
command queue state the answers report.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Literal

from .cloud_bundle_sync import CLOUD_EVENT_SYNC_COMMAND, cloud_json_answer, request_body_fields, run_native_cloud_sync

CLOUD_COMMAND_LEASE_FEATURE = "cloud-command-lease-v1"
CLOUD_COMMAND_REPORT_FEATURE = "cloud-command-report-v1"


def cloud_command_lease(auth_context: Mapping[str, object], call: Mapping[str, object]) -> dict[str, object]:
    """Lease one command job and return the native ``{"lease", "failure"}`` answer.

    ``call`` carries ``operations``, ``waitMs``, ``maxJobs``, ``collectExtras``,
    ``workspaceId``, ``deviceId``, ``daemonVersion`` and ``schemaVersions``.
    """

    from ..config import resolve_guard_home

    answer = run_native_cloud_sync(
        CLOUD_EVENT_SYNC_COMMAND,
        CLOUD_COMMAND_LEASE_FEATURE,
        resolve_guard_home(),
        "command_lease",
        auth_context=auth_context,
        subject="Guard command lease",
        extra={"commandLease": dict(call)},
    )
    if not isinstance(answer, dict) or not isinstance(answer.get("lease"), dict):
        raise RuntimeError("The Guard native runtime did not answer the Guard command lease.")
    return answer


def cloud_command_report(
    auth_context: Mapping[str, object],
    *,
    job_id: str,
    exact: bool,
    kind: Literal["ack", "result"],
    lease_id: str | None = None,
    body: bytes | None = None,
) -> dict[str, object]:
    """Send a leased job's ack (``lease_id``) or result (``body``) and return Guard Cloud's answer.

    A refusal or transport failure is raised as the ``HTTPError`` or
    ``URLError`` the command queue already handles, against the URL the
    native runtime sent the report to.
    """

    from ..config import resolve_guard_home

    call: dict[str, object] = {"jobId": job_id, "exact": exact, "kind": kind}
    if lease_id is not None:
        call["leaseId"] = lease_id
    with request_body_fields(body) as fields:
        answer = run_native_cloud_sync(
            CLOUD_EVENT_SYNC_COMMAND,
            CLOUD_COMMAND_REPORT_FEATURE,
            resolve_guard_home(),
            "command_report",
            auth_context=auth_context,
            subject="Guard command report",
            extra={"commandReport": {**call, **fields}},
        )
    if not isinstance(answer, dict):
        raise RuntimeError("The Guard native runtime did not answer the Guard command report.")
    url = answer.get("url")
    if not isinstance(url, str) or not url:
        raise RuntimeError("The Guard native runtime did not answer the Guard command report.")
    return cloud_json_answer(url, answer.get("reply"))


__all__ = ["CLOUD_COMMAND_LEASE_FEATURE", "CLOUD_COMMAND_REPORT_FEATURE", "cloud_command_lease", "cloud_command_report"]
