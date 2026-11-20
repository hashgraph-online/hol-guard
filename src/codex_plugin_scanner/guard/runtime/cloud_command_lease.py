"""Lease the next Guard Cloud command job with the native ``cloud-event-sync`` command.

The native runtime builds each lease body, sends it signed, checks the Cloud
Review protocol and picks the extra exact jobs a batch returned. Python keeps
the command queue state the answer reports.
"""

from __future__ import annotations

from collections.abc import Mapping

from .cloud_bundle_sync import CLOUD_EVENT_SYNC_COMMAND, run_native_cloud_sync

CLOUD_COMMAND_LEASE_FEATURE = "cloud-command-lease-v1"


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


__all__ = ["CLOUD_COMMAND_LEASE_FEATURE", "cloud_command_lease"]
