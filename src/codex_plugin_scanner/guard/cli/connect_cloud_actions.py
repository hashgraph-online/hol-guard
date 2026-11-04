"""Cloud actions choice made during ``hol-guard connect``.

There is no separate Cloud actions sign-in. While a person approves
``hol-guard connect`` in the browser they may also choose "Let AI tools on
this computer use Cloud actions". Guard Cloud records that choice on the
pairing and reports it back in the connect token response as
``guard_cloud_actions``. This module reads that report, keeps the last known
answer next to the pairing, and turns it into connect and status output.

The stored answer is a display hint only. Guard Cloud checks the pairing
itself whenever an AI tool asks for Cloud actions access. What the answer
means is decided by the native runtime's ``cloud_actions_connect`` kind.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Literal, TypedDict, cast

from ..store import GuardStore

CloudActionsConnectStatus = Literal["on", "off", "unknown"]

CLOUD_ACTIONS_CONNECT_STATE_PREFIX = "cloud_actions_connect:"
CLOUD_ACTIONS_CONFIGURE_COMMAND = "hol-guard cloud-actions ai-tools configure <ai-tool>"
CLOUD_ACTIONS_RECONNECT_COMMAND = "hol-guard connect"
_FEATURE = "native-cloud-actions-connect-v1"
_COMMAND = "cloud-actions-connect"
_NATIVE_UNAVAILABLE_MESSAGE = (
    "Guard's native runtime is not available, so HOL Guard could not check Cloud actions for this pairing. "
    "Run hol-guard doctor, then try again."
)
_DISCONNECTED_MESSAGE = f"{_NATIVE_UNAVAILABLE_MESSAGE} HOL Guard disconnected this computer before sending anything."


class CloudActionsConnectReport(TypedDict):
    status: Literal["on", "off"]
    workspace_id: str | None


class CloudActionsConnectSummary(TypedDict):
    status: CloudActionsConnectStatus
    workspace_id: str | None
    message: str


def parse_cloud_actions_connect_report(payload: Mapping[str, object]) -> CloudActionsConnectReport | None:
    """Read ``guard_cloud_actions`` from a connect token response, or ``None``."""
    value = payload.get("guard_cloud_actions")
    if not isinstance(value, Mapping):
        return None
    answer = _native(
        {"op": "report", "value": {"status": value.get("status"), "workspace_id": value.get("workspace_id")}}
    )
    return cast("CloudActionsConnectReport | None", answer.get("report") if answer is not None else None)


def _state_key(grant_id: str) -> str:
    return f"{CLOUD_ACTIONS_CONNECT_STATE_PREFIX}{grant_id}"


def record_cloud_actions_connect_report(
    store: GuardStore,
    *,
    grant_id: str | None,
    report: CloudActionsConnectReport | None,
    now: str,
) -> None:
    """Remember the answer for this pairing, or forget a stale one."""
    if not grant_id:
        return
    if report is None:
        store.delete_sync_payload(_state_key(grant_id))
        return
    store.set_sync_payload(
        _state_key(grant_id),
        {"status": report["status"], "workspace_id": report["workspace_id"], "checked_at": now},
        now,
    )


def read_cloud_actions_connect_report(store: GuardStore, *, grant_id: str | None) -> CloudActionsConnectReport | None:
    if not grant_id:
        return None
    stored = store.get_sync_payload(_state_key(grant_id))
    if not isinstance(stored, dict):
        return None
    return parse_cloud_actions_connect_report({"guard_cloud_actions": stored})


def cloud_actions_connect_summary(
    report: CloudActionsConnectReport | None,
    *,
    paired: bool,
) -> CloudActionsConnectSummary:
    answer = _native({"op": "summary", "report": report, "paired": paired})
    if answer is None or not isinstance(answer.get("message"), str):
        return {"status": "unknown", "workspace_id": None, "message": _NATIVE_UNAVAILABLE_MESSAGE}
    return cast("CloudActionsConnectSummary", answer)


def record_connect_cloud_actions(
    store: GuardStore,
    *,
    grant_id: str | None,
    report: CloudActionsConnectReport | None,
    now: str,
) -> dict[str, object]:
    """Store the answer from a finished connect and return its summary."""
    record_cloud_actions_connect_report(store, grant_id=grant_id, report=report, now=now)
    return dict(cloud_actions_connect_summary(report, paired=True))


def connect_status_cloud_actions(
    store: GuardStore,
    *,
    oauth_storage_health: Mapping[str, object],
) -> dict[str, object]:
    """Summary for ``hol-guard connect status``; only a healthy pairing counts."""
    grant_id = oauth_storage_health.get("grant_id")
    paired_grant_id = (
        grant_id if oauth_storage_health.get("state") == "healthy" and isinstance(grant_id, str) and grant_id else None
    )
    report = read_cloud_actions_connect_report(store, grant_id=paired_grant_id)
    return dict(cloud_actions_connect_summary(report, paired=paired_grant_id is not None))


def check_connect_cloud_workspace(*, workspace_id: str | None, cloud_workspace_id: str | None) -> str | None:
    """Return a problem message when the browser picked a different workspace.

    The caller checks this before the first sync and undoes the pairing, so
    nothing from this computer reaches the wrong workspace.
    """
    if cloud_workspace_id is None:
        return None
    return _problem({"op": "workspace", "workspace_id": workspace_id, "cloud_workspace_id": cloud_workspace_id})


def check_connect_cloud_actions_declined(*, summary: object, cloud_actions_declined: bool) -> str | None:
    """Return a problem message when Cloud actions came back on despite ``--no-cloud-actions``.

    ``summary`` is the connect payload's ``cloud_actions`` summary. The caller
    undoes the pairing before the first sync, reports the problem and exits
    non-zero so scripts notice. Without an answer Guard Cloud did not turn Cloud
    actions on for this pairing, which is what the option asked for. An answer
    Guard could not read disconnects the computer too.
    """
    if not cloud_actions_declined or not isinstance(summary, Mapping):
        return None
    if summary.get("message") == _NATIVE_UNAVAILABLE_MESSAGE:
        return _DISCONNECTED_MESSAGE
    answer = _native(
        {"op": "report", "value": {"status": summary.get("status"), "workspace_id": summary.get("workspace_id")}}
    )
    if answer is None:
        return _DISCONNECTED_MESSAGE
    return _problem({"op": "declined", "report": answer.get("report"), "declined": True})


def _problem(request: dict[str, object]) -> str | None:
    """A check that cannot run disconnects the computer, like a failed one."""
    answer = _native(request)
    problem = answer.get("problem", 0) if answer is not None else 0
    if problem is None or isinstance(problem, str):
        return problem
    return _DISCONNECTED_MESSAGE


def _native(request: dict[str, object]) -> Any:  # the one-shot command's answer, or None
    # One-shot so that `cloud-actions status --offline` never starts a resident.
    from ..mdm.runtime_request import runtime_answer

    return runtime_answer(_FEATURE, _COMMAND, request, output_limit=4096, timeout_seconds=5.0)
