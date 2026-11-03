"""Cloud actions choice made during ``hol-guard connect``.

There is no separate Cloud actions sign-in. While a person approves
``hol-guard connect`` in the browser they may also choose "Let AI tools on
this computer use Cloud actions". Guard Cloud records that choice on the
pairing and reports it back in the connect token response as
``guard_cloud_actions``. This module reads that report, keeps the last known
answer next to the pairing, and turns it into connect and status output.

The stored answer is a display hint only. Guard Cloud checks the pairing
itself whenever an AI tool asks for Cloud actions access.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from typing import Literal, TypedDict

from ..store import GuardStore

CloudActionsConnectStatus = Literal["on", "off", "unknown"]

CLOUD_ACTIONS_CONNECT_STATE_PREFIX = "cloud_actions_connect:"
CLOUD_ACTIONS_CONFIGURE_COMMAND = "hol-guard cloud-actions ai-tools configure <ai-tool>"
CLOUD_ACTIONS_RECONNECT_COMMAND = "hol-guard connect"


class CloudActionsConnectReport(TypedDict):
    status: Literal["on", "off"]
    workspace_id: str | None


class CloudActionsConnectSummary(TypedDict):
    status: CloudActionsConnectStatus
    workspace_id: str | None
    message: str


def parse_cloud_actions_connect_report(payload: Mapping[str, object]) -> CloudActionsConnectReport | None:
    """Read ``guard_cloud_actions`` from a connect token response.

    Guard Cloud leaves the field out when Cloud actions are not available, for
    other apps, or when it could not look the pairing up. Anything malformed is
    treated the same way, so the CLI never claims an answer it did not get.
    """
    value = payload.get("guard_cloud_actions")
    if not isinstance(value, Mapping):
        return None
    status = value.get("status")
    if status not in ("on", "off"):
        return None
    workspace_id = value.get("workspace_id")
    return {
        "status": status,
        "workspace_id": workspace_id.strip() if isinstance(workspace_id, str) and workspace_id.strip() else None,
    }


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
    if not paired:
        return {
            "status": "off",
            "workspace_id": None,
            "message": f"This computer is not paired. Run {CLOUD_ACTIONS_RECONNECT_COMMAND} first.",
        }
    if report is None:
        return {
            "status": "unknown",
            "workspace_id": None,
            "message": "Guard Cloud did not report Cloud actions for this pairing.",
        }
    if report["status"] == "on":
        return {
            "status": "on",
            "workspace_id": report["workspace_id"],
            "message": f"Ready. Set up an AI tool with {CLOUD_ACTIONS_CONFIGURE_COMMAND}.",
        }
    return {
        "status": "off",
        "workspace_id": report["workspace_id"],
        "message": (
            f"Off. To turn them on, run {CLOUD_ACTIONS_RECONNECT_COMMAND} again and choose "
            '"Let AI tools on this computer use Cloud actions".'
        ),
    }


def normalize_cloud_workspace_id(value: object) -> str | None:
    """Validate ``--cloud-workspace``. It names a Guard Cloud workspace, never a folder."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return str(uuid.UUID(text))
    except ValueError as error:
        raise ValueError(
            "--cloud-workspace takes a Guard Cloud workspace ID (a UUID), not a folder path. "
            "Copy it from Guard Cloud > Settings > Workspace."
        ) from error


def check_connect_cloud_actions_choices(
    *,
    workspace_id: str | None,
    report: CloudActionsConnectReport | None,
    cloud_workspace_id: str | None,
    cloud_actions_declined: bool,
) -> str | None:
    """Return a problem message when the finished connect does not match the flags.

    The pairing is kept either way; the caller reports the problem and exits
    non-zero so scripts notice.
    """
    if cloud_workspace_id is not None and (workspace_id or "").lower() != cloud_workspace_id.lower():
        return (
            f"This computer was paired to workspace {workspace_id or 'unknown'}, not {cloud_workspace_id}. "
            f"Run {CLOUD_ACTIONS_RECONNECT_COMMAND} --cloud-workspace {cloud_workspace_id} again and pick "
            "that workspace in the browser."
        )
    if cloud_actions_declined and report is not None and report["status"] == "on":
        return (
            "Cloud actions were turned on in the browser although --no-cloud-actions was set. "
            f"Run {CLOUD_ACTIONS_RECONNECT_COMMAND} --no-cloud-actions again and leave that option off."
        )
    return None
