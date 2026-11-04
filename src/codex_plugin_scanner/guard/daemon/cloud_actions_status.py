"""What the local dashboard may show about Cloud actions on this computer.

Cloud actions use the `hol-guard connect` pairing; there is no separate
sign-in. `GET /v1/cloud-actions/status` reads the pairing, what the last
connect said about Cloud actions, and the last saved check. It never calls
Guard Cloud, so it answers offline and fast. `POST /v1/cloud-actions/status`
asks Guard Cloud whether it offers Cloud actions (the public description, the
same check as `hol-guard cloud-actions status`), at most once a minute, and
saves the answer.

The projection is deliberately narrow: the workspace, the Guard Cloud site
(host only), whether Cloud actions are on for this computer, and a state code.
It never carries an access value, a file path or a server reply body. The
check result says when it was made and whether it is stale, so the page can
label old answers instead of presenting them as current. Included actions and
connected accounts are not reported by Guard Cloud yet; the projection says so
rather than inventing numbers.

These routes accept only the daemon's own token or a dashboard session, like
every other `/v1` route.

The native runtime reads and writes the saved check and composes the
projection. Python keeps the pairing read, the one-check-at-a-time lock, the
live check of Guard Cloud and the Guard Cloud page address, which follows this
daemon's environment.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from ..store import GuardStore

CLOUD_ACTIONS_STATUS_SCHEMA = "guard.cloud-actions.local-status.v2"
STALE_AFTER = timedelta(minutes=5)
CHECK_INTERVAL = timedelta(minutes=1)

_CHECK_LOCK = threading.Lock()


@dataclass(frozen=True)
class CheckResult:
    """The saved service check: a stable state code and a message safe to show."""

    state: str
    message: str
    http_status: int | None = None


@dataclass(frozen=True)
class _Pairing:
    origin: str
    workspace_id: str | None
    cloud_actions: str


# Argument: the Guard Cloud origin to ask.
Checker = Callable[[str], CheckResult]


class CloudActionsCheckBusyError(RuntimeError):
    """Another check is running."""


class CloudActionsCheckedRecentlyError(RuntimeError):
    """The last check is less than a minute old."""

    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__("checked_recently")
        self.retry_after_seconds = retry_after_seconds


class CloudActionsNotPairedError(RuntimeError):
    """There is no pairing to check."""


class CloudActionsStatusUnavailableError(RuntimeError):
    """The native runtime could not read or save the check."""


def _cloud_base_url(origin: str) -> str | None:
    """Where Guard Cloud's pages live for this pairing, or None for a site Guard does not recognise."""

    from ..cli.oauth_client import guard_api_base_path, is_guard_oauth_origin_allowed

    if not is_guard_oauth_origin_allowed(origin):
        return None
    try:
        return f"{origin}{guard_api_base_path(origin)}"
    except ValueError:
        return None


def _pairing(store: GuardStore) -> _Pairing | None:
    from ..cli.cloud_actions_access import CloudActionsAccessError, read_cloud_actions_pairing
    from ..cli.connect_cloud_actions import read_cloud_actions_connect_report

    try:
        pairing = read_cloud_actions_pairing(store)
    except CloudActionsAccessError:
        return None
    grant_id = store.get_oauth_local_credential_health().get("grant_id")
    report = read_cloud_actions_connect_report(store, grant_id=grant_id if isinstance(grant_id, str) else None)
    return _Pairing(
        origin=pairing.origin,
        workspace_id=pairing.workspace_id or (report["workspace_id"] if report is not None else None),
        cloud_actions=report["status"] if report is not None else "unknown",
    )


def _native(store: GuardStore, args: dict[str, object]) -> dict[str, Any]:
    """The native runtime reads and writes the saved check under the Guard home."""

    from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    try:
        return native_runner_authority("cloud_actions_status", args, guard_home=store.guard_home)
    except NativeRunnerAuthorityError as error:
        raise CloudActionsStatusUnavailableError("status_unavailable") from error


def _utc(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat()


def _projection(store: GuardStore, pairing: _Pairing | None, moment: datetime) -> dict[str, Any]:
    paired = (
        None
        if pairing is None
        else {
            "origin": pairing.origin,
            "workspace_id": pairing.workspace_id,
            "cloud_actions": pairing.cloud_actions,
            "cloud_base_url": _cloud_base_url(pairing.origin),
        }
    )
    return _native(store, {"op": "project", "pairing": paired, "now": _utc(moment)})


def cloud_actions_local_status(store: GuardStore, *, now: datetime | None = None) -> dict[str, object]:
    """This computer's Cloud actions and the last saved check, without calling Guard Cloud."""

    from ..cli.cloud_actions_alpha_cleanup import remove_alpha_sign_ins

    moment = now or datetime.now(timezone.utc)
    remove_alpha_sign_ins(store.guard_home)
    return _projection(store, _pairing(store), moment)["status"]


def _live_checker(origin: str) -> CheckResult:
    from ..cli.cloud_actions_access import CloudActionsPairing
    from ..cli.cloud_actions_health import check_service

    service = check_service(CloudActionsPairing(origin=origin, workspace_id=None))
    return CheckResult(service.state, service.message, service.http_status)


def check_cloud_actions(
    store: GuardStore, *, now: datetime | None = None, checker: Checker | None = None
) -> dict[str, object]:
    """Ask Guard Cloud whether it offers Cloud actions, save the answer, and return the projection.

    Raises CloudActionsNotPairedError without a pairing, CloudActionsCheckedRecentlyError
    within a minute of the last check, CloudActionsCheckBusyError while another check runs,
    OSError when the answer cannot be saved, and CloudActionsStatusUnavailableError when the
    native runtime cannot read the saved check.
    """

    if not _CHECK_LOCK.acquire(blocking=False):
        raise CloudActionsCheckBusyError("check_running")
    try:
        moment = now or datetime.now(timezone.utc)
        pairing = _pairing(store)
        if pairing is None:
            raise CloudActionsNotPairedError("not_paired")
        retry_after = _projection(store, pairing, moment).get("retry_after_seconds")
        if isinstance(retry_after, int):
            raise CloudActionsCheckedRecentlyError(retry_after)
        service = (checker or _live_checker)(pairing.origin)
        entry = {"state": service.state, "message": service.message, "http_status": service.http_status}
        try:
            _native(store, {"op": "record", "origin": pairing.origin, "checked_at": _utc(moment), "service": entry})
        except CloudActionsStatusUnavailableError as error:
            raise OSError("check_not_saved") from error
        return cloud_actions_local_status(store, now=moment)
    finally:
        _CHECK_LOCK.release()
