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
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from ..store import GuardStore
from .atomic_replace import replace_file

CLOUD_ACTIONS_STATUS_SCHEMA = "guard.cloud-actions.local-status.v2"
STALE_AFTER = timedelta(minutes=5)
CHECK_INTERVAL = timedelta(minutes=1)

_CACHE_SCHEMA = "guard.cloud-actions.service-check.v1"
_CACHE_FILE = "service-check.json"
_MAX_CACHE_BYTES = 16 * 1024
_MAX_MESSAGE_CHARS = 240
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


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_iso(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _site_host(origin: str) -> str | None:
    try:
        parts = urlsplit(origin)
        host = parts.hostname
        port = parts.port
    except ValueError:
        return None
    if not host:
        return None
    return f"{host}:{port}" if port is not None else host


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


def _cache_path(guard_home: Path) -> Path:
    return guard_home / "cloud-actions" / _CACHE_FILE


def _read_cache(guard_home: Path, origin: str) -> tuple[datetime, CheckResult] | None:
    path = _cache_path(guard_home)
    try:
        if path.stat().st_size > _MAX_CACHE_BYTES:
            return None
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    # A check of another Guard Cloud says nothing about this pairing.
    if not isinstance(payload, dict) or payload.get("schema") != _CACHE_SCHEMA or payload.get("origin") != origin:
        return None
    checked = _parse_iso(payload.get("checked_at"))
    service = payload.get("service")
    if checked is None or not isinstance(service, dict):
        return None
    state = service.get("state")
    message = service.get("message")
    status = service.get("http_status")
    if not isinstance(state, str) or not isinstance(message, str):
        return None
    return checked, CheckResult(state, message[:_MAX_MESSAGE_CHARS], status if isinstance(status, int) else None)


def _write_cache(guard_home: Path, origin: str, checked: datetime, service: CheckResult) -> None:
    path = _cache_path(guard_home)
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        os.chmod(path.parent, 0o700)
    text = json.dumps(
        {"schema": _CACHE_SCHEMA, "origin": origin, "checked_at": _iso(checked), "service": _check_dict(service)}
    )
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
        replace_file(temporary_path, path)
    finally:
        with suppress(OSError):
            temporary_path.unlink()


def _check_dict(check: CheckResult) -> dict[str, object]:
    entry: dict[str, object] = {"state": check.state, "message": check.message[:_MAX_MESSAGE_CHARS]}
    if check.http_status is not None:
        entry["http_status"] = check.http_status
    return entry


def _connection(guard_home: Path, pairing: _Pairing | None, now: datetime) -> dict[str, object]:
    if pairing is None:
        return {"state": "not_paired", "check": {"state": "not_checked"}}
    row: dict[str, object] = {
        "state": pairing.cloud_actions,
        "workspace": pairing.workspace_id,
        "site": _site_host(pairing.origin),
        "cloud_url": pairing.origin,
        "cloud_base_url": _cloud_base_url(pairing.origin),
    }
    saved = _read_cache(guard_home, pairing.origin)
    if saved is None:
        row["check"] = {"state": "not_checked"}
    else:
        checked, service = saved
        row["check"] = {
            "checked_at": _iso(checked),
            "stale": now - checked > STALE_AFTER,
            "service": _check_dict(service),
        }
    return row


def cloud_actions_local_status(store: GuardStore, *, now: datetime | None = None) -> dict[str, object]:
    """This computer's Cloud actions and the last saved check, without calling Guard Cloud."""

    from ..cli.cloud_actions_alpha_cleanup import remove_alpha_sign_ins

    moment = now or datetime.now(timezone.utc)
    remove_alpha_sign_ins(store.guard_home)
    pairing = _pairing(store)
    saved = _read_cache(store.guard_home, pairing.origin) if pairing is not None else None
    return {
        "schema": CLOUD_ACTIONS_STATUS_SCHEMA,
        "generated_at": _iso(moment),
        "stale_after_seconds": int(STALE_AFTER.total_seconds()),
        "check_interval_seconds": int(CHECK_INTERVAL.total_seconds()),
        "next_check_allowed_at": _iso(saved[0] + CHECK_INTERVAL) if saved is not None else None,
        "connection": _connection(store.guard_home, pairing, moment),
        "included_actions": "not_available_yet",
        "accounts": "not_available_yet",
    }


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
    within a minute of the last check, and CloudActionsCheckBusyError while another check runs.
    """

    if not _CHECK_LOCK.acquire(blocking=False):
        raise CloudActionsCheckBusyError("check_running")
    try:
        moment = now or datetime.now(timezone.utc)
        pairing = _pairing(store)
        if pairing is None:
            raise CloudActionsNotPairedError("not_paired")
        saved = _read_cache(store.guard_home, pairing.origin)
        if saved is not None and timedelta(0) <= moment - saved[0] < CHECK_INTERVAL:
            raise CloudActionsCheckedRecentlyError(max(1, int((saved[0] + CHECK_INTERVAL - moment).total_seconds())))
        service = (checker or _live_checker)(pairing.origin)
        _write_cache(store.guard_home, pairing.origin, moment, service)
        return cloud_actions_local_status(store, now=moment)
    finally:
        _CHECK_LOCK.release()
