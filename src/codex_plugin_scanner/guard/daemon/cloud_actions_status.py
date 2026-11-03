"""What the local dashboard may show about Cloud actions sign-ins.

`GET /v1/cloud-actions/status` reads the saved sign-ins and the last saved
check. It never calls Guard Cloud, so it answers offline and fast.
`POST /v1/cloud-actions/status` runs the same checks as `hol-guard
cloud-actions status`, at most once a minute, and saves what Guard Cloud
answered.

The projection is deliberately narrow. Each row names the workspace, the Guard
Cloud site (host only), when the sign-in was made and when it expires, and a
state code. It never carries an access or refresh value, a secret reference, a
file path or a server reply body. Every check result says when it was made and
whether it is stale, so the page can label old answers instead of presenting
them as current. Included actions and connected accounts are not reported by
Guard Cloud yet; the projection says so rather than inventing numbers.

Signing in to Cloud actions never authorizes the daemon: these routes accept
only the daemon's own token or a dashboard session, like every other `/v1`
route.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from ..cli.cloud_actions_session import PROFILE_PATTERN, CloudActionsProfile, CloudActionsSessionStore

CLOUD_ACTIONS_STATUS_SCHEMA = "guard.cloud-actions.local-status.v1"
STALE_AFTER = timedelta(minutes=5)
CHECK_INTERVAL = timedelta(minutes=1)
MAX_PROFILES = 32

_CACHE_SCHEMA = "guard.cloud-actions.last-check.v1"
_CACHE_FILE = "last-check.json"
_MAX_CACHE_BYTES = 64 * 1024
_MAX_MESSAGE_CHARS = 240
_CHECK_LOCK = threading.Lock()


@dataclass(frozen=True)
class CheckResult:
    """One profile's saved check: a stable state code and a message safe to show."""

    state: str
    message: str
    http_status: int | None = None


Checker = Callable[[CloudActionsProfile, str], tuple[CheckResult, CheckResult]]


class CloudActionsCheckBusyError(RuntimeError):
    """Another check is running."""


class CloudActionsCheckedRecentlyError(RuntimeError):
    """The last check is less than a minute old."""

    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__("checked_recently")
        self.retry_after_seconds = retry_after_seconds


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


def _site_host(issuer: str) -> str | None:
    try:
        parts = urlsplit(issuer)
        host = parts.hostname
        port = parts.port
    except ValueError:
        return None
    if not host:
        return None
    return f"{host}:{port}" if port is not None else host


def _profile_names(store: CloudActionsSessionStore) -> list[str]:
    folder = store.root / "profiles"
    try:
        entries = sorted(folder.iterdir())
    except OSError:
        return []
    names = [
        entry.stem
        for entry in entries
        if entry.suffix == ".json" and PROFILE_PATTERN.fullmatch(entry.stem) is not None and entry.is_file()
    ]
    return names[:MAX_PROFILES]


def _cache_path(store: CloudActionsSessionStore) -> Path:
    return store.root / _CACHE_FILE


def _read_cache(store: CloudActionsSessionStore) -> dict[str, dict[str, object]]:
    path = _cache_path(store)
    try:
        if path.stat().st_size > _MAX_CACHE_BYTES:
            return {}
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(payload, dict) or payload.get("schema") != _CACHE_SCHEMA:
        return {}
    profiles = payload.get("profiles")
    if not isinstance(profiles, dict):
        return {}
    return {name: entry for name, entry in profiles.items() if isinstance(name, str) and isinstance(entry, dict)}


def _write_cache(store: CloudActionsSessionStore, profiles: dict[str, dict[str, object]]) -> None:
    from ..cli.cloud_actions_session import (
        _ensure_private_dir,  # pyright: ignore[reportPrivateUsage]
        _write_private_atomic,  # pyright: ignore[reportPrivateUsage]
    )

    _ensure_private_dir(store.root)
    _write_private_atomic(_cache_path(store), json.dumps({"schema": _CACHE_SCHEMA, "profiles": profiles}))


def _check_dict(check: CheckResult) -> dict[str, object]:
    entry: dict[str, object] = {"state": check.state, "message": check.message[:_MAX_MESSAGE_CHARS]}
    if check.http_status is not None:
        entry["http_status"] = check.http_status
    return entry


def _saved_check(entry: object) -> CheckResult | None:
    if not isinstance(entry, dict):
        return None
    state = entry.get("state")
    message = entry.get("message")
    status = entry.get("http_status")
    if not isinstance(state, str) or not isinstance(message, str):
        return None
    return CheckResult(state, message[:_MAX_MESSAGE_CHARS], status if isinstance(status, int) else None)


def _row_state(*, has_secret: bool, expired: bool, check: tuple[CheckResult, CheckResult] | None) -> str:
    if not has_secret:
        return "profile_damaged"
    # An expiry that passed after the last check is still an expiry.
    if expired:
        return "sign_in_expired"
    if check is None:
        return "not_checked"
    service, connection = check
    return service.state if service.state != "current" else connection.state


def _saved_pair(
    cached: dict[str, object] | None, profile: CloudActionsProfile
) -> tuple[datetime, CheckResult, CheckResult] | None:
    # A check made for an earlier sign-in says nothing about this one.
    if cached is None or cached.get("signed_in_at") != profile.signed_in_at:
        return None
    checked = _parse_iso(cached.get("checked_at"))
    service = _saved_check(cached.get("service"))
    connection = _saved_check(cached.get("connection"))
    if checked is None or service is None or connection is None:
        return None
    return checked, service, connection


def _row(
    store: CloudActionsSessionStore, name: str, cached: dict[str, object] | None, now: datetime
) -> dict[str, object]:
    profile = store.load(name)
    if profile is None:
        return {"profile": name, "state": "profile_damaged", "check": {"state": "not_checked"}}
    saved = _saved_pair(cached, profile)
    expired = profile.is_expired(now)
    row: dict[str, object] = {
        "profile": profile.name,
        "workspace": profile.workspace_id,
        "site": _site_host(profile.issuer),
        "signed_in_at": profile.signed_in_at,
        "expires_at": profile.expires_at,
        "expired": expired,
        "state": _row_state(
            has_secret=store.load_secrets(name) is not None,
            expired=expired,
            check=None if saved is None else (saved[1], saved[2]),
        ),
    }
    if saved is None:
        row["check"] = {"state": "not_checked"}
    else:
        checked, service, connection = saved
        row["check"] = {
            "checked_at": _iso(checked),
            "stale": now - checked > STALE_AFTER,
            "service": _check_dict(service),
            "connection": _check_dict(connection),
        }
    return row


def _last_checked(cache: dict[str, dict[str, object]], names: list[str]) -> datetime | None:
    moments = [moment for name in names if (moment := _parse_iso(cache.get(name, {}).get("checked_at"))) is not None]
    return max(moments, default=None)


def cloud_actions_local_status(guard_home: Path, *, now: datetime | None = None) -> dict[str, object]:
    """The saved sign-ins and their last check, without calling Guard Cloud."""

    moment = now or datetime.now(timezone.utc)
    store = CloudActionsSessionStore(guard_home)
    cache = _read_cache(store)
    names = _profile_names(store)
    last_checked = _last_checked(cache, names)
    return {
        "schema": CLOUD_ACTIONS_STATUS_SCHEMA,
        "generated_at": _iso(moment),
        "stale_after_seconds": int(STALE_AFTER.total_seconds()),
        "check_interval_seconds": int(CHECK_INTERVAL.total_seconds()),
        "next_check_allowed_at": _iso(last_checked + CHECK_INTERVAL) if last_checked is not None else None,
        "sign_ins": [_row(store, name, cache.get(name), moment) for name in names],
        "included_actions": "not_available_yet",
        "accounts": "not_available_yet",
    }


def _live_checker(profile: CloudActionsProfile, access_token: str) -> tuple[CheckResult, CheckResult]:
    from ..cli.cloud_actions_health import check_connection, check_service

    service = check_service(profile)
    if service.state in {"offline", "not_turned_on", "profile_damaged"}:
        same = CheckResult(service.state, service.message, service.http_status)
        return same, same
    connection = check_connection(profile, access_token)
    return (
        CheckResult(service.state, service.message, service.http_status),
        CheckResult(connection.state, connection.message, connection.http_status),
    )


def check_cloud_actions(
    guard_home: Path,
    *,
    now: datetime | None = None,
    checker: Checker | None = None,
) -> dict[str, object]:
    """Ask Guard Cloud about every saved sign-in once, save the answers, and return the projection.

    Raises CloudActionsCheckedRecentlyError within a minute of the last check
    and CloudActionsCheckBusyError while another check runs.
    """

    if not _CHECK_LOCK.acquire(blocking=False):
        raise CloudActionsCheckBusyError("check_running")
    try:
        moment = now or datetime.now(timezone.utc)
        store = CloudActionsSessionStore(guard_home)
        cache = _read_cache(store)
        names = _profile_names(store)
        latest = _last_checked(cache, names)
        if latest is not None and timedelta(0) <= moment - latest < CHECK_INTERVAL:
            raise CloudActionsCheckedRecentlyError(max(1, int((latest + CHECK_INTERVAL - moment).total_seconds())))
        run = checker or _live_checker
        fresh: dict[str, dict[str, object]] = {}
        for name in names:
            profile = store.load(name)
            secrets = store.load_secrets(name) if profile is not None else None
            if profile is None or secrets is None:
                continue
            service, connection = run(profile, secrets.access_token)
            fresh[name] = {
                "checked_at": _iso(moment),
                "signed_in_at": profile.signed_in_at,
                "service": _check_dict(service),
                "connection": _check_dict(connection),
            }
        _write_cache(store, fresh)
        return cloud_actions_local_status(guard_home, now=moment)
    finally:
        _CHECK_LOCK.release()
