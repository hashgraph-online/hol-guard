"""The local dashboard's view of Cloud actions sign-ins.

`GET /v1/cloud-actions/status` reads saved sign-ins and the last check without
calling Guard Cloud; `POST` runs one check a minute. The tests check that every
answer is labelled with its age, that nothing secret or path-like leaves the
daemon, and that a Cloud actions sign-in can never stand in for the daemon's
own token.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.cli.cloud_actions_session import (
    CloudActionsProfile,
    CloudActionsSecrets,
    CloudActionsSessionStore,
)
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.daemon import cloud_actions_status as status_module
from codex_plugin_scanner.guard.daemon.cloud_actions_status import (
    CheckResult,
    CloudActionsCheckedRecentlyError,
    check_cloud_actions,
    cloud_actions_local_status,
)
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store import GuardStore

NOW = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)
ACCESS = "cloud-actions-access-canary-3c9d"
REFRESH = "cloud-actions-refresh-canary-81aa"
WS = "11111111-1111-4111-8111-111111111111"


def _sign_in(
    home: Path,
    name: str = "default",
    *,
    expires: datetime | None = None,
    signed_in: str = "",
    issuer: str = "https://cloud.example.test:8443",
) -> None:
    store = CloudActionsSessionStore(home)
    profile = CloudActionsProfile(
        name=name,
        issuer=issuer,
        resource=f"{issuer}/api/guard/gateway/mcp",
        client_id="client-1",
        workspace_id=WS,
        scopes=("guard:gateway",),
        expires_at=(expires or NOW + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        grant_id="grant-1",
        signed_in_at=signed_in or "2026-11-03T11:00:00Z",
    )
    with store.lock(name):
        store.save(profile, CloudActionsSecrets(access_token=ACCESS, refresh_token=REFRESH))


def _connected(_profile: CloudActionsProfile, access: str, _deadline: float = 0.0) -> tuple[CheckResult, CheckResult]:
    assert access == ACCESS
    return (
        CheckResult("current", "Guard Cloud offers Cloud actions as this sign-in expects.", 200),
        CheckResult("connected", "Guard Cloud accepted this sign-in.", 501),
    )


def _assert_nothing_private(payload: object, home: Path) -> None:
    text = json.dumps(payload)
    for secret in (ACCESS, REFRESH, "secret_ref", "cloud-actions-default-", str(home), "/api/guard/gateway"):
        assert secret not in text


def test_no_sign_ins_reports_nothing_and_no_numbers(tmp_path: Path) -> None:
    payload = cloud_actions_local_status(tmp_path, now=NOW)

    assert payload["sign_ins"] == []
    assert payload["included_actions"] == "not_available_yet"
    assert payload["accounts"] == "not_available_yet"
    assert payload["next_check_allowed_at"] is None


def test_saved_sign_in_is_shown_unchecked_with_host_only(tmp_path: Path) -> None:
    _sign_in(tmp_path)

    payload = cloud_actions_local_status(tmp_path, now=NOW)

    assert payload["sign_ins"] == [
        {
            "profile": "default",
            "workspace": WS,
            "site": "cloud.example.test:8443",
            "cloud_url": "https://cloud.example.test:8443",
            "cloud_base_url": None,
            "signed_in_at": "2026-11-03T11:00:00Z",
            "expires_at": "2026-11-03T13:00:00Z",
            "expired": False,
            "state": "not_checked",
            "check": {"state": "not_checked"},
        }
    ]
    _assert_nothing_private(payload, tmp_path)


@pytest.mark.parametrize(
    ("issuer", "staging", "expected"),
    [
        ("https://hol.org", "", "https://hol.org"),
        ("https://staging.example.test", "https://staging.example.test|/points", "https://staging.example.test/points"),
        ("http://127.0.0.1:3017", "", "http://127.0.0.1:3017"),
        ("https://cloud.example.test:8443", "", None),
        ("https://hol.org.example.test", "", None),
    ],
)
def test_guard_cloud_pages_are_offered_only_for_sites_guard_recognises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, issuer: str, staging: str, expected: str | None
) -> None:
    monkeypatch.setenv("HOL_GUARD_STAGING_ORIGIN", staging)
    _sign_in(tmp_path, issuer=issuer)

    row = cloud_actions_local_status(tmp_path, now=NOW)["sign_ins"][0]

    assert row["cloud_base_url"] == expected
    _assert_nothing_private(row, tmp_path)


def test_check_is_saved_privately_and_labelled_stale_after_five_minutes(tmp_path: Path) -> None:
    _sign_in(tmp_path)

    checked = check_cloud_actions(tmp_path, now=NOW, checker=_connected)
    later = cloud_actions_local_status(tmp_path, now=NOW + timedelta(minutes=5, seconds=1))

    row = checked["sign_ins"][0]
    assert row["state"] == "connected"
    assert row["check"]["checked_at"] == "2026-11-03T12:00:00Z"
    assert row["check"]["stale"] is False
    assert later["sign_ins"][0]["check"]["stale"] is True
    assert later["sign_ins"][0]["state"] == "connected"
    cache = tmp_path / "cloud-actions" / "last-check.json"
    assert ACCESS not in cache.read_text() and REFRESH not in cache.read_text()
    if os.name != "nt":
        assert cache.stat().st_mode & 0o077 == 0
    _assert_nothing_private(checked, tmp_path)
    _assert_nothing_private(later, tmp_path)


def test_checks_run_at_most_once_a_minute(tmp_path: Path) -> None:
    _sign_in(tmp_path)
    check_cloud_actions(tmp_path, now=NOW, checker=_connected)

    with pytest.raises(CloudActionsCheckedRecentlyError) as error:
        check_cloud_actions(tmp_path, now=NOW + timedelta(seconds=20), checker=_connected)

    assert error.value.retry_after_seconds == 40
    again = check_cloud_actions(tmp_path, now=NOW + timedelta(seconds=61), checker=_connected)
    assert again["sign_ins"][0]["check"]["checked_at"] == "2026-11-03T12:01:01Z"


def test_offline_answer_is_reported_as_offline(tmp_path: Path) -> None:
    _sign_in(tmp_path)

    def offline(_profile: CloudActionsProfile, _access: str, _deadline: float) -> tuple[CheckResult, CheckResult]:
        result = CheckResult("offline", "Guard Cloud could not be reached.")
        return result, result

    payload = check_cloud_actions(tmp_path, now=NOW, checker=offline)

    row = payload["sign_ins"][0]
    assert row["state"] == "offline"
    assert row["check"]["connection"] == {"state": "offline", "message": "Guard Cloud could not be reached."}


def test_a_new_sign_in_drops_the_previous_check(tmp_path: Path) -> None:
    _sign_in(tmp_path)
    check_cloud_actions(tmp_path, now=NOW, checker=_connected)
    _sign_in(tmp_path, signed_in="2026-11-03T12:00:30Z")

    payload = cloud_actions_local_status(tmp_path, now=NOW + timedelta(seconds=40))

    assert payload["sign_ins"][0]["state"] == "not_checked"
    assert payload["sign_ins"][0]["check"] == {"state": "not_checked"}


def test_expiry_after_the_last_check_wins(tmp_path: Path) -> None:
    _sign_in(tmp_path, expires=NOW + timedelta(minutes=2))
    check_cloud_actions(tmp_path, now=NOW, checker=_connected)

    payload = cloud_actions_local_status(tmp_path, now=NOW + timedelta(minutes=3))

    assert payload["sign_ins"][0]["state"] == "sign_in_expired"
    assert payload["sign_ins"][0]["expired"] is True


def test_missing_secret_or_damaged_profile_is_profile_damaged(tmp_path: Path) -> None:
    _sign_in(tmp_path)
    _sign_in(tmp_path, "work")
    profiles = tmp_path / "cloud-actions" / "profiles"
    record = json.loads((profiles / "default.json").read_text())
    record["secret_ref"] = "cloud-actions-default-0000000000000000"
    (profiles / "default.json").write_text(json.dumps(record))
    (profiles / "work.json").write_text("{not json")

    payload = cloud_actions_local_status(tmp_path, now=NOW)

    states = {row["profile"]: row["state"] for row in payload["sign_ins"]}
    assert states == {"default": "profile_damaged", "work": "profile_damaged"}
    _assert_nothing_private(payload, tmp_path)


def test_a_profile_without_a_time_zone_reads_as_expired(tmp_path: Path) -> None:
    _sign_in(tmp_path)
    profiles = tmp_path / "cloud-actions" / "profiles"
    record = json.loads((profiles / "default.json").read_text())
    record["expires_at"] = "2026-11-03T13:00:00"
    (profiles / "default.json").write_text(json.dumps(record))

    payload = cloud_actions_local_status(tmp_path, now=NOW)

    assert payload["sign_ins"][0]["expired"] is True
    assert payload["sign_ins"][0]["state"] == "sign_in_expired"


def test_the_site_and_access_value_are_read_under_the_profile_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _sign_in(tmp_path)
    held: list[str] = []
    reads: list[tuple[str, bool]] = []
    real_lock = CloudActionsSessionStore.lock
    real_load = CloudActionsSessionStore.load
    real_secrets = CloudActionsSessionStore.load_secrets

    @contextmanager
    def tracked_lock(self: CloudActionsSessionStore, name: str, *, timeout: float | None = None) -> Iterator[None]:
        with real_lock(self, name, timeout=timeout):
            held.append(name)
            try:
                yield
            finally:
                held.remove(name)

    def tracked_load(self: CloudActionsSessionStore, name: str) -> CloudActionsProfile | None:
        reads.append(("profile", name in held))
        return real_load(self, name)

    def tracked_secrets(self: CloudActionsSessionStore, name: str) -> CloudActionsSecrets | None:
        reads.append(("secrets", name in held))
        return real_secrets(self, name)

    monkeypatch.setattr(CloudActionsSessionStore, "lock", tracked_lock)
    monkeypatch.setattr(CloudActionsSessionStore, "load", tracked_load)
    monkeypatch.setattr(CloudActionsSessionStore, "load_secrets", tracked_secrets)
    reads_before = len(reads)
    seen: list[str] = []

    def checker(profile: CloudActionsProfile, access: str, _deadline: float) -> tuple[CheckResult, CheckResult]:
        seen.extend(kind for kind, locked in reads[reads_before:] if locked)
        return _connected(profile, access)

    check_cloud_actions(tmp_path, now=NOW, checker=checker)

    assert seen == ["profile", "secrets"]


def test_a_check_stops_at_its_time_budget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _sign_in(tmp_path, "client")
    _sign_in(tmp_path, "work")
    clock = [100.0]
    monkeypatch.setattr(status_module, "_clock", lambda: clock[0])
    deadlines: list[float] = []

    def slow(profile: CloudActionsProfile, access: str, deadline: float) -> tuple[CheckResult, CheckResult]:
        deadlines.append(deadline)
        clock[0] += 30.0
        return _connected(profile, access)

    payload = check_cloud_actions(tmp_path, now=NOW, checker=slow, budget_seconds=20.0)

    assert deadlines == [120.0]
    states = {row["profile"]: row["check"].get("state", "checked") for row in payload["sign_ins"]}
    assert states == {"client": "checked", "work": "not_checked"}


def test_a_later_check_starts_with_the_sign_in_the_budget_missed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _sign_in(tmp_path, "client")
    _sign_in(tmp_path, "work")
    clock = [100.0]
    monkeypatch.setattr(status_module, "_clock", lambda: clock[0])
    order: list[str] = []

    def slow(profile: CloudActionsProfile, access: str, deadline: float) -> tuple[CheckResult, CheckResult]:
        order.append(profile.name)
        clock[0] += 30.0
        return _connected(profile, access)

    check_cloud_actions(tmp_path, now=NOW, checker=slow, budget_seconds=20.0)
    later = NOW + timedelta(minutes=2)
    payload = check_cloud_actions(tmp_path, now=later, checker=slow, budget_seconds=20.0)

    assert order == ["client", "work"]
    checked_at = {row["profile"]: row["check"].get("checked_at") for row in payload["sign_ins"]}
    # The first answer for "client" is kept rather than erased by the second check.
    assert checked_at == {"client": "2026-11-03T12:00:00Z", "work": "2026-11-03T12:02:00Z"}


def test_waiting_for_a_busy_sign_in_counts_against_the_budget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _sign_in(tmp_path, "client")
    _sign_in(tmp_path, "work")
    clock = [100.0]
    monkeypatch.setattr(status_module, "_clock", lambda: clock[0])
    real_lock = CloudActionsSessionStore.lock
    timeouts: dict[str, float | None] = {}
    checked: list[str] = []

    @contextmanager
    def waiting_lock(self: CloudActionsSessionStore, name: str, *, timeout: float | None = None) -> Iterator[None]:
        timeouts[name] = timeout
        with real_lock(self, name, timeout=timeout):
            # Another process held "work" until after the budget ran out.
            if name == "work":
                clock[0] += 30.0
            yield

    def quick(profile: CloudActionsProfile, access: str, deadline: float) -> tuple[CheckResult, CheckResult]:
        checked.append(profile.name)
        clock[0] += 15.0
        return _connected(profile, access)

    monkeypatch.setattr(CloudActionsSessionStore, "lock", waiting_lock)
    payload = check_cloud_actions(tmp_path, now=NOW, checker=quick, budget_seconds=20.0)

    assert timeouts == {"client": 20.0, "work": 5.0}
    assert checked == ["client"]
    states = {row["profile"]: row["check"].get("state", "checked") for row in payload["sign_ins"]}
    assert states == {"client": "checked", "work": "not_checked"}


def _request(
    port: int,
    path: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=json.dumps(body or {}).encode("utf-8") if method == "POST" else None,
        headers={"Content-Type": "application/json", **(headers or {})},
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        raw = error.read().decode("utf-8")
        try:
            return error.code, json.loads(raw)
        except json.JSONDecodeError:
            return error.code, {"raw": raw}


@pytest.fixture
def daemon(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    # The daemon reads the real clock, so its sign-in expires relative to it.
    _sign_in(tmp_path, expires=datetime.now(timezone.utc) + timedelta(hours=1))
    monkeypatch.setattr(status_module, "_live_checker", _connected)
    server = GuardDaemonServer(GuardStore(tmp_path), host="127.0.0.1", port=0)
    server.start()
    try:
        yield server
    finally:
        server.stop()


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_a_cloud_actions_sign_in_cannot_authorize_the_daemon(daemon: Any, tmp_path: Path, method: str) -> None:
    for headers in ({"Authorization": f"Bearer {ACCESS}"}, {"X-Guard-Token": ACCESS}, {"X-Guard-Token": REFRESH}):
        status, payload = _request(daemon.port, "/v1/cloud-actions/status", method=method, headers=headers)
        assert status == 401, headers
        _assert_nothing_private(payload, tmp_path)
    assert not (tmp_path / "cloud-actions" / "last-check.json").exists()


def test_daemon_serves_the_projection_and_one_check_a_minute(daemon: Any, tmp_path: Path) -> None:
    token = {"X-Guard-Token": daemon._server.auth_token}

    read_status, read = _request(daemon.port, "/v1/cloud-actions/status", headers=token)
    check_status, checked = _request(daemon.port, "/v1/cloud-actions/status", method="POST", headers=token)
    again_status, again = _request(daemon.port, "/v1/cloud-actions/status", method="POST", headers=token)

    assert read_status == 200
    assert read["sign_ins"][0]["state"] == "not_checked"
    assert check_status == 200
    assert checked["sign_ins"][0]["state"] == "connected"
    assert checked["sign_ins"][0]["check"]["stale"] is False
    assert again_status == 429
    assert again["error"] == "checked_recently"
    for payload in (read, checked, again):
        _assert_nothing_private(payload, tmp_path)


def _pause_on_this_computer(home: Path) -> str:
    request_id = "req-local-pause"
    GuardStore(home).add_approval_request(
        GuardApprovalRequest(
            request_id=request_id,
            harness="codex",
            artifact_id="codex:session:tool:local-pause",
            artifact_name="local pause",
            artifact_type="tool_action_request",
            artifact_hash="hash-local-pause",
            policy_action="require-reapproval",
            recommended_scope="artifact",
            changed_fields=("args",),
            source_scope="session",
            config_path=str(home / "workspace" / ".codex" / "config.toml"),
            review_command=f"hol-guard approvals approve {request_id}",
            approval_url=f"http://127.0.0.1/pending/{request_id}",
        ),
        "2026-11-03T11:30:00+00:00",
    )
    return request_id


@pytest.mark.parametrize(
    "cloud_id",
    [
        "gxr1:hosted_action:0b5e7c1d-4f7a-4c39-9d3e-6a1f2b3c4d5e",
        "gxr1%3Ahosted_action%3A0b5e7c1d-4f7a-4c39-9d3e-6a1f2b3c4d5e",
        "0b5e7c1d-4f7a-4c39-9d3e-6a1f2b3c4d5e",
    ],
)
def test_a_guard_cloud_decision_id_cannot_resolve_anything_on_this_computer(
    daemon: Any, tmp_path: Path, cloud_id: str
) -> None:
    pending = _pause_on_this_computer(tmp_path)
    token = {"X-Guard-Token": daemon._server.auth_token}

    for action in ("approve", "block"):
        status, payload = _request(
            daemon.port,
            f"/v1/requests/{cloud_id}/{action}",
            method="POST",
            headers=token,
            body={"scope": "artifact", "reason": "approved in Guard Cloud"},
        )
        assert status >= 400, (cloud_id, action, payload)
        assert payload.get("resolved") is not True

    assert GuardStore(tmp_path).get_approval_request(pending)["status"] == "pending"


@pytest.mark.parametrize("cloud_answer", ["connected", "offline", "expired"])
def test_local_approvals_keep_working_whatever_guard_cloud_says(
    daemon: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cloud_answer: str
) -> None:
    pending = _pause_on_this_computer(tmp_path)
    token = {"X-Guard-Token": daemon._server.auth_token}
    if cloud_answer == "offline":
        monkeypatch.setattr(
            status_module,
            "_live_checker",
            lambda *_args: (CheckResult("offline", "Guard Cloud did not answer.", None),) * 2,
        )
    if cloud_answer == "expired":
        _sign_in(tmp_path, expires=datetime.now(timezone.utc) - timedelta(hours=1))

    check_status, checked = _request(daemon.port, "/v1/cloud-actions/status", method="POST", headers=token)
    status, payload = _request(
        daemon.port,
        f"/v1/requests/{pending}/approve",
        method="POST",
        headers=token,
        body={"scope": "artifact", "reason": "approved on this computer"},
    )

    expected = {"connected": "connected", "offline": "offline", "expired": "sign_in_expired"}[cloud_answer]
    assert check_status == 200
    assert checked["sign_ins"][0]["state"] == expected
    assert status == 200
    assert payload["resolved"] is True
    assert GuardStore(tmp_path).get_approval_request(pending)["status"] != "pending"
