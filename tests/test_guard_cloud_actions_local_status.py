"""The local dashboard's view of Cloud actions on this computer.

Cloud actions use the `hol-guard connect` pairing. `GET /v1/cloud-actions/status`
reads the pairing, what connect said about Cloud actions and the last saved
check, without calling Guard Cloud; `POST` asks Guard Cloud's public
description at most once a minute. The tests check that every answer is
labelled with its age, that nothing secret or path-like leaves the daemon, and
that Cloud actions access can never stand in for the daemon's own token.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal

import pytest

from codex_plugin_scanner.guard.cli import cloud_actions_access
from codex_plugin_scanner.guard.cli.cloud_actions_access import CloudActionsAccessError, CloudActionsPairing
from codex_plugin_scanner.guard.cli.connect_cloud_actions import record_cloud_actions_connect_report
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.daemon import cloud_actions_status as status_module
from codex_plugin_scanner.guard.daemon.cloud_actions_status import (
    CheckResult,
    CloudActionsCheckedRecentlyError,
    CloudActionsNotPairedError,
    check_cloud_actions,
    cloud_actions_local_status,
)
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store import GuardStore

NOW = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)
WS = "11111111-1111-4111-8111-111111111111"
SITE = "https://cloud.example.test:8443"
ACCESS = "cloud-actions-access-canary-3c9d"


def _pair(
    monkeypatch: pytest.MonkeyPatch,
    home: Path,
    *,
    origin: str = SITE,
    report: Literal["on", "off"] | None = None,
    grant_id: str = "grant-1",
) -> GuardStore:
    """Pair `home` with `origin`; `report` is what connect said about Cloud actions."""

    def read_pairing(_store: object) -> CloudActionsPairing:
        return CloudActionsPairing(origin=origin, workspace_id=WS)

    monkeypatch.setattr(cloud_actions_access, "read_cloud_actions_pairing", read_pairing)
    monkeypatch.setattr(
        GuardStore, "get_oauth_local_credential_health", lambda _self: {"state": "healthy", "grant_id": grant_id}
    )
    store = GuardStore(home)
    if report is not None:
        record_cloud_actions_connect_report(
            store, grant_id=grant_id, report={"status": report, "workspace_id": WS}, now="2026-11-03T11:00:00Z"
        )
    return store


def _connection(projection: dict[str, object]) -> Any:
    return projection["connection"]


def _unpaired(monkeypatch: pytest.MonkeyPatch, home: Path) -> GuardStore:
    def read_pairing(_store: object) -> CloudActionsPairing:
        raise CloudActionsAccessError("not_paired", "Not paired.")

    monkeypatch.setattr(cloud_actions_access, "read_cloud_actions_pairing", read_pairing)
    return GuardStore(home)


def _current(origin: str) -> CheckResult:
    assert origin == SITE
    return CheckResult("current", "Guard Cloud offers Cloud actions.", 200)


@pytest.fixture(autouse=True)
def _connection_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    """Guard Cloud accepts the connection unless a test says otherwise."""

    monkeypatch.setattr(status_module, "_live_pairing_checker", lambda _store: None)


_LIVE_PAIRING_CHECKER = status_module._live_pairing_checker  # pyright: ignore[reportPrivateUsage]


def _refresh_raising(monkeypatch: pytest.MonkeyPatch, error: Exception) -> list[bool]:
    """Use the real connection check, with a renewal that fails with `error`."""
    from codex_plugin_scanner.guard.runtime import runner

    monkeypatch.setattr(status_module, "_live_pairing_checker", _LIVE_PAIRING_CHECKER)
    calls: list[bool] = []

    def resolve(_store: object, *, force_refresh: bool = False, **_kwargs: object) -> dict[str, object]:
        calls.append(force_refresh)
        raise error

    monkeypatch.setattr(runner, "_resolve_guard_sync_auth_context", resolve)
    return calls


def test_a_revoked_connection_asks_to_reconnect(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.runtime import runner

    store = _pair(monkeypatch, tmp_path, report="on")
    calls = _refresh_raising(
        monkeypatch,
        runner.GuardSyncAuthorizationExpiredError(runner._guard_oauth_reconnect_after_revoked_message()),  # pyright: ignore[reportPrivateUsage]
    )

    checked = check_cloud_actions(store, now=NOW, checker=_current)

    assert calls == [True]
    assert _connection(checked)["check"]["service"] == {
        "state": "reconnect",
        "message": "Guard Cloud refused to renew this computer's access.",
    }
    _assert_nothing_private(checked, tmp_path)


def _not_proof_of_revocation() -> list[Exception]:
    from codex_plugin_scanner.guard.runtime import runner

    expired = runner.GuardSyncAuthorizationExpiredError
    rejected = runner._GuardOAuthRefreshRejectedError  # pyright: ignore[reportPrivateUsage]
    reauthorize = runner._guard_oauth_reauthorization_message()  # pyright: ignore[reportPrivateUsage]
    return [
        RuntimeError("rate limited"),
        OSError("unreachable"),
        ValueError("bad answer"),
        # A malformed renewal answer or a proof Guard could not sign.
        expired(reauthorize),
        expired(f"{reauthorize} could not sign the proof"),
        # Guard Cloud refused the request for another reason than invalid_grant.
        rejected(f"{reauthorize} Guard Cloud answered 400 invalid_request (invalid_grant hint)."),
    ]


@pytest.mark.parametrize("error", _not_proof_of_revocation())
def test_a_connection_check_that_cannot_tell_keeps_the_service_answer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    store = _pair(monkeypatch, tmp_path, report="on")
    _refresh_raising(monkeypatch, error)

    checked = check_cloud_actions(store, now=NOW, checker=_current)

    assert _connection(checked)["check"]["service"]["state"] == "current"


def test_an_unreachable_guard_cloud_skips_the_connection_check(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _pair(monkeypatch, tmp_path, report="on")
    calls = _refresh_raising(monkeypatch, RuntimeError("not reached"))

    checked = check_cloud_actions(
        store, now=NOW, checker=lambda _origin: CheckResult("offline", "Guard Cloud could not be reached.")
    )

    assert calls == []
    assert _connection(checked)["check"]["service"]["state"] == "offline"


def _assert_nothing_private(payload: object, home: Path) -> None:
    text = json.dumps(payload)
    for value in (ACCESS, "secret_ref", str(home), "/api/guard/gateway", "grant-1"):
        assert value not in text


def test_before_connect_reports_not_paired_and_no_numbers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    payload = cloud_actions_local_status(_unpaired(monkeypatch, tmp_path), now=NOW)

    assert payload["schema"] == "guard.cloud-actions.local-status.v2"
    assert payload["connection"] == {"state": "not_paired", "check": {"state": "not_checked"}}
    assert payload["included_actions"] == "not_available_yet"
    assert payload["accounts"] == "not_available_yet"
    assert payload["next_check_allowed_at"] is None
    assert "sign_ins" not in payload


@pytest.mark.parametrize(("report", "state"), [(None, "unknown"), ("on", "on"), ("off", "off")])
def test_the_pairing_is_shown_unchecked_with_host_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, report: Literal["on", "off"] | None, state: str
) -> None:
    store = _pair(monkeypatch, tmp_path, report=report)

    payload = cloud_actions_local_status(store, now=NOW)

    assert payload["connection"] == {
        "state": state,
        "workspace": WS,
        "site": "cloud.example.test:8443",
        "cloud_url": SITE,
        "cloud_base_url": None,
        "check": {"state": "not_checked"},
    }
    _assert_nothing_private(payload, tmp_path)


@pytest.mark.parametrize(
    ("origin", "staging", "expected"),
    [
        ("https://hol.org", "", "https://hol.org"),
        ("https://staging.example.test", "https://staging.example.test|/points", "https://staging.example.test/points"),
        ("http://127.0.0.1:3017", "", "http://127.0.0.1:3017"),
        ("https://cloud.example.test:8443", "", None),
        ("https://hol.org.example.test", "", None),
    ],
)
def test_guard_cloud_pages_are_offered_only_for_sites_guard_recognises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, origin: str, staging: str, expected: str | None
) -> None:
    monkeypatch.setenv("HOL_GUARD_STAGING_ORIGIN", staging)
    store = _pair(monkeypatch, tmp_path, origin=origin)

    row = _connection(cloud_actions_local_status(store, now=NOW))

    assert row["cloud_base_url"] == expected


def test_check_is_saved_privately_and_labelled_stale_after_five_minutes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _pair(monkeypatch, tmp_path)

    checked = check_cloud_actions(store, now=NOW, checker=_current)
    later = cloud_actions_local_status(store, now=NOW + timedelta(minutes=5, seconds=1))

    check = _connection(checked)["check"]
    assert check == {
        "checked_at": "2026-11-03T12:00:00Z",
        "stale": False,
        "service": {"state": "current", "message": "Guard Cloud offers Cloud actions.", "http_status": 200},
    }
    assert _connection(later)["check"]["stale"] is True
    cache = tmp_path / "cloud-actions" / "service-check.json"
    if os.name != "nt":
        assert cache.stat().st_mode & 0o077 == 0
    _assert_nothing_private(checked, tmp_path)


def test_checks_run_at_most_once_a_minute(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _pair(monkeypatch, tmp_path)
    check_cloud_actions(store, now=NOW, checker=_current)

    with pytest.raises(CloudActionsCheckedRecentlyError) as error:
        check_cloud_actions(store, now=NOW + timedelta(seconds=20), checker=_current)

    assert error.value.retry_after_seconds == 40
    again = check_cloud_actions(store, now=NOW + timedelta(seconds=61), checker=_current)
    assert _connection(again)["check"]["checked_at"] == "2026-11-03T12:01:01Z"


def test_a_check_before_connect_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _unpaired(monkeypatch, tmp_path)

    with pytest.raises(CloudActionsNotPairedError):
        check_cloud_actions(store, now=NOW, checker=_current)

    assert not (tmp_path / "cloud-actions" / "service-check.json").exists()


def test_a_check_of_another_guard_cloud_is_not_shown(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _pair(monkeypatch, tmp_path)
    check_cloud_actions(store, now=NOW, checker=_current)
    store = _pair(monkeypatch, tmp_path, origin="https://hol.org")

    payload = cloud_actions_local_status(store, now=NOW + timedelta(seconds=30))

    assert _connection(payload)["check"] == {"state": "not_checked"}
    assert payload["next_check_allowed_at"] is None


def test_reconnecting_clears_the_check_of_the_revoked_connection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _pair(monkeypatch, tmp_path, report="on")
    check_cloud_actions(
        store, now=NOW, checker=_current, pairing_checker=lambda _store: CheckResult("reconnect", "refused")
    )
    store = _pair(monkeypatch, tmp_path, report="on", grant_id="grant-2")

    payload = cloud_actions_local_status(store, now=NOW + timedelta(seconds=30))
    assert _connection(payload)["check"] == {"state": "not_checked"}
    assert payload["next_check_allowed_at"] is None

    checked = check_cloud_actions(store, now=NOW + timedelta(seconds=30), checker=_current)
    assert _connection(checked)["check"]["service"]["state"] == "current"


def test_a_damaged_saved_check_reads_as_not_checked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _pair(monkeypatch, tmp_path)
    cache = tmp_path / "cloud-actions" / "service-check.json"
    cache.parent.mkdir(parents=True)
    cache.write_text("{not json", encoding="utf-8")

    assert _connection(cloud_actions_local_status(store, now=NOW))["check"] == {"state": "not_checked"}


def test_reading_status_removes_alpha_sign_ins(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _pair(monkeypatch, tmp_path)
    profiles = tmp_path / "cloud-actions" / "profiles"
    profiles.mkdir(parents=True)
    (profiles / "default.json").write_text("{}", encoding="utf-8")

    cloud_actions_local_status(store, now=NOW)

    assert not profiles.exists()


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
    store = _pair(monkeypatch, tmp_path)
    monkeypatch.setattr(status_module, "_live_checker", _current)
    server = GuardDaemonServer(store, host="127.0.0.1", port=0)
    server.start()
    try:
        yield server
    finally:
        server.stop()


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_cloud_actions_access_cannot_authorize_the_daemon(daemon: Any, tmp_path: Path, method: str) -> None:
    for headers in ({"Authorization": f"Bearer {ACCESS}"}, {"X-Guard-Token": ACCESS}):
        status, payload = _request(daemon.port, "/v1/cloud-actions/status", method=method, headers=headers)
        assert status == 401, headers
        _assert_nothing_private(payload, tmp_path)
    assert not (tmp_path / "cloud-actions" / "service-check.json").exists()


def test_daemon_serves_the_projection_and_one_check_a_minute(daemon: Any, tmp_path: Path) -> None:
    token = {"X-Guard-Token": daemon._server.auth_token}

    read_status, read = _request(daemon.port, "/v1/cloud-actions/status", headers=token)
    check_status, checked = _request(daemon.port, "/v1/cloud-actions/status", method="POST", headers=token)
    again_status, again = _request(daemon.port, "/v1/cloud-actions/status", method="POST", headers=token)

    assert read_status == 200
    assert _connection(read)["check"] == {"state": "not_checked"}
    assert check_status == 200
    assert _connection(checked)["check"]["service"]["state"] == "current"
    assert _connection(checked)["check"]["stale"] is False
    assert again_status == 429
    assert again["error"] == "checked_recently"
    for payload in (read, checked, again):
        _assert_nothing_private(payload, tmp_path)


def test_daemon_check_before_connect_is_refused(daemon: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _unpaired(monkeypatch, tmp_path)
    token = {"X-Guard-Token": daemon._server.auth_token}

    status, payload = _request(daemon.port, "/v1/cloud-actions/status", method="POST", headers=token)

    assert (status, payload["error"]) == (409, "not_paired")


def test_daemon_answers_unavailable_when_the_native_runtime_cannot_read_the_check(
    daemon: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from codex_plugin_scanner.guard import native_runner_authority as authority

    def unavailable(*_args: object, **_kwargs: object) -> dict[str, Any]:
        raise authority.NativeRunnerAuthorityError("native_runner_authority_unavailable")

    monkeypatch.setattr(authority, "native_runner_authority", unavailable)
    token = {"X-Guard-Token": daemon._server.auth_token}

    for method in ("GET", "POST"):
        status, payload = _request(daemon.port, "/v1/cloud-actions/status", method=method, headers=token)
        assert (status, payload["error"]) == (503, "status_unavailable"), method
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

    approval = GuardStore(tmp_path).get_approval_request(pending)
    assert approval is not None
    assert approval["status"] == "pending"


@pytest.mark.parametrize("cloud_answer", ["current", "offline", "not_paired", "out_of_actions"])
def test_local_approvals_keep_working_whatever_guard_cloud_says(
    daemon: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cloud_answer: str
) -> None:
    pending = _pause_on_this_computer(tmp_path)
    token = {"X-Guard-Token": daemon._server.auth_token}
    if cloud_answer == "offline":
        monkeypatch.setattr(
            status_module, "_live_checker", lambda _origin: CheckResult("offline", "Guard Cloud did not answer.")
        )
    if cloud_answer == "out_of_actions":
        # Guard Cloud refusing work, as when a workspace has used its included actions.
        monkeypatch.setattr(
            status_module,
            "_live_checker",
            lambda _origin: CheckResult("unexpected_answer", "Guard Cloud answered HTTP 402.", 402),
        )
    if cloud_answer == "not_paired":
        _unpaired(monkeypatch, tmp_path)

    check_status, _ = _request(daemon.port, "/v1/cloud-actions/status", method="POST", headers=token)
    status, payload = _request(
        daemon.port,
        f"/v1/requests/{pending}/approve",
        method="POST",
        headers=token,
        body={"scope": "artifact", "reason": "approved on this computer"},
    )

    assert check_status == (409 if cloud_answer == "not_paired" else 200)
    assert status == 200
    assert payload["resolved"] is True
    approval = GuardStore(tmp_path).get_approval_request(pending)
    assert approval is not None
    assert approval["status"] != "pending"
