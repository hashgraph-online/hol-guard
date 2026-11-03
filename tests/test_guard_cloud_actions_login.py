"""Cloud actions sign-in against a local stand-in for Guard Cloud.

The stand-in speaks the same metadata, registration, token and revocation
shapes as Guard Cloud. Each test bends one answer and checks that nothing is
saved unless every check passes, and that no credential reaches the output.
"""

from __future__ import annotations

import io
import json
import stat
import sys
import urllib.parse
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.cli import commands_dispatch_cloud_actions as dispatch
from codex_plugin_scanner.guard.cli.cloud_actions_login import sign_in
from codex_plugin_scanner.guard.cli.cloud_actions_oauth import (
    CLOUD_ACTIONS_SCOPES,
    CloudActionsSignInError,
    resolve_cloud_origin,
)
from codex_plugin_scanner.guard.cli.cloud_actions_session import CloudActionsSessionStore
from tests.cloud_actions_login_support import (
    OTHER_WS,
    RESOURCE_PATH,
    WS,
    Browser,
    FakeCloud,
    _all_file_bytes,
    _cli,
    _json_out,
    _login,
    browser_fixture,  # noqa: F401 -- shared fixture
    cloud_fixture,  # noqa: F401 -- shared fixture
)


def test_sign_in_saves_one_workspace_and_prints_no_credentials(
    cloud: FakeCloud, browser: Browser, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = _login(cloud, tmp_path, "--cloud-workspace", WS)
    payload, output = _json_out(capsys)

    assert exit_code == 0, output
    assert payload == {
        "schema": "guard.cloud-actions.v1",
        "command": "login",
        "state": "signed_in",
        "profile": "default",
        "cloud_url": cloud.origin,
        "cloud_workspace": WS,
        "scopes": list(CLOUD_ACTIONS_SCOPES),
        "expires_at": payload["expires_at"],
    }
    for secret in cloud.issued:
        assert secret not in output
        assert secret.encode() not in _all_file_bytes(tmp_path)
    store = CloudActionsSessionStore(tmp_path)
    saved = store.load_secrets("default")
    assert saved is not None
    assert saved.refresh_token == "refresh-secret-1"
    profile_file = tmp_path / "cloud-actions" / "profiles" / "default.json"
    if sys.platform != "win32":
        assert stat.S_IMODE(profile_file.stat().st_mode) == 0o600
        assert stat.S_IMODE(profile_file.parent.stat().st_mode) == 0o700


def test_sign_in_asks_only_for_cloud_actions(
    cloud: FakeCloud, browser: Browser, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _login(cloud, tmp_path, "--cloud-workspace", WS) == 0
    capsys.readouterr()

    [registration] = cloud.registrations
    assert registration["token_endpoint_auth_method"] == "none"
    assert registration["grant_types"] == ["authorization_code", "refresh_token"]
    assert set(registration["scope"].split()) == set(CLOUD_ACTIONS_SCOPES)
    assert all(urllib.parse.urlsplit(uri).hostname in {"127.0.0.1", "::1"} for uri in registration["redirect_uris"])
    [url] = browser.opened
    params = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
    assert url.startswith(f"{cloud.origin}/api/guard/oauth/authorize?")
    assert params["resource"] == f"{cloud.origin}{RESOURCE_PATH}"
    assert params["scope"].split() == list(CLOUD_ACTIONS_SCOPES)
    assert params["code_challenge_method"] == "S256"
    assert params["workspace_id"] == WS
    assert not {"runtime_id", "machine_id", "application_id", "runtime_label", "audience"} & set(params)
    assert urllib.parse.urlsplit(params["redirect_uri"]).hostname == "127.0.0.1"
    [token_request] = cloud.token_requests
    assert token_request["grant_type"] == "authorization_code"
    assert token_request["resource"] == params["resource"]
    assert token_request["redirect_uri"] == params["redirect_uri"]
    assert len(token_request["code_verifier"]) >= 43


def test_registered_client_is_reused_for_the_same_cloud(
    cloud: FakeCloud, browser: Browser, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _login(cloud, tmp_path) == 0
    assert _login(cloud, tmp_path, "--profile", "second") == 0
    capsys.readouterr()

    assert len(cloud.registrations) == 1
    assert {request["client_id"] for request in cloud.token_requests} == {"guard-dcr-1"}


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"authorization_server": {"issuer": "https://hol.org"}}, "metadata_issuer_mismatch"),
        ({"protected_resource": {"resource": "https://hol.org/api/guard/gateway/mcp"}}, "metadata_resource_mismatch"),
        ({"protected_resource": {"authorization_servers": ["https://hol.org"]}}, "metadata_origin_mismatch"),
        (
            {"authorization_server": {"token_endpoint": "https://hol.org/api/guard/oauth/token"}},
            "metadata_origin_mismatch",
        ),
        ({"authorization_server": {"code_challenge_methods_supported": ["plain"]}}, "metadata_invalid"),
        ({"disabled": True}, "cloud_actions_not_enabled"),
    ],
    ids=["issuer", "resource", "authorization-server", "endpoint-origin", "no-s256", "not-enabled"],
)
def test_metadata_for_another_server_is_refused_before_the_browser_opens(
    cloud: FakeCloud,
    browser: Browser,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    overrides: dict[str, Any],
    reason: str,
) -> None:
    cloud.overrides.update(overrides)

    exit_code = _login(cloud, tmp_path)
    payload, _ = _json_out(capsys)

    assert exit_code == 1
    assert payload["state"] == "failed"
    assert payload["reason"] == reason
    assert browser.opened == []
    assert cloud.registrations == []
    assert not (tmp_path / "cloud-actions" / "profiles").exists()


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"claims": {"aud": "local-daemon"}}, "grant_audience_mismatch"),
        ({"claims": {"aud": "https://hol.org/api/guard/gateway/mcp"}}, "grant_audience_mismatch"),
        ({"claims": {"client_id": "hol-guard-local"}}, "grant_client_mismatch"),
        ({"token": {"scope": "gateway:discover guard:sync"}}, "grant_scope_mismatch"),
        ({"token": {"scope": ""}}, "grant_scope_mismatch"),
        ({"token": {"token_type": "DPoP"}}, "grant_invalid"),
        ({"claims": {"workspace": None}}, "grant_invalid"),
        ({"workspace": OTHER_WS}, "workspace_mismatch"),
    ],
    ids=[
        "local-daemon-audience",
        "other-cloud-audience",
        "other-client",
        "extra-scope",
        "no-scope",
        "not-bearer",
        "no-workspace",
        "other-workspace",
    ],
)
def test_a_grant_that_is_not_for_cloud_actions_is_revoked_and_not_saved(
    cloud: FakeCloud,
    browser: Browser,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    overrides: dict[str, Any],
    reason: str,
) -> None:
    cloud.overrides.update(overrides)

    exit_code = _login(cloud, tmp_path, "--cloud-workspace", WS)
    payload, output = _json_out(capsys)

    assert exit_code == 1
    assert payload["reason"] == reason
    assert not (tmp_path / "cloud-actions" / "profiles").exists()
    assert {entry["token"] for entry in cloud.revocations} == set(cloud.issued)
    for secret in cloud.issued:
        assert secret not in output


@pytest.mark.parametrize(
    ("callback", "reason"),
    [
        ({"iss": "https://hol.org"}, "callback_issuer_mismatch"),
        ({"iss": None}, "callback_issuer_mismatch"),
        ({"code": None, "error": "access_denied"}, "sign_in_declined"),
        ({"code": None, "error": "invalid_scope"}, "sign_in_refused"),
    ],
    ids=["other-issuer", "missing-issuer", "declined", "refused"],
)
def test_a_callback_that_fails_its_checks_never_reaches_the_token_endpoint(
    cloud: FakeCloud,
    browser: Browser,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    callback: dict[str, str | None],
    reason: str,
) -> None:
    browser.callback.update(callback)

    exit_code = _login(cloud, tmp_path)
    payload, _ = _json_out(capsys)

    assert exit_code == 1
    assert payload["reason"] == reason
    assert cloud.token_requests == []
    assert not (tmp_path / "cloud-actions" / "profiles").exists()


def test_a_callback_with_another_state_is_ignored(cloud: FakeCloud, tmp_path: Path) -> None:
    browser = Browser(cloud, callback={"state": "someone-elses-state"})

    with pytest.raises(CloudActionsSignInError) as raised:
        _ = sign_in(
            store=CloudActionsSessionStore(tmp_path),
            profile_name="default",
            cloud_url=cloud.origin,
            workspace_id=None,
            timeout_seconds=1,
            open_browser=browser,
            notice=io.StringIO(),
        )

    assert raised.value.reason == "sign_in_timed_out"
    assert browser.statuses == [400]
    assert cloud.token_requests == []


def test_cancelling_saves_nothing(
    cloud: FakeCloud, tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def interrupt(url: str) -> bool:
        del url
        raise KeyboardInterrupt

    monkeypatch.setattr(dispatch, "open_browser_url", interrupt)

    exit_code = _login(cloud, tmp_path)
    payload, _ = _json_out(capsys)

    assert exit_code == 130
    assert payload["state"] == "cancelled"
    assert cloud.token_requests == []
    assert not (tmp_path / "cloud-actions" / "profiles").exists()


def test_no_browser_prints_the_link_on_stderr_only(
    cloud: FakeCloud, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    store = CloudActionsSessionStore(tmp_path)
    notice = io.StringIO()
    browser = Browser(cloud)

    profile = sign_in(
        store=store,
        profile_name="default",
        cloud_url=cloud.origin,
        workspace_id=None,
        timeout_seconds=5,
        open_browser=lambda url: browser(url) and False,
        notice=notice,
    )

    assert profile.workspace_id == WS
    assert notice.getvalue().startswith("Open this link to sign in:\n")
    assert capsys.readouterr().out == ""


def test_profiles_keep_workspaces_apart(
    cloud: FakeCloud, browser: Browser, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _login(cloud, tmp_path, "--cloud-workspace", WS, "--profile", "work") == 0
    cloud.overrides["workspace"] = OTHER_WS
    assert _login(cloud, tmp_path, "--cloud-workspace", OTHER_WS, "--profile", "client") == 0
    capsys.readouterr()
    home = ("--guard-home", str(tmp_path), "--json")

    assert _cli("status", "--profile", "work", *home) == 0
    work, _ = _json_out(capsys)
    assert (work["state"], work["cloud_workspace"]) == ("signed_in", WS)
    assert _cli("status", "--profile", "work", "--cloud-workspace", OTHER_WS, *home) == 0
    assert _json_out(capsys)[0]["workspace_matches"] is False

    assert _cli("workspace", "select", OTHER_WS, "--profile", "work", *home) == 4
    refused, _ = _json_out(capsys)
    assert refused["reason"] == "workspace_needs_sign_in"
    assert refused["signed_in_workspace"] == WS
    assert _cli("workspace", "select", OTHER_WS, "--profile", "client", *home) == 0
    assert _json_out(capsys)[0]["state"] == "selected"
    assert _cli("status", *home) == 0
    assert _json_out(capsys)[0]["state"] == "signed_out"


def test_workspace_select_points_to_the_sign_in_command(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = _cli("workspace", "select", WS, "--profile", "work", "--guard-home", str(tmp_path))

    assert exit_code == 4
    assert f"hol-guard cloud-actions login --cloud-workspace {WS} --profile work" in capsys.readouterr().out


def test_signing_in_again_ends_the_previous_grant(
    cloud: FakeCloud, browser: Browser, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _login(cloud, tmp_path) == 0
    first_access, first_refresh = cloud.issued
    assert _login(cloud, tmp_path) == 0
    capsys.readouterr()

    assert {entry["token"] for entry in cloud.revocations} == {first_access, first_refresh}
    saved = CloudActionsSessionStore(tmp_path).load_secrets("default")
    assert saved is not None and saved.refresh_token == "refresh-secret-2"


def test_a_failed_sign_in_keeps_the_previous_one(
    cloud: FakeCloud, browser: Browser, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _login(cloud, tmp_path, "--cloud-workspace", WS) == 0
    cloud.overrides["workspace"] = OTHER_WS
    assert _login(cloud, tmp_path, "--cloud-workspace", WS) == 1
    capsys.readouterr()

    profile = CloudActionsSessionStore(tmp_path).load("default")
    assert profile is not None and profile.workspace_id == WS
    assert CloudActionsSessionStore(tmp_path).load_secrets("default") is not None


def test_logout_ends_the_grant_and_removes_it(
    cloud: FakeCloud, browser: Browser, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _login(cloud, tmp_path) == 0
    capsys.readouterr()

    assert _cli("logout", "--guard-home", str(tmp_path), "--json") == 0
    payload, _ = _json_out(capsys)

    assert (payload["was_signed_in"], payload["revoked"]) == (True, True)
    assert {entry["token_type_hint"] for entry in cloud.revocations} == {"refresh_token", "access_token"}
    store = CloudActionsSessionStore(tmp_path)
    assert store.load("default") is None
    assert store.load_secrets("default") is None


def test_status_reports_an_expired_sign_in(
    cloud: FakeCloud, browser: Browser, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _login(cloud, tmp_path) == 0
    capsys.readouterr()
    profile_file = tmp_path / "cloud-actions" / "profiles" / "default.json"
    record = json.loads(profile_file.read_text())
    record["expires_at"] = "2020-01-01T00:00:00Z"
    profile_file.write_text(json.dumps(record))

    assert _cli("status", "--guard-home", str(tmp_path), "--json") == 0

    assert _json_out(capsys)[0]["state"] == "expired"


def test_sign_in_leaves_the_device_sign_in_alone(
    cloud: FakeCloud, browser: Browser, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _login(cloud, tmp_path) == 0
    capsys.readouterr()

    top_level = {path.name for path in tmp_path.iterdir()}
    assert top_level <= {"cloud-actions", "secrets"}
    names = {path.name for path in (tmp_path / "secrets").iterdir() if not path.name.startswith(".")}
    assert names - {"key.bin"}, "the sign-in was not saved under secrets/"
    assert all(name == "key.bin" or name.startswith("cloud-actions-default-") for name in names)


@pytest.mark.parametrize(
    "url",
    [
        "https://guard.example.com",
        "http://hol.org",
        "https://user@hol.org",
        "ftp://127.0.0.1",
        "hol.org",
    ],
)
def test_only_hol_guard_cloud_or_this_computer_is_accepted(url: str) -> None:
    with pytest.raises(CloudActionsSignInError):
        _ = resolve_cloud_origin(url)


def test_cloud_url_is_reduced_to_its_origin() -> None:
    assert resolve_cloud_origin("https://hol.org/guard/connect") == "https://hol.org"
    assert resolve_cloud_origin("http://127.0.0.1:3017") == "http://127.0.0.1:3017"
