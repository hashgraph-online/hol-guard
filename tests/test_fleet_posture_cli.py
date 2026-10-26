"""CLI surface for fleet posture: settings opt-out, cloud status and inventory --sync."""

from __future__ import annotations

import io
import json
import urllib.error
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
from codex_plugin_scanner.guard.runtime import fleet_posture as fp
from codex_plugin_scanner.guard.runtime import runner as guard_runner_module
from codex_plugin_scanner.guard.store import GuardStore
from tests.support.network import stub_authenticated_urlopen

pytestmark = [pytest.mark.usefixtures("native_hook_force")]


def _run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    rc = main(["guard", *argv])
    captured = capsys.readouterr()
    return rc, captured.out, captured.err


def _seed_cloud(store: GuardStore) -> None:
    key_material = generate_dpop_key_pair()
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="demo-token",
        dpop_private_key_pem=key_material.private_key_pem,
        dpop_public_jwk=key_material.public_jwk,
        dpop_public_jwk_thumbprint=key_material.public_jwk_thumbprint,
        grant_id="grant-1",
        machine_id="machine-1",
        workspace_id="workspace-1",
        now="2026-05-19T00:00:00Z",
    )
    guard_runner_module._test_sync_auth_context_override = {
        "sync_url": "https://hol.org/api/guard/receipts/sync",
        "access_token": "demo-token",
        "dpop_key_material": None,
    }


@pytest.fixture(autouse=True)
def _clear_auth_override():
    yield
    guard_runner_module._test_sync_auth_context_override = None


def test_settings_set_fleet_posture_off_then_on(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home = tmp_path / "home"
    rc, out, _ = _run(capsys, "settings", "set", "fleet-posture", "off", "--home", str(home), "--json")
    assert rc == 0
    assert json.loads(out)["fleet_posture"] == "off"
    assert fp.fleet_posture_opted_out(GuardStore(home))

    rc, out, _ = _run(capsys, "settings", "set", "fleet-posture", "on", "--home", str(home), "--json")
    assert rc == 0
    assert json.loads(out)["fleet_posture"] == "on"
    assert not fp.fleet_posture_opted_out(GuardStore(home))


def test_settings_set_fleet_posture_off_is_refused_on_managed_installs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fp, "fleet_posture_managed", lambda _config: True)
    home = tmp_path / "home"
    rc, out, _ = _run(capsys, "settings", "set", "fleet-posture", "off", "--home", str(home), "--json")
    payload = json.loads(out)
    assert rc == 2
    assert payload["managed"] is True
    assert "cannot be turned off" in payload["error"]
    assert not fp.fleet_posture_opted_out(GuardStore(home))


def test_cloud_status_offline_flag_prints_local_summary_only(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "home"
    rc, out, _ = _run(capsys, "cloud", "status", "--home", str(home), "--offline", "--json")
    payload = json.loads(out)
    assert rc == 0
    assert "cloud_sees" not in payload
    assert payload["fleet_posture"]["last_sent"] is None
    assert payload["fleet_posture"]["reporting"] == "full"


def test_cloud_status_when_not_signed_in_is_a_plain_message(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home = tmp_path / "home"
    rc, out, _ = _run(capsys, "cloud", "status", "--home", str(home))
    assert rc == 0
    assert "Last sync: never" in out
    assert "Not signed in to Guard Cloud" in out


def test_cloud_status_reports_what_the_cloud_sees(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    _seed_cloud(GuardStore(home))
    seen_urls: list[str] = []
    machine = {
        "guardVersion": "3.47.0",
        "os": "macos",
        "aiTools": [{"harness": "claude-code", "protectionState": "protected"}],
    }

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self) -> bytes:
            return json.dumps(machine).encode("utf-8")

    def fake_urlopen(request, timeout):
        seen_urls.append(request.full_url)
        return _Response()

    stub_authenticated_urlopen(monkeypatch, fake_urlopen)

    rc, out, _ = _run(capsys, "cloud", "status", "--home", str(home), "--json")
    payload = json.loads(out)

    assert rc == 0
    assert seen_urls == ["https://hol.org/api/guard/v1/fleet/machines/self"]
    assert payload["cloud_sees"]["status"] == "ok"
    assert payload["cloud_sees"]["machine"]["aiTools"][0]["protectionState"] == "protected"


@pytest.mark.parametrize(
    ("failure", "expected_status"),
    [
        (urllib.error.HTTPError("https://hol.org", 404, "Not Found", {}, io.BytesIO(b"{}")), "not_supported"),
        (urllib.error.HTTPError("https://hol.org", 500, "Server Error", {}, io.BytesIO(b"{}")), "unavailable"),
        (urllib.error.URLError("no route"), "offline"),
    ],
)
def test_cloud_status_degrades_gracefully(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    failure: Exception,
    expected_status: str,
) -> None:
    home = tmp_path / "home"
    _seed_cloud(GuardStore(home))

    def fake_urlopen(request, timeout):
        raise failure

    stub_authenticated_urlopen(monkeypatch, fake_urlopen)

    rc, out, _ = _run(capsys, "cloud", "status", "--home", str(home), "--json")
    payload = json.loads(out)

    assert rc == 0
    assert payload["cloud_sees"]["status"] == expected_status
    assert payload["cloud_sees"]["message"]


def test_inventory_sync_flag_queues_a_full_inventory(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    rc, out, _ = _run(capsys, "inventory", "--home", str(home), "--workspace", str(workspace), "--json")
    assert rc == 0
    assert "fleet_posture" not in json.loads(out)
    assert not fp.full_inventory_requested(GuardStore(home))

    rc, out, _ = _run(capsys, "inventory", "--home", str(home), "--workspace", str(workspace), "--json", "--sync")
    assert rc == 0
    assert json.loads(out)["fleet_posture"] == {"next_sync_inventory": "full"}
    assert fp.full_inventory_requested(GuardStore(home))
