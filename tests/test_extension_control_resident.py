"""The extension-control routes the native daemon answers from its resident library process."""

from __future__ import annotations

import json
import subprocess
import sys
import urllib.request
from pathlib import Path

import pytest

from ci.native_daemon_harness import NativeGuardDaemon
from codex_plugin_scanner.guard import extension_control_host
from codex_plugin_scanner.guard.extension_control_host import extension_control, host_for
from codex_plugin_scanner.guard.library_calls import LibraryCallError, run_library_call
from codex_plugin_scanner.guard.store import GuardStore


@pytest.fixture(autouse=True)
def _fresh_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(extension_control_host, "_HOSTS", {})


def test_one_process_keeps_one_host_per_guard_home(tmp_path: Path) -> None:
    # A preview's proof waits in this host for its apply, so every call in
    # the resident process must reach the same one.
    home = tmp_path / "guard-home"
    first = host_for(GuardStore(home))

    assert host_for(GuardStore(home)) is first
    assert host_for(GuardStore(tmp_path / "other-home")) is not first


def test_reads_answer_with_no_store(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")

    for path in ("/v1/extension-controls/effective", "/v1/extension-controls/catalog"):
        reply = extension_control(store, {"method": "GET", "path": path})
        assert reply["status"] == 200
        assert reply["no_store"] is True
        assert isinstance(reply["body"], dict)


def test_refresh_serves_the_effective_controls(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    effective = extension_control(store, {"method": "GET", "path": "/v1/extension-controls/effective"})

    refreshed = extension_control(store, {"method": "POST", "path": "/v1/extension-controls/refresh", "payload": {}})

    assert refreshed["status"] == 200
    assert refreshed["body"]["catalog_digest"] == effective["body"]["catalog_digest"]


def test_a_refused_request_keeps_the_service_status(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")

    reply = extension_control(store, {"method": "POST", "path": "/v1/extension-controls/apply", "payload": {}})

    assert reply["status"] >= 400
    assert reply["no_store"] is False
    assert "error" in reply["body"]


@pytest.mark.parametrize(
    "args",
    [
        {"method": "GET", "path": "/v1/extension-controls/apply"},
        {"method": "POST", "path": "/v1/extension-controls/catalog", "payload": {}},
        {"method": "DELETE", "path": "/v1/extension-controls/effective"},
        {"method": "POST", "path": "/v1/extension-controls/preview", "payload": []},
    ],
)
def test_requests_the_service_does_not_answer_are_refused(tmp_path: Path, args: dict[str, object]) -> None:
    with pytest.raises(LibraryCallError):
        extension_control(GuardStore(tmp_path / "guard-home"), args)


def test_the_call_is_registered(tmp_path: Path) -> None:
    request = {"call": "route.extension_control", "args": {"method": "GET", "path": "/v1/extension-controls/history"}}

    answer = run_library_call(tmp_path / "guard-home", json.dumps(request).encode())

    assert answer["ok"]["status"] == 200


def test_native_daemon_answers_the_reads(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    with NativeGuardDaemon(store, home_dir=tmp_path) as daemon:
        for path in ("/v1/extension-controls/effective", "/v1/extension-controls/catalog"):
            request = urllib.request.Request(
                f"{daemon.base_url}{path}", headers={"X-Guard-Token": daemon.auth_token}
            )
            with urllib.request.urlopen(request, timeout=30) as response:
                assert response.status == 200
                assert response.headers["Cache-Control"] == "no-store"
                assert isinstance(json.loads(response.read()), dict)
        refresh = urllib.request.Request(
            f"{daemon.base_url}/v1/extension-controls/refresh",
            data=b"{}",
            method="POST",
            headers={"X-Guard-Token": daemon.auth_token, "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(refresh, timeout=30) as response:
            assert response.status == 200
            assert "catalog_digest" in json.loads(response.read())
        if sys.platform != "win32":
            # The daemon answered from its resident library process, not a relay.
            listed = subprocess.run(["ps", "-ax", "-o", "command="], capture_output=True, text=True, check=True)
            assert any(
                "library-serve" in line and str(store.guard_home) in line for line in listed.stdout.splitlines()
            )
