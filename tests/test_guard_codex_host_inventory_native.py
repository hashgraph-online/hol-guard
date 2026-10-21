"""Native Codex daemon protocol and cache regressions."""

import os
import subprocess
import threading

import pytest

from codex_plugin_scanner.guard.runtime import codex_host_inventory as inventory
from tests.codex_host_inventory_support import _handler, _host

pytestmark = pytest.mark.skipif(os.name == "nt", reason="Codex host inventory requires Unix peer credentials")


def test_codex_owned_daemon_without_guard_pid_record(tmp_path, monkeypatch):
    def handler(request):
        response = _handler(request)
        if request["method"] == "app/read":
            app = response["result"]["apps"][0]
            app["toolSummaries"] = app.pop("tools")
        return response

    cache = inventory.CodexHostInventoryCache()
    with _host(tmp_path, monkeypatch, handler) as (home, requests):
        (home / "app-server-control" / "hol-guard-app-server.pid").unlink()
        cache.refresh(codex_home=home, cancel=threading.Event())
        payload = cache.read()
        assert payload is not None
        assert payload["apps"][0]["tools"][0]["name"] == "send_message"
        assert payload["permissions_granted"] is False
        assert "host_pid" not in payload
        assert [row["method"] for row in requests] == ["initialize", "initialized", "app/installed", "app/read"]
        monkeypatch.setattr(inventory, "_is_codex_process", lambda _pid: pytest.fail("cache spawned process check"))
        for _ in range(5):
            assert cache.read() is not None
        marker = home / "app-server-control" / "hol-guard-app-server.pid"
        marker.write_text(str(os.getpid()))
        marker.chmod(0o600)
        assert cache.read() is None


@pytest.mark.parametrize("wrong_peer", ["uid", "process"])
def test_codex_owned_daemon_still_authenticates_peer(tmp_path, monkeypatch, wrong_peer):
    with _host(tmp_path, monkeypatch, _handler) as (home, requests):
        (home / "app-server-control" / "hol-guard-app-server.pid").unlink()
        if wrong_peer == "process":
            monkeypatch.setattr(inventory, "_is_codex_process", lambda _pid: False)
        else:
            monkeypatch.setattr(inventory, "_peer_identity", lambda _client: (os.geteuid() + 1, os.getpid()))
        with pytest.raises(ValueError, match="codex_host_untrusted"):
            inventory.read_codex_host_inventory(codex_home=home)
    assert requests == []


def test_dangling_pid_marker_is_not_treated_as_native_host(tmp_path):
    control = tmp_path / "app-server-control"
    control.mkdir(mode=0o700)
    (control / "hol-guard-app-server.pid").symlink_to(tmp_path / "missing")
    with pytest.raises(OSError):
        inventory._optional_managed_pid(control / "socket")


def test_protocol_tool_summaries_bound_long_display_text(tmp_path, monkeypatch):
    def handler(request):
        response = _handler(request)
        if request["method"] == "app/read":
            app = response["result"]["apps"][0]
            app["toolSummaries"] = app.pop("tools")
            app["toolSummaries"][0].update(title="t" * 700, description="d" * 9030)
        return response

    with _host(tmp_path, monkeypatch, handler) as (home, _requests):
        snapshot = inventory.read_codex_host_inventory(codex_home=home)
    assert snapshot.metadata_complete
    tool = snapshot.apps[0]["tools"][0]
    assert len(tool["title"]) == 512
    assert len(tool["description"]) == 4000
    assert "inputSchema" not in tool


@pytest.mark.parametrize("missing", [False, True])
def test_unavailable_tool_summaries_keep_app_but_not_complete(tmp_path, monkeypatch, missing):
    def handler(request):
        response = _handler(request)
        if request["method"] == "app/read":
            app = response["result"]["apps"][0]
            if missing:
                app.pop("tools")
            else:
                app["toolSummaries"] = None
        return response

    with _host(tmp_path, monkeypatch, handler) as (home, _requests):
        snapshot = inventory.read_codex_host_inventory(codex_home=home)
    assert not snapshot.metadata_complete
    assert snapshot.apps[0]["tools"] == []
    assert snapshot.apps[0]["metadata_available"] is False


def test_managed_marker_removal_invalidates_snapshot(tmp_path, monkeypatch):
    cache = inventory.CodexHostInventoryCache()
    with _host(tmp_path, monkeypatch, _handler) as (home, _requests):
        cache.refresh(codex_home=home, cancel=threading.Event())
        assert cache.read() is not None
        (home / "app-server-control" / "hol-guard-app-server.pid").unlink()
        assert cache.read() is None


def test_native_peer_process_timeout_is_a_bounded_refresh_failure(tmp_path, monkeypatch):
    def timeout(_pid):
        raise subprocess.TimeoutExpired("ps", 1)

    cache = inventory.CodexHostInventoryCache()
    with _host(tmp_path, monkeypatch, _handler) as (home, requests):
        (home / "app-server-control" / "hol-guard-app-server.pid").unlink()
        monkeypatch.setattr(inventory, "_is_codex_process", timeout)
        with pytest.raises(ValueError, match="codex_host_unavailable"):
            cache.refresh(codex_home=home, cancel=threading.Event())
        assert cache.read() is None
    assert requests == []
