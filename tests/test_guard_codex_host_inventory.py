"""Existing-host inventory must authenticate its peer without starting servers."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import socket
import struct
import tempfile
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import codex_host_inventory as inventory

pytestmark = pytest.mark.skipif(os.name == "nt", reason="Codex host inventory requires Unix peer credentials")


@pytest.mark.parametrize(
    ("arguments", "expected"),
    [
        (b"/opt/codex/codex\0app-server\0", True),
        (b"/run/rosetta/rosetta\0/opt/codex/codex\0/opt/codex/codex\0app-server\0", True),
        (b"/run/rosetta/rosetta\0/opt/codex/codex\0/opt/other/codex\0app-server\0", False),
        (b"/run/rosetta/rosetta\0codex\0codex\0app-server\0", False),
        (b"/run/rosetta/rosetta\0/opt/other/tool\0/opt/other/tool\0app-server\0", False),
        (b"/run/rosetta/rosetta\0/opt/codex/codex\0/opt/codex/codex\0exec\0", False),
        (b"/opt/codex/codex\0" + b"x" * 65_536, False),
    ],
)
def test_translated_codex_process_layouts(monkeypatch: pytest.MonkeyPatch, arguments: bytes, expected: bool) -> None:
    monkeypatch.setattr(inventory.sys, "platform", "linux")
    monkeypatch.setattr(inventory.os, "readlink", lambda _path: "/run/rosetta/rosetta")
    monkeypatch.setattr(Path, "open", lambda _path, _mode: io.BytesIO(arguments))
    assert inventory._is_codex_process(123) is expected


def _exact(client: socket.socket, size: int) -> bytes:
    result = b""
    while len(result) < size:
        part = client.recv(size - len(result))
        if not part:
            raise EOFError
        result += part
    return result


def _request(client: socket.socket) -> dict[str, object]:
    first, second = _exact(client, 2)
    assert first == 0x81 and second & 0x80
    size = second & 0x7F
    if size == 126:
        size = struct.unpack("!H", _exact(client, 2))[0]
    elif size == 127:
        size = struct.unpack("!Q", _exact(client, 8))[0]
    mask = _exact(client, 4)
    payload = _exact(client, size)
    return json.loads(bytes(value ^ mask[index % 4] for index, value in enumerate(payload)))


def _send(client: socket.socket, message: dict[str, object]) -> None:
    payload = json.dumps(message).encode()
    header = bytes([0x81, len(payload)]) if len(payload) < 126 else bytes([0x81, 126]) + struct.pack("!H", len(payload))
    client.sendall(header + payload)


@contextmanager
def _host(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    handler: Callable[[dict[str, object]], dict[str, object]],
) -> Iterator[tuple[Path, list[dict[str, object]]]]:
    # Unix socket paths must fit macOS's 104-byte sockaddr_un limit as well.
    with tempfile.TemporaryDirectory(prefix="codex-", dir="/tmp") as directory:
        home = Path(directory) / ".codex"
        control = home / "app-server-control"
        control.mkdir(parents=True, mode=0o700)
        path = control / "app-server-control.sock"
        pid_path = control / "hol-guard-app-server.pid"
        pid_path.write_text(str(os.getpid()))
        pid_path.chmod(0o600)
        requests: list[dict[str, object]] = []
        failures: list[BaseException] = []
        monkeypatch.setattr(inventory, "_is_codex_process", lambda _pid: True)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(path))
        path.chmod(0o600)
        listener.listen(1)
        listener.settimeout(1)

        def serve() -> None:
            try:
                with listener.accept()[0] as client:
                    client.settimeout(2)
                    headers = b""
                    while not headers.endswith(b"\r\n\r\n"):
                        headers += _exact(client, 1)
                    key = next(
                        line.split(b": ", 1)[1]
                        for line in headers.split(b"\r\n")
                        if line.startswith(b"Sec-WebSocket-Key:")
                    )
                    accept = base64.b64encode(hashlib.sha1(key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest())
                    client.sendall(
                        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                        b"Sec-WebSocket-Accept: " + accept + b"\r\n\r\n"
                    )
                    while True:
                        request = _request(client)
                        requests.append(request)
                        if "id" in request:
                            _send(client, handler(request))
            except (TimeoutError, EOFError, BrokenPipeError, ConnectionResetError):
                pass
            except BaseException as error:
                failures.append(error)

        thread = threading.Thread(target=serve)
        thread.start()
        try:
            yield home, requests
        finally:
            thread.join(timeout=3)
            listener.close()
            path.unlink(missing_ok=True)
            assert not thread.is_alive()
            assert not failures


def _handler(request: dict[str, object]) -> dict[str, object]:
    method = request["method"]
    if method == "initialize":
        result = {"userAgent": "codex/0.159.2"}
    elif method == "app/installed":
        result = {"apps": [{"id": "example", "runtimeName": "example-runtime", "enabled": True, "callable": True}]}
    elif method == "app/read":
        result = {
            "apps": [
                {
                    "id": "example",
                    "name": "Example connector",
                    "tools": [
                        {
                            "name": "send_message",
                            "title": "Send a message",
                            "description": "Change external content",
                            "isReadOnly": True,
                            "inputSchema": {"type": "object"},
                        },
                    ],
                }
            ],
            "missingAppIds": [],
        }
    else:
        raise AssertionError("unexpected host method")
    return {"id": request["id"], "result": result}


def test_existing_host_is_kernel_authenticated_and_summaries_cannot_grant(tmp_path, monkeypatch):
    with _host(tmp_path, monkeypatch, _handler) as (home, requests):
        snapshot = inventory.read_codex_host_inventory(codex_home=home)
    assert [row["method"] for row in requests] == ["initialize", "initialized", "app/installed", "app/read"]
    assert requests[2]["params"] == {"forceRefresh": False}
    assert requests[3]["params"] == {"appIds": ["example"], "includeTools": True}
    assert len({row["id"] for row in requests if "id" in row}) == 3
    assert snapshot.apps[0]["name"] == "Example connector"
    assert snapshot.apps[0]["tools"] == [
        {"name": "send_message", "title": "Send a message", "description": "Change external content"}
    ]
    payload = snapshot.as_payload()
    assert payload["catalog_coverage"] == "host-summary"
    assert payload["schemas_available"] is False
    assert payload["account_verified"] is False
    assert payload["permissions_granted"] is False
    assert str(home) not in json.dumps(payload)


@pytest.mark.parametrize("wrong_peer", ["pid", "uid", "process"])
def test_wrong_host_or_user_rejected_before_handshake(tmp_path, monkeypatch, wrong_peer):
    with _host(tmp_path, monkeypatch, _handler) as (home, requests):
        if wrong_peer == "process":
            monkeypatch.setattr(inventory, "_is_codex_process", lambda _pid: False)
        else:
            monkeypatch.setattr(
                inventory,
                "_peer_identity",
                lambda _client: (
                    os.geteuid() + (wrong_peer == "uid"),
                    os.getpid() + (wrong_peer == "pid"),
                ),
            )
        with pytest.raises(ValueError, match="codex_host_untrusted"):
            inventory.read_codex_host_inventory(codex_home=home)
    assert requests == []


@pytest.mark.parametrize("fault", ["replay", "foreign_app", "missing_app", "duplicate_app", "duplicate_tool", "error"])
def test_replay_and_malformed_pages_fail_atomically(tmp_path, monkeypatch, fault):
    previous: list[object] = []

    def handler(request):
        response = _handler(request)
        if request["method"] == "app/read":
            if fault == "replay":
                response["id"] = previous[0]
            elif fault == "foreign_app":
                response["result"]["apps"][0]["id"] = "another-account"
            elif fault == "missing_app":
                response["result"]["apps"] = []
            elif fault == "duplicate_app":
                response["result"]["apps"] *= 2
            elif fault == "duplicate_tool":
                response["result"]["apps"][0]["tools"] *= 2
            elif fault == "error":
                response = {"id": request["id"], "error": {"message": "private host details"}}
        previous.append(request["id"])
        return response

    with (
        _host(tmp_path, monkeypatch, handler) as (home, _requests),
        pytest.raises(ValueError, match=r"codex_host_(invalid|unavailable)"),
    ):
        inventory.read_codex_host_inventory(codex_home=home)


def test_missing_metadata_is_explicit_without_losing_host_runtime_state(tmp_path, monkeypatch):
    def handler(request):
        response = _handler(request)
        if request["method"] == "app/read":
            response["result"] = {"apps": [], "missingAppIds": ["example"]}
        return response

    with _host(tmp_path, monkeypatch, handler) as (home, _requests):
        snapshot = inventory.read_codex_host_inventory(codex_home=home)
    assert snapshot.metadata_complete is False
    assert snapshot.apps[0]["callable"] is True
    assert snapshot.apps[0]["metadata_available"] is False
    assert snapshot.apps[0]["tools"] == []


def test_reconnect_during_metadata_read_invalidates_snapshot(tmp_path, monkeypatch):
    home_ref: list[Path] = []

    def handler(request):
        if request["method"] == "app/read":
            (home_ref[0] / "app-server-control" / "hol-guard-app-server.pid").write_text(str(os.getpid() + 1))
        return _handler(request)

    with _host(tmp_path, monkeypatch, handler) as (home, _requests):
        home_ref.append(home)
        with pytest.raises(ValueError, match="codex_host_changed"):
            inventory.read_codex_host_inventory(codex_home=home)


def test_missing_host_and_cancellation_never_launch_processes(tmp_path, monkeypatch):
    monkeypatch.setattr(inventory.subprocess, "Popen", lambda *args, **kwargs: pytest.fail("process start forbidden"))
    with pytest.raises(ValueError, match="codex_host_unavailable"):
        inventory.read_codex_host_inventory(codex_home=tmp_path)
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(ValueError, match="codex_host_cancelled"):
        inventory.read_codex_host_inventory(codex_home=tmp_path, cancel=cancel)


def test_unsupported_platform_returns_explicit_fallback_without_socket_access(tmp_path, monkeypatch):
    monkeypatch.setattr(inventory.sys, "platform", "win32")
    monkeypatch.setattr(inventory, "_socket_target", lambda _path: pytest.fail("unsupported host socket accessed"))
    with pytest.raises(ValueError, match="codex_host_unsupported"):
        inventory.read_codex_host_inventory(codex_home=tmp_path)


def test_public_metadata_pages_are_bounded_and_preserve_all_installed_apps(tmp_path, monkeypatch):
    def handler(request):
        if request["method"] == "app/installed":
            result = {"apps": [{"id": f"app_{index}", "enabled": True, "callable": False} for index in range(101)]}
        elif request["method"] == "app/read":
            ids = request["params"]["appIds"]
            result = {"apps": [{"id": app_id, "name": app_id, "tools": []} for app_id in ids], "missingAppIds": []}
        else:
            return _handler(request)
        return {"id": request["id"], "result": result}

    with _host(tmp_path, monkeypatch, handler) as (home, requests):
        snapshot = inventory.read_codex_host_inventory(codex_home=home)
    assert len(snapshot.apps) == 101
    assert [len(row["params"]["appIds"]) for row in requests if row["method"] == "app/read"] == [100, 1]
    assert snapshot.apps[-1]["app_id"] == "app_100"
    assert snapshot.metadata_complete is True


@pytest.mark.parametrize("value", [" example", "example\n", "example tool", "\x00example"])
def test_identifiers_are_not_normalized_into_another_connection(value):
    with pytest.raises(ValueError, match="codex_host_invalid"):
        inventory._installed_apps({"apps": [{"id": value, "enabled": True, "callable": True}]})


def test_empty_display_descriptions_are_valid_but_annotations_are_not_authority():
    apps = inventory._installed_apps({"apps": [{"id": "example", "enabled": True, "callable": False}]})
    assert (
        inventory._merge_metadata(
            apps,
            {
                "apps": [
                    {
                        "id": "example",
                        "name": "Example",
                        "tools": [
                            {"name": "delete", "description": "", "isReadOnly": True, "isEnabled": True},
                        ],
                    }
                ],
                "missingAppIds": [],
            },
        )
        is True
    )
    assert apps[0]["tools"] == [{"name": "delete", "title": None, "description": None}]
    assert apps[0]["callable"] is False


def test_private_socket_alias_is_pinned_to_authenticated_target(tmp_path, monkeypatch):
    with _host(tmp_path, monkeypatch, _handler) as (home, _requests):
        path = home / "app-server-control" / "app-server-control.sock"
        target = path.with_name("daemon.sock")
        path.rename(target)
        path.symlink_to(target)
        snapshot = inventory.read_codex_host_inventory(codex_home=home)
    assert snapshot.apps[0]["app_id"] == "example"


def test_socket_alias_to_a_shared_directory_is_rejected(tmp_path, monkeypatch):
    with _host(tmp_path, monkeypatch, _handler) as (home, _requests):
        path = home / "app-server-control" / "app-server-control.sock"
        shared = home.parent / "shared"
        shared.mkdir(mode=0o755)
        target = shared / "daemon.sock"
        path.rename(target)
        path.symlink_to(target)
        with pytest.raises(ValueError, match="codex_host_untrusted"):
            inventory.read_codex_host_inventory(codex_home=home)


def test_public_cache_never_reads_rpc_on_listing_and_invalidates_reconnect(tmp_path, monkeypatch):
    cache = inventory.CodexHostInventoryCache()
    with _host(tmp_path, monkeypatch, _handler) as (home, requests):
        cache.refresh(codex_home=home, cancel=threading.Event())
        before = len(requests)
        payload = cache.read()
        assert payload is not None
        payload["apps"].clear()
        assert len(cache.read()["apps"]) == 1
        assert len(requests) == before
        (home / "app-server-control" / "hol-guard-app-server.pid").write_text(str(os.getpid() + 1))
        assert cache.read() is None
    cache.refresh(codex_home=tmp_path / "unavailable", cancel=threading.Event())
    assert cache.read() is None


@pytest.mark.parametrize("outcome", ["success", "failure", "cancelled", "cancelled-during-read"])
def test_refresh_keeps_valid_public_snapshot_visible_until_result(tmp_path, monkeypatch, outcome):
    cache = inventory.CodexHostInventoryCache()
    with _host(tmp_path, monkeypatch, _handler) as (home, _requests):
        cache.refresh(codex_home=home, cancel=threading.Event())
        payload = cache.read()
        assert payload is not None
        snapshot = inventory.CodexHostInventory(payload["connection_id"], tuple(payload["apps"]), True)
        entered, release, cancel = threading.Event(), threading.Event(), threading.Event()

        def slow_read(**_kwargs):
            entered.set()
            assert release.wait(2)
            if outcome == "failure":
                raise ValueError("codex_host_unavailable")
            if outcome.startswith("cancelled"):
                cancel.set()
                if outcome == "cancelled-during-read":
                    raise ValueError("codex_host_cancelled")
            return snapshot

        monkeypatch.setattr(inventory, "read_codex_host_inventory", slow_read)
        failures = []

        def refresh():
            try:
                cache.refresh(codex_home=home, cancel=cancel)
            except ValueError as error:
                failures.append(str(error))

        worker = threading.Thread(target=refresh)
        worker.start()
        try:
            assert entered.wait(2)
            assert cache.read() == payload
        finally:
            release.set()
            worker.join(2)
        assert not worker.is_alive()
        if outcome == "failure":
            assert cache.read() is None
            assert failures == ["codex_host_unavailable"]
        elif outcome == "success":
            current = cache.read()
            assert current["expires_at_ms"] >= payload["expires_at_ms"]
            assert {key: value for key, value in current.items() if key != "expires_at_ms"} == {
                key: value for key, value in payload.items() if key != "expires_at_ms"
            }
        else:
            assert cache.read() == payload
            assert not failures
            monkeypatch.setattr(inventory, "_SNAPSHOT_TTL", -1)
            assert cache.read() is None


def test_expired_public_cache_is_not_presented_as_current(tmp_path, monkeypatch):
    cache = inventory.CodexHostInventoryCache()
    with _host(tmp_path, monkeypatch, _handler) as (home, _requests):
        cache.refresh(codex_home=home, cancel=threading.Event())
        assert cache.read() is not None
        monkeypatch.setattr(inventory, "_SNAPSHOT_TTL", -1)
        assert cache.read() is None


@pytest.mark.parametrize(
    "reason", ["codex_host_timeout", "codex_host_untrusted", "codex_host_invalid", "private injected details"]
)
def test_host_refresh_failure_is_visible_and_logs_only_reason_code(tmp_path, monkeypatch, caplog, reason):
    def fail(**_kwargs):
        raise ValueError(reason)

    monkeypatch.setattr(inventory, "read_codex_host_inventory", fail)
    cache = inventory.CodexHostInventoryCache()
    expected = reason if reason in inventory._FAILURE_CODES else "codex_host_invalid"
    with pytest.raises(ValueError, match=expected):
        cache.refresh(codex_home=tmp_path, cancel=threading.Event())
    assert expected in caplog.text
    assert "private injected details" not in caplog.text
    assert cache.read() is None


def test_failed_host_snapshot_marks_background_job_failed(tmp_path, monkeypatch):
    from codex_plugin_scanner.guard.daemon.local_cli_api import LocalCliApiService
    from codex_plugin_scanner.guard.store import GuardStore

    def fail(**_kwargs):
        raise ValueError("codex_host_untrusted")

    monkeypatch.setattr(inventory, "read_codex_host_inventory", fail)
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    store = GuardStore(tmp_path / "guard")
    service = LocalCliApiService(store=store)
    before = store.read_local_cli_revision()
    try:
        job = service.refresh_job({"operation": "codex-host-connections"})
        deadline = inventory.time.monotonic() + 3
        while inventory.time.monotonic() < deadline:
            state = service.refresh_job({"job_id": job["job_id"]})
            if state["state"] not in {"running", "cancelling"}:
                break
            inventory.time.sleep(0.01)
        assert state["state"] == "failed"
        assert state["error"] == "discovery_failed"
        assert service.list_items()["host_inventory"] is None
        assert store.read_local_cli_revision() == before
    finally:
        assert service._discovery_jobs.close()


def test_shared_depth_scanner_keeps_each_rpc_limit_and_ignores_string_brackets():
    from codex_plugin_scanner.guard.runtime.codex_config_rpc import _check_json_depth

    quoted = json.dumps({"text": "[" * 100 + '\\"' + "]" * 100}).encode()
    _check_json_depth(quoted)
    inventory._check_depth(quoted)
    moderate = b"[" * 33 + b"0" + b"]" * 33
    _check_json_depth(moderate)
    with pytest.raises(ValueError, match="codex_host_limit"):
        inventory._check_depth(moderate)
    excessive = b"[" * 65 + b"0" + b"]" * 65
    with pytest.raises(ValueError, match="codex_config_rpc_invalid"):
        _check_json_depth(excessive)
    for malformed in (b"]", b"}" * 64 + excessive, b"]" * 32 + moderate):
        with pytest.raises(ValueError, match="codex_config_rpc_invalid"):
            _check_json_depth(malformed)
        with pytest.raises(ValueError, match="codex_host_limit"):
            inventory._check_depth(malformed)


def test_background_host_inventory_is_not_persisted_or_enrolled_as_a_grant(tmp_path, monkeypatch):
    from codex_plugin_scanner.guard.daemon.local_cli_api import LocalCliApiService
    from codex_plugin_scanner.guard.store import GuardStore

    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    store = GuardStore(tmp_path / "guard")
    service = LocalCliApiService(store=store)
    before = store.read_local_cli_revision()
    try:
        with _host(tmp_path, monkeypatch, _handler) as (_home, _requests):
            monkeypatch.setattr(Path, "home", staticmethod(lambda: _home.parent))
            job = service.refresh_job({"operation": "codex-host-connections"})
            deadline = inventory.time.monotonic() + 3
            while inventory.time.monotonic() < deadline:
                state = service.refresh_job({"job_id": job["job_id"]})
                if state["state"] not in {"running", "cancelling"}:
                    break
                inventory.time.sleep(0.01)
            assert state["state"] == "complete", state
            payload = service.list_items()
            assert payload["host_inventory"]["apps"][0]["name"] == "Example connector"
            assert payload["host_inventory"]["permissions_granted"] is False
            assert payload["items"] == []
            assert store.read_local_cli_revision() == before
        assert service.list_items()["host_inventory"] is None
    finally:
        assert service._discovery_jobs.close()


def test_stalled_host_snapshot_does_not_delay_configured_discovery(tmp_path, monkeypatch):
    from codex_plugin_scanner.guard.daemon.local_cli_api import LocalCliApiService
    from codex_plugin_scanner.guard.store import GuardStore

    store = GuardStore(tmp_path / "guard")
    service = LocalCliApiService(store=store)
    entered = threading.Event()

    def stalled(*, codex_home, cancel):
        entered.set()
        assert cancel.wait(3)

    monkeypatch.setattr(service._codex_host_inventory, "refresh", stalled)
    monkeypatch.setattr(service, "_observe_harness_mcp_servers", lambda **_kwargs: {})
    try:
        host_job = service.refresh_job({"operation": "codex-host-connections"})
        assert entered.wait(1)
        configured = service.refresh_job({"operation": "configured-connections"})
        deadline = inventory.time.monotonic() + 1
        while inventory.time.monotonic() < deadline:
            state = service.refresh_job({"job_id": configured["job_id"]})
            if state["state"] not in {"running", "cancelling"}:
                break
            inventory.time.sleep(0.01)
        assert state["state"] == "complete"
        assert service.refresh_job({"job_id": host_job["job_id"]})["state"] == "running"
    finally:
        assert service._discovery_jobs.close()


@pytest.mark.parametrize("unsafe", ["symlink", "permissions"])
def test_pid_record_must_be_private_and_not_symlinked(tmp_path, unsafe):
    control = tmp_path / "app-server-control"
    control.mkdir(mode=0o700)
    record = control / "hol-guard-app-server.pid"
    if unsafe == "symlink":
        target = tmp_path / "target"
        target.write_text(str(os.getpid()))
        record.symlink_to(target)
        with pytest.raises(OSError):
            inventory._managed_pid(control / "socket")
    else:
        record.write_text(str(os.getpid()))
        record.chmod(0o644)
        with pytest.raises(ValueError, match="codex_host_untrusted"):
            inventory._managed_pid(control / "socket")
