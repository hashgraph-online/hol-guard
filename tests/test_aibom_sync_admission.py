"""Inventory admission uses actual collection, stores and platform locks."""

from __future__ import annotations

import io
import json
import subprocess
import sys
import threading
import urllib.error
from collections.abc import Callable
from datetime import datetime, timezone
from email.message import Message
from pathlib import Path
from queue import Queue
from typing import Any

import pytest

from codex_plugin_scanner.guard import aibom_cli, store_connection_schema
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.aibom_operation_authority import capture_aibom_operation, commit_aibom_results
from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.store import GuardStore


@pytest.fixture(autouse=True)
def _no_raw_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def denied(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Unexpected raw network operation")

    monkeypatch.setattr("socket.create_connection", denied)
    monkeypatch.setattr("socket.socket.connect", denied)


def _fixture(tmp_path: Path) -> tuple[GuardStore, HarnessContext, dict[str, Any], dict[str, Any]]:
    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True)
    (home / ".codex").mkdir(parents=True)
    (home / ".codex/config.toml").write_text('[mcp_servers.generic]\ncommand="node"\nargs=["server.js"]\n')
    store = GuardStore(tmp_path / "guard", allow_system_keyring=False)
    key = generate_dpop_key_pair()
    now = datetime.now(timezone.utc).isoformat()
    credentials: dict[str, Any] = {
        "issuer": "https://hol.org",
        "client_id": "guard-local-daemon",
        "refresh_token": "synthetic-refresh",
        "access_token": "synthetic-access",
        "access_token_expires_at": "2099-01-01T00:00:00Z",
        "dpop_private_key_pem": key.private_key_pem,
        "dpop_public_jwk": key.public_jwk,
        "dpop_public_jwk_thumbprint": key.public_jwk_thumbprint,
        "grant_id": "grant-alpha",
        "machine_id": "machine-alpha",
        "workspace_id": "workspace-alpha",
        "now": now,
    }
    store.set_oauth_local_credentials(**credentials)
    args: dict[str, Any] = {
        "generated_at": now,
        "options": aibom_cli.AibomCliOptions(),
        "auth_context": {
            "sync_url": "https://hol.org/api/guard/receipts/sync",
            "access_token": "synthetic-access",
            "dpop_key_material": key,
        },
        "expected_workspace_id": "workspace-alpha",
    }
    return store, HarnessContext(home_dir=home, workspace_dir=workspace, guard_home=store.guard_home), args, credentials


def _bound_result(store: GuardStore, context: HarnessContext, key: str, payload: dict[str, object], now: str) -> None:
    operation = capture_aibom_operation(store, context, now=now, bind_installation=True)
    assert operation is not None
    assert commit_aibom_results(store, operation, {key: payload}, now=now)


class _Response(io.BytesIO):
    status = 200

    def __init__(self, request: Any, now: str):
        self.headers: dict[str, str] = {}
        events = json.loads(request.data)["events"]
        assert request.full_url.endswith("/api/v1/guard/events")
        assert events
        super().__init__(json.dumps({"accepted": len(events), "rejected": 0, "statuses": [], "syncedAt": now}).encode())

    def getcode(self) -> int:
        return 200


def _automatic(store: GuardStore, context: HarnessContext, args: dict[str, Any], *, force: bool = False):
    return aibom_cli.sync_aibom_snapshots_if_due(
        store,
        **args,
        force=force,
        min_interval_seconds=60,
        home_dir=context.home_dir,
        workspace_dir=context.workspace_dir,
    )


def _start(call: Callable[[], object], name: str = "waiter") -> tuple[threading.Thread, Queue[object]]:
    result: Queue[object] = Queue()

    def invoke() -> None:
        try:
            result.put(call())
        except BaseException as error:
            result.put(error)

    thread = threading.Thread(target=invoke, name=name, daemon=True)
    thread.start()
    return thread, result


def _finish(worker: tuple[threading.Thread, Queue[object]]) -> dict[str, object]:
    thread, result = worker
    thread.join(timeout=10)
    assert not thread.is_alive()
    value = result.get_nowait()
    if isinstance(value, BaseException):
        raise value
    assert isinstance(value, dict)
    return value


def _observe_waiter(monkeypatch: pytest.MonkeyPatch) -> threading.Event:
    blocked = threading.Event()
    original: Callable[[Any], None] = vars(store_connection_schema)["_acquire_advisory_file_lock"]

    def acquire(handle: Any) -> None:
        try:
            original(handle)
        except BlockingIOError:
            if threading.current_thread().name == "waiter" and Path(handle.name).name == "aibom-sync.lock":
                blocked.set()
            raise

    monkeypatch.setattr(store_connection_schema, "_acquire_advisory_file_lock", acquire)
    return blocked


@pytest.mark.parametrize("second_mode", ["automatic", "force", "direct"])
@pytest.mark.parametrize("first_outcome", ["success", "failure"])
def test_actual_upload_serializes_entrypoints_and_rechecks_predecessor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, second_mode: str, first_outcome: str
) -> None:
    store, context, args, _ = _fixture(tmp_path)
    peer = GuardStore(store.guard_home, allow_system_keyring=False)
    blocked = _observe_waiter(monkeypatch)
    entered = threading.Event()
    release = threading.Event()
    requests: list[object] = []

    def transport(request: Any, timeout: float) -> _Response:
        assert timeout == 90
        requests.append(request)
        if threading.current_thread().name == "first":
            entered.set()
            assert release.wait(10)
            if first_outcome == "failure":
                raise urllib.error.HTTPError(request.full_url, 500, "Controlled", Message(), None)
        return _Response(request, args["generated_at"])

    monkeypatch.setattr(runner, "managed_urlopen", transport)
    first = _start(lambda: _automatic(store, context, args), "first")
    second = None
    try:
        assert entered.wait(10)
        if second_mode == "direct":
            second = _start(lambda: aibom_cli.sync_aibom_snapshots(peer, context, **args))
        else:
            second = _start(lambda: _automatic(peer, context, args, force=second_mode == "force"))
        assert blocked.wait(10)
        assert len(requests) == 1
        with peer.hold_oauth_refresh_lock(timeout_seconds=0), peer.hold_oauth_credential_lock(timeout_seconds=0):
            peer.set_sync_payload("receipt_sync_cursor", {"last_rowid": 17}, args["generated_at"])
        assert peer.get_sync_payload("receipt_sync_cursor") == {"last_rowid": 17}
    finally:
        release.set()
        first[0].join(timeout=10)
        if second is not None:
            second[0].join(timeout=10)
        assert not first[0].is_alive()
        assert second is None or not second[0].is_alive()
    first_result = _finish(first)
    assert second is not None
    second_result = _finish(second)
    assert first_result["synced"] is (first_outcome == "success")
    skipped = second_mode == "automatic" and first_outcome == "success"
    assert len(requests) == (1 if skipped else 2)
    assert second_result["synced"] is not skipped
    if skipped:
        assert second_result["reason"] == "recently_synced"
    else:
        assert second_result["accepted"] == 1
    assert peer.get_sync_payload("receipt_sync_cursor") == {"last_rowid": 17}


@pytest.mark.parametrize("mutation", ["workspace", "freshness", "backoff", "empty-freshness"])
def test_waiter_reads_connection_and_admission_state_only_after_reservation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    store, context, args, credentials = _fixture(tmp_path)
    peer = GuardStore(store.guard_home, allow_system_keyring=False)
    blocked = _observe_waiter(monkeypatch)
    reads: list[str] = []
    actual_read = aibom_cli.capture_aibom_operation

    def read_workspace(*args: Any, **kwargs: Any):
        reads.append("workspace")
        return actual_read(*args, **kwargs)

    def no_collection(*_args: object, **_kwargs: object) -> None:
        pytest.fail("An ineligible waiter must not collect inventory")

    monkeypatch.setattr(aibom_cli, "capture_aibom_operation", read_workspace)
    monkeypatch.setattr(aibom_cli, "collect_aibom_snapshots", no_collection)
    worker = None
    try:
        with store.hold_aibom_sync_lock():
            worker = _start(lambda: _automatic(peer, context, args))
            assert blocked.wait(10)
            assert reads == []
            if mutation == "workspace":
                replacement: dict[str, Any] = {**credentials, "workspace_id": "workspace-beta"}
                store.set_oauth_local_credentials(**replacement)
            elif mutation == "backoff":
                _bound_result(
                    store,
                    context,
                    "aibom_guard_events_backoff",
                    {"sync_reason": "guard_events_endpoint_unavailable", "synced_at": args["generated_at"]},
                    args["generated_at"],
                )
            else:
                _bound_result(
                    store,
                    context,
                    "aibom_sync_summary",
                    {
                        "synced": True,
                        "synced_at": args["generated_at"],
                        "snapshots": 0 if mutation == "empty-freshness" else 1,
                    },
                    args["generated_at"],
                )
    finally:
        if worker is not None:
            worker[0].join(timeout=10)
    assert worker is not None
    result = _finish(worker)
    expected = {"workspace": "workspace_changed", "backoff": "guard_events_endpoint_unavailable"}.get(
        mutation, "recently_synced"
    )
    assert result["reason"] == expected
    assert reads == ["workspace"]


@pytest.mark.parametrize("mode", ["automatic", "force", "direct"])
def test_existing_backoff_difference_and_reservation_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    store, context, args, _ = _fixture(tmp_path)
    now = args["generated_at"]
    _bound_result(
        store,
        context,
        "aibom_guard_events_backoff",
        {"sync_reason": "guard_events_endpoint_unavailable", "synced_at": now},
        now,
    )
    requests: list[object] = []

    def transport(request: Any, timeout: float) -> _Response:
        assert timeout == 90
        requests.append(request)
        return _Response(request, now)

    monkeypatch.setattr(runner, "managed_urlopen", transport)
    result = (
        aibom_cli.sync_aibom_snapshots(store, context, **args)
        if mode == "direct"
        else _automatic(store, context, args, force=mode == "force")
    )
    assert result["synced"] is (mode == "direct")
    assert len(requests) == int(mode == "direct")
    if mode != "direct":
        assert result["reason"] == "guard_events_endpoint_unavailable"
    with GuardStore(store.guard_home, allow_system_keyring=False).hold_aibom_sync_lock(timeout_seconds=0):
        pass


@pytest.mark.parametrize("mode", ["automatic", "direct"])
def test_admission_timeout_is_not_caught_as_operation_outcome(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    store, context, args, _ = _fixture(tmp_path)
    peer = GuardStore(store.guard_home, allow_system_keyring=False)
    actual = peer.hold_aibom_sync_lock
    monkeypatch.setattr(peer, "hold_aibom_sync_lock", lambda: actual(timeout_seconds=0))
    with store.hold_aibom_sync_lock(), pytest.raises(TimeoutError, match="inventory sync lock"):
        if mode == "direct":
            aibom_cli.sync_aibom_snapshots(peer, context, **args)
        else:
            _automatic(peer, context, args)
    with peer.hold_aibom_sync_lock():
        pass


@pytest.mark.parametrize("failure", [RuntimeError, ValueError])
def test_admission_releases_after_collection_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: type[Exception]
) -> None:
    store, context, args, _ = _fixture(tmp_path)

    def fail(*_args: object, **_kwargs: object) -> None:
        raise failure("Controlled collection failure")

    monkeypatch.setattr(aibom_cli, "collect_aibom_snapshots", fail)
    with pytest.raises(failure, match="Controlled collection failure"):
        aibom_cli.sync_aibom_snapshots(store, context, **args)
    with GuardStore(store.guard_home, allow_system_keyring=False).hold_aibom_sync_lock(timeout_seconds=0):
        pass


def test_separate_store_home_has_independent_inventory_admission(tmp_path: Path) -> None:
    first = GuardStore(tmp_path / "first", allow_system_keyring=False)
    second = GuardStore(tmp_path / "second", allow_system_keyring=False)
    with first.hold_aibom_sync_lock(), second.hold_aibom_sync_lock(timeout_seconds=0):
        second.set_sync_payload("receipt_sync_cursor", {"last_rowid": 19}, "2026-01-01T00:00:00Z")
    assert first.get_sync_payload("receipt_sync_cursor") is None


@pytest.mark.parametrize("termination", ["normal", "killed"])
def test_actual_child_reservation_excludes_parent_and_releases_on_exit(tmp_path: Path, termination: str) -> None:
    store = GuardStore(tmp_path / "guard", allow_system_keyring=False)
    code = r"""
import socket,sys
from pathlib import Path
from codex_plugin_scanner.guard.store import GuardStore
def denied(*args, **kwargs): raise AssertionError("Unexpected raw network")
socket.socket.connect = denied
socket.create_connection = denied
store = GuardStore(Path(sys.argv[1]), allow_system_keyring=False)
with store.hold_aibom_sync_lock():
    print("reserved", flush=True)
    assert sys.stdin.read(1) == "x"
print("released", flush=True)
"""
    child = subprocess.Popen(
        [sys.executable, "-c", code, str(store.guard_home)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    lines: Queue[str] = Queue()
    assert child.stdout is not None

    def read_boundary() -> None:
        assert child.stdout is not None
        lines.put(child.stdout.readline())

    reader = threading.Thread(target=read_boundary, daemon=True)
    reader.start()
    try:
        assert lines.get(timeout=10).strip() == "reserved"
        reader.join(timeout=10)
        assert not reader.is_alive()
        with pytest.raises(TimeoutError, match="inventory sync lock"), store.hold_aibom_sync_lock(timeout_seconds=0):
            pass
        if termination == "killed":
            child.kill()
            output, error = child.communicate(timeout=10)
            assert child.returncode != 0
        else:
            output, error = child.communicate("x", timeout=10)
            assert child.returncode == 0 and output.strip() == "released"
        assert error == ""
        with store.hold_aibom_sync_lock(timeout_seconds=0):
            pass
    finally:
        if child.poll() is None:
            child.kill()
        reader.join(timeout=10)
        assert not reader.is_alive()
        child.communicate(timeout=10)


def test_actual_child_automatic_sync_waits_before_connection_and_collection(tmp_path: Path) -> None:
    store, context, args, _ = _fixture(tmp_path)
    code = r"""
import io,json,socket,sys
from pathlib import Path
from codex_plugin_scanner.guard import aibom_cli,store_connection_schema
from codex_plugin_scanner.guard.cli.oauth_client import GuardDpopKeyMaterial
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.store import GuardStore

def denied(*args, **kwargs): raise AssertionError("Unexpected raw network")
socket.socket.connect = denied
socket.create_connection = denied
store = GuardStore(Path(sys.argv[1]), allow_system_keyring=False)
credentials = store.get_oauth_local_credentials()
key = GuardDpopKeyMaterial(
    algorithm="ES256", private_key_pem=credentials["dpop_private_key_pem"],
    public_jwk=credentials["dpop_public_jwk"], public_jwk_thumbprint=credentials["dpop_public_jwk_thumbprint"],
)
auth = {"sync_url":"https://hol.org/api/guard/receipts/sync","access_token":"synthetic-access","dpop_key_material":key}
original = store_connection_schema._acquire_advisory_file_lock
admitted = False
announced = False

def acquisition(handle):
    global admitted,announced
    try:
        result = original(handle)
        if Path(handle.name).name == "aibom-sync.lock": admitted = True
        return result
    except BlockingIOError:
        if Path(handle.name).name == "aibom-sync.lock" and not announced:
            announced = True
            print("blocked", flush=True)
        raise
store_connection_schema._acquire_advisory_file_lock = acquisition
actual_workspace = aibom_cli.capture_aibom_operation

def workspace(*args, **kwargs):
    assert admitted, "Connection checked before inventory admission"
    return actual_workspace(*args, **kwargs)
aibom_cli.capture_aibom_operation = workspace
actual_collect = aibom_cli.collect_aibom_snapshots

def collect(*args, **kwargs):
    assert admitted, "Collected before inventory admission"
    return actual_collect(*args, **kwargs)
aibom_cli.collect_aibom_snapshots = collect
class Response(io.BytesIO):
    status=200;headers={}
    def getcode(self):return 200

def transport(request,timeout):
    assert admitted and timeout == 90
    events = json.loads(request.data)["events"]
    return Response(json.dumps({"accepted":len(events),"rejected":0,"statuses":[],"syncedAt":sys.argv[4]}).encode())
runner.managed_urlopen = transport
result = aibom_cli.sync_aibom_snapshots_if_due(
    store, generated_at=sys.argv[4], options=aibom_cli.AibomCliOptions(), auth_context=auth,
    expected_workspace_id="workspace-alpha", home_dir=Path(sys.argv[2]), workspace_dir=Path(sys.argv[3]),
)
assert result["synced"] is True and result["accepted"] == 1
print("synced",flush=True)
"""
    child = None
    reader = None
    try:
        with store.hold_aibom_sync_lock():
            child = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    code,
                    str(store.guard_home),
                    str(context.home_dir),
                    str(context.workspace_dir),
                    args["generated_at"],
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            lines: Queue[str] = Queue()

            def read_boundary() -> None:
                assert child is not None and child.stdout is not None
                lines.put(child.stdout.readline())

            reader = threading.Thread(target=read_boundary, daemon=True)
            reader.start()
            assert lines.get(timeout=10).strip() == "blocked"
            reader.join(timeout=10)
            assert not reader.is_alive()
            assert child.poll() is None
            assert store.get_sync_payload("aibom_sync_summary") is None
        output, error = child.communicate(timeout=10)
        assert child.returncode == 0 and error == ""
        assert output.strip() == "synced"
        summary = store.get_sync_payload("aibom_sync_summary")
        assert isinstance(summary, dict)
        assert summary["synced"] is True and summary["accepted"] == 1
    finally:
        if child is not None:
            if child.poll() is None:
                child.kill()
            if reader is not None:
                reader.join(timeout=10)
                assert not reader.is_alive()
            child.communicate(timeout=10)
