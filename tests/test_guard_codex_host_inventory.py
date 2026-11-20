"""The Codex host inventory cache renders what the native ``codex_host_inventory`` kind answers.

Socket, marker, process and protocol behavior is covered by the Rust tests in
``codex_host_probe_tests.rs`` and ``codex_host_read_tests.rs``.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_runner_authority
from codex_plugin_scanner.guard.runtime import codex_host_inventory as inventory

pytestmark = pytest.mark.skipif(os.name == "nt", reason="Codex host inventory requires Unix peer credentials")

APP = {
    "app_id": "example",
    "name": "Example connector",
    "enabled": True,
    "callable": True,
    "metadata_available": True,
    "tools": [{"name": "send_message", "title": "Send a message", "description": "Change external content"}],
}
SOURCE = {"target": "/tmp/hgx/app-server-control/daemon.sock", "identity": [1, 2, 3, 4]}


class FakeNative:
    """Stands in for the resident: records each request and answers from ``read`` and ``valid``."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.requests: list[tuple[str, dict[str, object]]] = []
        self.options: list[dict[str, object]] = []
        self.read: object = {
            "snapshot": {
                "connection_id": "a" * 64,
                "apps": [APP],
                "metadata_complete": True,
                "host_pid": os.getpid(),
                "managed_pid": os.getpid(),
                "source": SOURCE,
            }
        }
        self.valid: object = {"valid": True}
        monkeypatch.setattr(native_runner_authority, "native_runner_authority", self)

    def __call__(self, kind: str, request: dict[str, object], **options: object) -> dict[str, object]:
        self.requests.append((kind, request))
        self.options.append(options)
        reply = self.read if "read" in request else self.valid
        if isinstance(reply, Exception):
            raise reply
        return reply  # type: ignore[return-value]

    def checks(self) -> list[dict[str, object]]:
        return [request["check"] for _kind, request in self.requests if "check" in request]  # type: ignore[misc]


@pytest.fixture
def native(monkeypatch: pytest.MonkeyPatch) -> FakeNative:
    return FakeNative(monkeypatch)


def test_read_sends_only_paths_and_renders_the_snapshot(tmp_path, monkeypatch, native):
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path / "home"))
    snapshot = inventory.read_codex_host_inventory(codex_home=tmp_path / ".codex", timeout=3.0)
    ((kind, request),) = native.requests
    assert kind == "codex_host_inventory"
    assert request == {
        "read": {
            "codex_home": str(tmp_path / ".codex"),
            "home_dir": str(tmp_path / "home"),
            "temp_dir": inventory.tempfile.gettempdir(),
            "timeout_ms": 3000,
        }
    }
    assert snapshot.apps[0]["name"] == "Example connector"
    payload = snapshot.as_payload()
    assert payload["catalog_coverage"] == "host-summary"
    assert payload["schemas_available"] is False
    assert payload["account_verified"] is False
    assert payload["permissions_granted"] is False
    assert str(tmp_path) not in json.dumps(payload)


def test_cancellation_never_reaches_the_native_read(tmp_path, native):
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(ValueError, match="codex_host_cancelled"):
        inventory.read_codex_host_inventory(codex_home=tmp_path, cancel=cancel)
    assert native.requests == []


def test_cancellation_during_the_native_read_drops_the_answer(tmp_path, monkeypatch, native):
    cancel = threading.Event()
    answer = native.read

    def cancelled(*_args, **_options):
        cancel.set()
        return answer

    monkeypatch.setattr(native_runner_authority, "native_runner_authority", cancelled)
    cache = inventory.CodexHostInventoryCache()
    cache.refresh(codex_home=tmp_path, cancel=cancel)
    assert cache.read() is None


@pytest.mark.parametrize(
    ("reply", "expected"),
    [
        ({"error": "codex_host_untrusted"}, "untrusted"),
        ({"error": "codex_host_changed"}, "changed"),
        ({"error": "private injected details"}, "invalid"),
        ({"error": ["codex_host_limit"]}, "invalid"),
        ({"snapshot": "example"}, "invalid"),
        ({}, "invalid"),
        (
            {"snapshot": {"connection_id": "a", "apps": ["example"], "metadata_complete": True, "host_pid": 2}},
            "invalid",
        ),
        ({"snapshot": {"connection_id": "a", "apps": [], "metadata_complete": 1, "host_pid": 2}}, "invalid"),
        ({"snapshot": {"connection_id": "a", "apps": [], "metadata_complete": True, "host_pid": "2"}}, "invalid"),
        (
            {
                "snapshot": {
                    "connection_id": "a",
                    "apps": [],
                    "metadata_complete": True,
                    "host_pid": 2,
                    "managed_pid": "2",
                    "source": SOURCE,
                }
            },
            "invalid",
        ),
        (
            {"snapshot": {"connection_id": "a", "apps": [], "metadata_complete": True, "host_pid": 2, "source": {}}},
            "invalid",
        ),
        (native_runner_authority.NativeRunnerAuthorityError("native_runner_authority_unavailable"), "unavailable"),
        (
            native_runner_authority.NativeRunnerAuthorityRefusalError("native_runner_authority_request_too_large"),
            "limit",
        ),
    ],
)
def test_native_reply_raises_only_host_codes(tmp_path, native, reply, expected):
    native.read = reply
    with pytest.raises(ValueError, match=f"^codex_host_{expected}$"):
        inventory.read_codex_host_inventory(codex_home=tmp_path)


def test_no_host_is_silent_and_clears_the_cache(tmp_path, native, caplog):
    cache = inventory.CodexHostInventoryCache()
    cache.refresh(codex_home=tmp_path, cancel=threading.Event())
    assert cache.read() is not None
    native.read = {"absent": True}
    cache.refresh(codex_home=tmp_path, cancel=threading.Event())
    assert cache.read() is None
    assert "Codex host inventory failed" not in caplog.text
    with pytest.raises(ValueError, match=r"^codex_host_unavailable$") as raised:
        inventory.read_codex_host_inventory(codex_home=tmp_path)
    assert isinstance(raised.value.__cause__, FileNotFoundError)


def test_public_cache_never_reads_rpc_on_listing_and_invalidates_reconnect(tmp_path, native):
    cache = inventory.CodexHostInventoryCache()
    cache.refresh(codex_home=tmp_path, cancel=threading.Event())
    reads = len(native.requests)
    payload = cache.read()
    assert payload is not None
    payload["apps"].clear()
    assert len(cache.read()["apps"]) == 1
    # A listing only asks whether the host is still the one that was read.
    assert all("check" in request for _kind, request in native.requests[reads:])
    check = native.checks()[0]
    assert check == {
        "codex_home": str(tmp_path),
        "home_dir": check["home_dir"],
        "temp_dir": inventory.tempfile.gettempdir(),
        "target": SOURCE["target"],
        "identity": SOURCE["identity"],
        "pid": os.getpid(),
        "managed_pid": os.getpid(),
    }
    native.valid = {"valid": False}
    assert cache.read() is None
    native.valid = {"valid": "yes"}
    assert cache.read() is None
    native.valid = native_runner_authority.NativeRunnerAuthorityError("native_runner_authority_unavailable")
    assert cache.read() is None


def test_expired_public_cache_is_not_presented_as_current(tmp_path, monkeypatch, native):
    cache = inventory.CodexHostInventoryCache()
    cache.refresh(codex_home=tmp_path, cancel=threading.Event())
    assert cache.read() is not None
    monkeypatch.setattr(inventory, "_SNAPSHOT_TTL", -1)
    checks = len(native.checks())
    assert cache.read() is None
    assert len(native.checks()) == checks


def test_snapshot_without_a_source_is_not_cached(tmp_path, monkeypatch, native):
    snapshot = inventory.CodexHostInventory("a" * 64, (), True, os.getpid(), None)
    monkeypatch.setattr(inventory, "read_codex_host_inventory", lambda **_kwargs: snapshot)
    cache = inventory.CodexHostInventoryCache()
    with pytest.raises(ValueError, match="codex_host_invalid"):
        cache.refresh(codex_home=tmp_path, cancel=threading.Event())
    assert cache.read() is None


@pytest.mark.parametrize("outcome", ["success", "failure", "cancelled", "cancelled-during-read"])
def test_refresh_keeps_valid_public_snapshot_visible_until_result(tmp_path, monkeypatch, native, outcome):
    cache = inventory.CodexHostInventoryCache()
    cache.refresh(codex_home=tmp_path, cancel=threading.Event())
    payload = cache.read()
    assert payload is not None
    snapshot = inventory.CodexHostInventory(
        payload["connection_id"],
        tuple(payload["apps"]),
        True,
        os.getpid(),
        os.getpid(),
        (SOURCE["target"], (1, 2, 3, 4)),
    )
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
            cache.refresh(codex_home=tmp_path, cancel=cancel)
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
    from codex_plugin_scanner.guard.local_clis.local_cli_api import LocalCliApiService
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
        # The reason reaches the page as itself: a generic code would send the
        # reader to a restart instead of to the Codex app that refused.
        assert state["error"] == "codex_host_untrusted"
        assert service.list_items()["host_inventory"] is None
        assert store.read_local_cli_revision() == before
    finally:
        assert service._discovery_jobs.close()


def test_background_host_inventory_is_not_persisted_or_enrolled_as_a_grant(tmp_path, monkeypatch, native):
    from codex_plugin_scanner.guard.local_clis.local_cli_api import LocalCliApiService
    from codex_plugin_scanner.guard.store import GuardStore

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
        assert state["state"] == "complete", state
        payload = service.list_items()
        assert payload["host_inventory"]["apps"][0]["name"] == "Example connector"
        assert payload["host_inventory"]["permissions_granted"] is False
        assert payload["items"] == []
        assert store.read_local_cli_revision() == before
        native.valid = {"valid": False}
        assert service.list_items()["host_inventory"] is None
    finally:
        assert service._discovery_jobs.close()


def test_stalled_host_snapshot_does_not_delay_configured_discovery(tmp_path, monkeypatch):
    from codex_plugin_scanner.guard.local_clis.local_cli_api import LocalCliApiService
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
