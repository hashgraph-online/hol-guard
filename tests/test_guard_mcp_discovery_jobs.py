from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.local_cli_api import LocalCliApiError, LocalCliApiService
from codex_plugin_scanner.guard.daemon.local_cli_http import dispatch_local_cli_post
from codex_plugin_scanner.guard.daemon.mcp_discovery_jobs import DiscoveryJobError, McpDiscoveryJobs
from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity
from codex_plugin_scanner.guard.runtime.local_mcp_stdio import run_mcp_catalog
from codex_plugin_scanner.guard.store import GuardStore


def _finished(pool: McpDiscoveryJobs, job_id: str) -> dict[str, object]:
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        result = pool.read(job_id)
        if result["state"] not in {"running", "cancelling"}:
            return result
        time.sleep(0.01)
    pytest.fail("discovery did not finish promptly")


def test_jobs_bound_concurrency_deduplicate_and_shutdown():
    pool = McpDiscoveryJobs()
    entered = threading.Event()

    def stall(cancel: threading.Event) -> None:
        entered.set()
        assert cancel.wait(3)

    first = pool.start("connection-a", stall)
    assert entered.wait(1)
    assert pool.start("connection-a", stall)["job_id"] == first["job_id"]
    second = pool.start("connection-b", stall)
    third = pool.start("connection-c", stall)
    fourth = pool.start("connection-d", stall)
    with pytest.raises(DiscoveryJobError, match="discovery_busy"):
        pool.start("connection-e", stall)
    assert pool.read(str(first["job_id"]), cancel=True)["state"] == "cancelling"
    assert _finished(pool, str(first["job_id"]))["state"] == "cancelled"
    assert pool.close()
    assert pool.read(str(second["job_id"]))["state"] == "cancelled"
    assert pool.read(str(third["job_id"]))["state"] == "cancelled"
    assert pool.read(str(fourth["job_id"]))["state"] == "cancelled"
    with pytest.raises(DiscoveryJobError, match="discovery_unavailable"):
        pool.start("connection-c", stall)


def test_client_known_cancel_before_start_never_launches_worker():
    pool = McpDiscoveryJobs()
    client_job_id = "f" * 32
    launched = threading.Event()
    try:
        assert pool.read(client_job_id, cancel=True)["state"] == "cancelled"
        result = pool.start("inventory:configured", lambda _: launched.set(), requested_job_id=client_job_id)
        assert result == {
            "job_id": client_job_id,
            "cli_id": "inventory:configured",
            "state": "cancelled",
            "error": None,
        }
        assert not launched.is_set()
        with pytest.raises(DiscoveryJobError, match="discovery_job_unavailable"):
            pool.read(client_job_id)
    finally:
        assert pool.close()


def test_failed_job_redacts_details_backoff_and_completed_capacity(caplog):
    pool = McpDiscoveryJobs()
    try:

        def fail(_cancel: threading.Event) -> None:
            raise ValueError("PRIVATE TOKEN AND LAUNCH COMMAND")

        job = pool.start("connection", fail)
        result = _finished(pool, str(job["job_id"]))
        assert result["state"] == "failed"
        assert result["error"] == "discovery_failed"
        assert "PRIVATE" not in str(result)
        assert str(job["job_id"]) in caplog.text
        assert "ValueError" in caplog.text
        assert "PRIVATE TOKEN" not in caplog.text
        with pytest.raises(DiscoveryJobError, match="discovery_retry_backoff"):
            pool.start("connection", fail)
        for index in range(20):
            next_job = pool.start(f"connection-{index}", lambda _: None)
            assert _finished(pool, str(next_job["job_id"]))["state"] == "complete"
        assert len(pool._jobs) == 16
        with pytest.raises(DiscoveryJobError, match="discovery_job_unavailable"):
            pool.read(str(job["job_id"]))
    finally:
        assert pool.close()


def test_cancel_before_start_launches_nothing(tmp_path: Path):
    marker = tmp_path / "started"
    cancel = threading.Event()
    cancel.set()
    result = run_mcp_catalog([sys.executable, "-c", f"open({str(marker)!r}, 'w').close()"], cancel=cancel)
    assert result.reason == "cancelled"
    assert not marker.exists()


@pytest.mark.parametrize(
    "code", ["mcp_launch_failed", "mcp_transport_failed", "mcp_initialize_failed", "mcp_protocol_unsupported"]
)
def test_refresh_job_preserves_safe_probe_failure_codes(tmp_path, monkeypatch, code):
    store = GuardStore(tmp_path / "home")
    identity = UnlistedCliIdentity("local-cli.mcp-test", "Fixture", "executable", "c" * 64, "Fixture", None)
    store.record_local_cli_observation(identity, seen_at="2026-09-27T12:00:00Z", surface="mcp")
    service = LocalCliApiService(store=store)
    monkeypatch.setattr(
        service, "recognize", lambda *_args, **_kwargs: {"help_status": "failed", "discovery_error": code}
    )
    before = store.list_local_cli_items()
    try:
        job = service.refresh_job({"cli_id": identity.cli_id, "confirm_process_start": True})
        result = _finished(service._discovery_jobs, str(job["job_id"]))
        assert result["state"] == "failed"
        assert result["error"] == code
        assert store.list_local_cli_items() == before
    finally:
        assert service._discovery_jobs.close()


def test_refresh_api_requires_process_consent_and_cancel_does_not_mutate_grants(tmp_path: Path, monkeypatch):
    store = GuardStore(tmp_path / "home")
    identity = UnlistedCliIdentity(
        "local-cli.mcp-test",
        "Synthetic connector",
        "executable",
        "c" * 64,
        "Synthetic host",
        None,
    )
    store.record_local_cli_observation(identity, seen_at="2026-09-27T12:00:00Z", surface="mcp")
    service = LocalCliApiService(store=store)
    entered = threading.Event()

    def recognize(payload, *, cancel):
        assert payload == {"cli_id": identity.cli_id, "refresh": True}
        entered.set()
        assert cancel.wait(3)
        return {"help_status": "ok"}

    monkeypatch.setattr(service, "recognize", recognize)
    try:
        with pytest.raises(LocalCliApiError, match="Confirm starting"):
            service.refresh_job({"cli_id": identity.cli_id})
        assert not entered.is_set()
        job = dispatch_local_cli_post(
            service,
            "/v1/local-clis/refresh-job",
            {
                "cli_id": identity.cli_id,
                "confirm_process_start": True,
            },
        )
        assert entered.wait(1)
        assert service.list_items()["revision"] == 0
        service.refresh_job({"job_id": job["job_id"], "cancel": True})
        assert _finished(service._discovery_jobs, str(job["job_id"]))["state"] == "cancelled"
        assert store.read_local_cli_grant(identity.cli_id) is None
        assert store.read_local_cli_revision() == 0
    finally:
        assert service.close_discovery()


def test_configured_inventory_uses_read_adapters_and_never_launches(tmp_path: Path, monkeypatch):
    service = LocalCliApiService(store=GuardStore(tmp_path / "home"))
    calls = []
    monkeypatch.setattr(service, "_observe_harness_mcp_servers", lambda **_kwargs: calls.append("configuration"))
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.discover_observed_mcp_tools",
        lambda *_args, **_kwargs: calls.append("observations"),
    )

    def forbidden_launch(*_args, **_kwargs):
        pytest.fail("configuration discovery must not launch a server")

    monkeypatch.setattr("codex_plugin_scanner.guard.daemon.local_cli_api.probe_stdio_mcp_server", forbidden_launch)
    try:
        job = service.refresh_job({"operation": "configured-connections"})
        assert _finished(service._discovery_jobs, str(job["job_id"]))["state"] == "complete"
        assert calls == ["configuration", "observations"]
        assert service.refresh_job({"operation": "configured-connections"})["job_id"] == job["job_id"]
        assert calls == ["configuration", "observations"]
    finally:
        assert service.close_discovery()


@pytest.mark.parametrize(
    ("stage", "code"),
    [
        ("configuration", "configured_host_scan_failed"),
        ("observations", "observed_provider_scan_failed"),
    ],
)
def test_configured_inventory_reports_failed_stage_without_private_exception(
    tmp_path: Path, monkeypatch, stage: str, code: str
) -> None:
    service = LocalCliApiService(store=GuardStore(tmp_path / "home"))

    def fail(**_kwargs) -> None:
        raise ValueError("PRIVATE CONFIG OR PROVIDER RESULT")

    if stage == "configuration":
        monkeypatch.setattr(service, "_discovered_servers", fail)
    else:
        monkeypatch.setattr(service, "_observe_harness_mcp_servers", lambda **_kwargs: None)
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.daemon.local_cli_api.discover_observed_mcp_tools",
            lambda *_args, **_kwargs: fail(),
        )
    try:
        job = service.refresh_job({"operation": "configured-connections"})
        result = _finished(service._discovery_jobs, str(job["job_id"]))
        assert result["state"] == "failed"
        assert result["error"] == code
        assert "PRIVATE" not in str(result)
    finally:
        assert service.close_discovery()


def test_cancel_reaches_job_before_delayed_start_response(tmp_path: Path, monkeypatch):
    service = LocalCliApiService(store=GuardStore(tmp_path / "home"))
    launched = threading.Event()
    monkeypatch.setattr(service, "_observe_harness_mcp_servers", lambda **_kwargs: launched.set())
    client_job_id = "e" * 32
    try:
        assert service.refresh_job({"job_id": client_job_id, "cancel": True})["state"] == "cancelled"
        result = service.refresh_job({"operation": "configured-connections", "client_job_id": client_job_id})
        assert result["state"] == "cancelled"
        assert result["job_id"] == client_job_id
        assert not launched.is_set()
    finally:
        assert service.close_discovery()


@pytest.mark.skipif(os.name == "nt", reason="POSIX owned process group cleanup")
def test_cancel_stalled_real_probe_leaves_unrelated_process_alive(tmp_path: Path):
    marker = tmp_path / "owned-pids"
    script = (
        "import os, subprocess, sys, time; "
        "child=subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)']); "
        f"open({str(marker)!r}, 'w').write(str(os.getpid())+' '+str(child.pid)); "
        "time.sleep(30)"
    )
    cancel = threading.Event()
    outcome = []
    unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"], start_new_session=True)
    thread = threading.Thread(
        target=lambda: outcome.append(
            run_mcp_catalog([sys.executable, "-c", script], timeout=20, cancel=cancel),
        )
    )
    try:
        thread.start()
        deadline = time.monotonic() + 3
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert marker.exists()
        pids = [int(pid) for pid in marker.read_text().split()]
        cancel.set()
        thread.join(3)
        assert not thread.is_alive()
        assert outcome[0].reason == "cancelled"
        assert unrelated.poll() is None
        for pid in pids:
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.01)
            else:
                pytest.fail("Guard-owned probe descendant survived cancellation")
    finally:
        cancel.set()
        thread.join(3)
        unrelated.terminate()
        unrelated.wait(3)
