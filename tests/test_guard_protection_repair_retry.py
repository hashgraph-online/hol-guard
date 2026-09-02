"""Focused protection-repair retry behavior."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.daemon import protection_repair_retry
from codex_plugin_scanner.guard.daemon import server as daemon_server_module
from codex_plugin_scanner.guard.daemon.protection_repair_retry import incomplete_protection_repair_payload
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.runtime.protection_health import ProtectionCheckStatus
from codex_plugin_scanner.guard.store import GuardStore


def test_incomplete_repair_payload_asks_to_connect_an_app() -> None:
    payload = incomplete_protection_repair_payload(
        repaired_check_ids=["policy_engine"],
        failed_check_ids=["harness_hooks"],
        failed_harnesses=(),
        pending_check_ids=[],
        has_active_hooks=False,
        hook_failures=(),
        hook_repair_unknown=False,
    )
    assert payload["error"] == "protection_repair_incomplete"
    assert payload["message"] == (
        "Connect an AI app to start local protection. "
        "Repair cannot finish until at least one app is connected."
    )


def test_incomplete_repair_payload_keeps_generic_retry_copy_for_hook_failures() -> None:
    payload = incomplete_protection_repair_payload(
        repaired_check_ids=["policy_engine"],
        failed_check_ids=["harness_hooks"],
        failed_harnesses=("codex",),
        pending_check_ids=[],
        has_active_hooks=True,
        hook_failures=("codex",),
        hook_repair_unknown=False,
    )
    assert payload["message"] == (
        "Repair paused before every protection layer could be confirmed. Retry repair here."
    )


def test_protection_repair_all_retries_a_transient_containment_probe_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    monkeypatch.setattr(
        GuardStore,
        "setup_policy_integrity",
        lambda self, **_kwargs: {"mode": "protected"},
    )
    containment_probes: list[bool] = []

    def containment_payload(self, *, force_refresh=False):
        containment_probes.append(force_refresh)
        if len(containment_probes) == 1:
            raise RuntimeError("transient probe failure")
        return {}

    monkeypatch.setattr(
        daemon_server_module._GuardDaemonHandler,
        "_containment_health_payload",
        containment_payload,
    )
    monkeypatch.setattr(
        protection_repair_retry,
        "containment_health_signals",
        lambda value, **_kwargs: {
            check_id: SimpleNamespace(status=ProtectionCheckStatus.PASS)
            for check_id in (
                "decision_plane_compatibility",
                "containment_compatibility",
                "sandbox",
            )
        },
    )
    monkeypatch.setattr(GuardStore, "maintain_command_activity", lambda self, **_kwargs: None)
    monkeypatch.setattr(
        GuardStore,
        "get_command_activity_persistence_health",
        lambda self: SimpleNamespace(active_error_count=0),
    )
    monkeypatch.setattr(GuardStore, "count_command_activities", lambda self: 0)
    monkeypatch.setattr(
        daemon_server_module,
        "repair_failing_managed_harness_hooks",
        lambda _store: ((), ()),
    )
    monkeypatch.setattr(
        GuardStore,
        "list_managed_installs",
        lambda self: [{"harness": "codex", "active": True}],
    )
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    request = urllib.request.Request(
        f"http://127.0.0.1:{daemon.port}/v1/protection/repair",
        data=json.dumps({"check_id": "all"}).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Guard-Token": daemon._server.auth_token},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    finally:
        daemon.stop()

    assert payload["repaired"] is True
    assert containment_probes == [True, True]


def test_protection_repair_all_requires_a_connected_app(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    monkeypatch.setattr(GuardStore, "setup_policy_integrity", lambda self, **_kwargs: {"mode": "protected"})
    monkeypatch.setattr(
        daemon_server_module._GuardDaemonHandler,
        "_containment_health_payload",
        lambda self, **_kwargs: {},
    )
    monkeypatch.setattr(
        protection_repair_retry,
        "containment_health_signals",
        lambda value, **_kwargs: {
            check_id: SimpleNamespace(status=ProtectionCheckStatus.PASS)
            for check_id in (
                "decision_plane_compatibility",
                "containment_compatibility",
                "sandbox",
            )
        },
    )
    monkeypatch.setattr(GuardStore, "maintain_command_activity", lambda self, **_kwargs: None)
    monkeypatch.setattr(
        GuardStore,
        "get_command_activity_persistence_health",
        lambda self: SimpleNamespace(active_error_count=0),
    )
    monkeypatch.setattr(GuardStore, "count_command_activities", lambda self: 0)
    monkeypatch.setattr(daemon_server_module, "repair_failing_managed_harness_hooks", lambda _store: ((), ()))
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    request = urllib.request.Request(
        f"http://127.0.0.1:{daemon.port}/v1/protection/repair",
        data=json.dumps({"check_id": "all"}).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Guard-Token": daemon._server.auth_token},
        method="POST",
    )
    try:
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request, timeout=5)
        payload = json.loads(error.value.read().decode("utf-8"))
    finally:
        daemon.stop()

    assert error.value.code == 409
    assert payload["repaired"] is False
    assert "harness_hooks" in payload["failed_check_ids"]
    assert payload["failed_harnesses"] == []
    assert payload["message"] == (
        "Connect an AI app to start local protection. "
        "Repair cannot finish until at least one app is connected."
    )
