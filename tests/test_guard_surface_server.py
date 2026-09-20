"""Behavior tests for the Guard Surface Server runtime."""

# Keep the original dependency import order for partitioned surface tests.
from __future__ import annotations

import base64
import hashlib  # noqa: F401
import json
import os  # noqa: F401
import socket  # noqa: F401
import sqlite3
import sys  # noqa: F401
import tempfile  # noqa: F401
import time  # noqa: F401
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone  # noqa: F401
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.adapters import get_adapter  # noqa: F401
from codex_plugin_scanner.guard.adapters.base import HarnessContext  # noqa: F401
from codex_plugin_scanner.guard.cli import commands as guard_commands_module  # noqa: F401
from codex_plugin_scanner.guard.config import GuardConfig  # noqa: F401
from codex_plugin_scanner.guard.daemon import GuardDaemonServer, protection_repair_retry
from codex_plugin_scanner.guard.daemon import manager as daemon_manager_module  # noqa: F401
from codex_plugin_scanner.guard.daemon import runtime_hook_deadline as runtime_hook_deadline_module  # noqa: F401
from codex_plugin_scanner.guard.daemon import server as daemon_server_module
from codex_plugin_scanner.guard.daemon.discovery import load_authenticated_daemon_state
from codex_plugin_scanner.guard.desktop_notifications import DesktopNotificationSetupResult  # noqa: F401
from codex_plugin_scanner.guard.local_dashboard_session import (
    LOCAL_DASHBOARD_SESSION_AUDIENCE,  # noqa: F401
    LOCAL_DASHBOARD_SESSION_VERSION,  # noqa: F401
    build_local_dashboard_session_token,
)
from codex_plugin_scanner.guard.models import GuardApprovalRequest, GuardArtifact, PolicyDecision  # noqa: F401
from codex_plugin_scanner.guard.runtime.surface_server import GuardSurfaceRuntime, _browser_url_for_review  # noqa: F401
from codex_plugin_scanner.guard.schemas import build_surface_server_contract  # noqa: F401
from codex_plugin_scanner.guard.store import GuardStore
from tests.daemon_hook_test_client import open_authenticated_claude_request  # noqa: F401
from tests.support.network import urlopen_json  # noqa: F401


def _seed_guard_cloud(store, *, workspace_id=None, sync_url=None, token="demo-token", now="2026-05-19T00:00:00Z"):
    """Seed OAuth credentials (replaces legacy set_sync_credentials scaffolding).
    Also installs a test-only resolver override so sync-path exercises stay hermetic
    (no OAuth token refresh against the network). Tests that need real sync against a
    local server pass sync_url=<url>.
    """
    from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
    from codex_plugin_scanner.guard.runtime import runner as guard_runner_module

    dpop_key_material = generate_dpop_key_pair()
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token=token,
        dpop_private_key_pem=dpop_key_material.private_key_pem,
        dpop_public_jwk=dpop_key_material.public_jwk,
        dpop_public_jwk_thumbprint=dpop_key_material.public_jwk_thumbprint,
        grant_id="grant-1",
        machine_id="machine-1",
        workspace_id=workspace_id,
        now=now,
    )
    effective_sync_url = sync_url if sync_url is not None else "https://hol.org/api/guard/receipts/sync"
    guard_runner_module._test_sync_auth_context_override = {
        "sync_url": effective_sync_url,
        "access_token": token,
        "dpop_key_material": None,
    }


def _guard_get_request(port: int, path: str, auth_token: str) -> urllib.request.Request:
    return urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        headers={"X-Guard-Token": auth_token},
        method="GET",
    )


def _guard_dashboard_session_get_request(port: int, path: str, session_token: str) -> urllib.request.Request:
    return urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        headers={"X-Guard-Dashboard-Session": session_token},
        method="GET",
    )


def _approval_center_session_token(daemon: GuardDaemonServer) -> str:
    return build_local_dashboard_session_token(
        auth_token=daemon._server.auth_token,
        surface="approval-center",
    )


def _decode_dashboard_session_claims(token: str) -> dict[str, object]:
    _prefix, encoded_payload, _signature = token.split(".")
    padding = "=" * (-len(encoded_payload) % 4)
    return json.loads(base64.urlsafe_b64decode(f"{encoded_payload}{padding}").decode("utf-8"))


class TestGuardSurfaceServer:
    def test_harness_repair_runtime_failure_returns_actionable_response(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
        monkeypatch.setattr(
            daemon_server_module,
            "apply_managed_install",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("private adapter detail")),
        )
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()
        request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/harnesses/opencode/repair",
            data=json.dumps({"dry_run": False}).encode("utf-8"),
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
        assert payload == {
            "error": "harness_repair_failed",
            "harness": "opencode",
            "message": (
                "Guard could not repair opencode protection. Open this app's repair details and retry that "
                "protection layer. "
                "Your existing protection settings were preserved."
            ),
        }

    def test_daemon_trust_snapshot_tracks_only_committed_integrity_transitions(self, tmp_path: Path) -> None:
        store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()
        degraded = {
            "backend": "system-keyring",
            "degraded_reasons": ["policy_integrity_key_unavailable"],
            "mode": "degraded",
        }
        protected = {
            "backend": "system-keyring",
            "degraded_reasons": [],
            "mode": "protected",
        }

        try:
            with store._connect() as connection:
                store._queue_policy_integrity_state_notification(connection, degraded)
            committed_state = load_authenticated_daemon_state(store.guard_home)

            with pytest.raises(RuntimeError, match="rollback"), store._connect() as connection:
                store._queue_policy_integrity_state_notification(connection, protected)
                raise RuntimeError("rollback")
            rolled_back_state = load_authenticated_daemon_state(store.guard_home)
        finally:
            daemon.stop()

        assert committed_state is not None
        assert committed_state["trust_status"] == degraded
        assert rolled_back_state is not None
        assert rolled_back_state["trust_status"] == degraded

    def test_protection_repair_requires_auth_and_repairs_integrity(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
        monkeypatch.setattr(
            GuardStore,
            "setup_policy_integrity",
            lambda self, **_kwargs: {"mode": "protected"},
        )
        monkeypatch.setattr(
            GuardStore,
            "get_cached_policy_integrity_state",
            lambda self: {"backend": "system-keyring", "degraded_reasons": [], "mode": "protected"},
        )
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        unauthenticated = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/protection/repair",
            data=json.dumps({"check_id": "rule_packs"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        authenticated = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/protection/repair",
            data=json.dumps({"check_id": "rule_packs"}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "X-Guard-Token": daemon._server.auth_token,
            },
            method="POST",
        )
        try:
            with pytest.raises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(unauthenticated, timeout=5)
            with urllib.request.urlopen(authenticated, timeout=5) as response:
                payload = json.loads(response.read().decode("utf-8"))
            authenticated_state = load_authenticated_daemon_state(store.guard_home)
        finally:
            daemon.stop()

        assert error.value.code == 401
        assert payload == {
            "repaired": True,
            "repair_scope": "local_integrity",
            "check_ids": ["policy_engine", "rule_packs", "tamper_checks"],
            "pending_check_ids": [],
            "message": "Integrity protection restored.",
        }
        assert authenticated_state is not None
        assert authenticated_state["trust_status"] == {
            "backend": "system-keyring",
            "degraded_reasons": [],
            "mode": "protected",
        }

    def test_protection_repair_all_returns_an_inline_recovery_result(
        self,
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
        monkeypatch.setattr(
            daemon_server_module._GuardDaemonHandler,
            "_containment_health_payload",
            lambda self, *, force_refresh=False: containment_probes.append(force_refresh) or {},
        )
        monkeypatch.setattr(
            protection_repair_retry,
            "containment_health_signals",
            lambda value, **_kwargs: {
                check_id: SimpleNamespace(status=protection_repair_retry.ProtectionCheckStatus.PASS)
                for check_id in (
                    "decision_plane_compatibility",
                    "containment_compatibility",
                    "sandbox",
                )
            },
        )
        maintained: list[bool] = []
        monkeypatch.setattr(
            GuardStore,
            "maintain_command_activity",
            lambda self, **_kwargs: maintained.append(True),
        )
        monkeypatch.setattr(
            GuardStore, "get_command_activity_persistence_health", lambda self: SimpleNamespace(active_error_count=0)
        )
        monkeypatch.setattr(GuardStore, "count_command_activities", lambda self: 0)
        monkeypatch.setattr(daemon_server_module, "repair_failing_managed_harness_hooks", lambda _store: ((), ()))
        monkeypatch.setattr(GuardStore, "list_managed_installs", lambda self: [{"harness": "codex", "active": True}])
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()
        request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/protection/repair",
            data=json.dumps({"check_id": "all"}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "X-Guard-Token": daemon._server.auth_token,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                payload = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()
        assert payload["repaired"] is True
        assert payload["check_ids"] == [
            "policy_engine",
            "rule_packs",
            "tamper_checks",
            "harness_hooks",
            "decision_plane_compatibility",
            "containment_compatibility",
            "sandbox",
            "decision_stream",
        ]
        assert payload["pending_check_ids"] == []
        assert payload["message"] == "Integrity protection restored."
        assert maintained
        assert containment_probes == [True]

    def test_protection_repair_converts_recovery_type_errors_to_inline_failure(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)

        def fail_setup(_store: GuardStore, **_kwargs: object) -> dict[str, object]:
            raise TypeError("invalid recovery state")

        monkeypatch.setattr(
            GuardStore,
            "setup_policy_integrity",
            fail_setup,
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
            with pytest.raises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(request, timeout=5)
            payload = json.loads(error.value.read().decode("utf-8"))
        finally:
            daemon.stop()

        assert error.value.code == 409
        assert payload["error"] == "protection_repair_failed"

    def test_protection_repair_converts_command_store_errors_to_inline_failure(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)

        def fail_probe(_store: GuardStore) -> None:
            raise sqlite3.OperationalError("write failed")

        monkeypatch.setattr(
            daemon_server_module,
            "_repair_command_activity_persistence_health",
            fail_probe,
        )
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()
        request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/protection/repair",
            data=json.dumps({"check_id": "decision_stream"}).encode("utf-8"),
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
        assert payload["error"] == "protection_repair_failed"

    def test_protection_repair_recovers_degraded_integrity_without_trusting_invalid_rows(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
        monkeypatch.setattr(
            GuardStore,
            "setup_policy_integrity",
            lambda self, **_kwargs: {"mode": "degraded", "degraded_reasons": ["rollback_detected"]},
        )
        repair_calls: list[bool] = []
        monkeypatch.setattr(
            GuardStore,
            "repair_policy_integrity",
            lambda self, *, clear_invalid, **_kwargs: (
                repair_calls.append(clear_invalid) or {"mode": "protected", "counts": {"valid": 0}}
            ),
        )
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()
        request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/protection/repair",
            data=json.dumps({"check_id": "rule_packs"}).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-Guard-Token": daemon._server.auth_token},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                payload = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()

        assert payload["repaired"] is True
        assert repair_calls == [False]
        assert payload["message"] == "Integrity protection restored."

    def test_protection_repair_keeps_cloud_policy_availability_separate_from_local_integrity(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
        degraded_status = {
            "mode": "degraded",
            "degraded_reasons": ["policy_integrity_key_unavailable"],
            "counts": {"valid": 0},
        }
        monkeypatch.setattr(GuardStore, "setup_policy_integrity", lambda self, **_kwargs: degraded_status)
        monkeypatch.setattr(
            GuardStore,
            "repair_policy_integrity",
            lambda self, **_kwargs: degraded_status,
        )
        monkeypatch.setattr(
            GuardStore,
            "reset_policy_integrity",
            lambda self, **_kwargs: (_ for _ in ()).throw(AssertionError("repair must not reset local trust")),
        )
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()
        request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/protection/repair",
            data=json.dumps({"check_id": "rule_packs"}).encode("utf-8"),
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
        assert payload["error"] == "local_integrity_repair_incomplete"
        assert payload["repair_scope"] == "local_integrity"
        assert "unauthenticated policy data" not in payload["message"]
        assert "Guard Cloud policy availability" in payload["message"]

    def test_protection_repair_all_reports_containment_probe_failure_inline(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
        monkeypatch.setattr(
            GuardStore,
            "setup_policy_integrity",
            lambda self, **_kwargs: {"mode": "protected"},
        )
        monkeypatch.setattr(
            daemon_server_module._GuardDaemonHandler,
            "_containment_health_payload",
            lambda self, **_kwargs: (_ for _ in ()).throw(RuntimeError("probe failed")),
        )
        monkeypatch.setattr(
            daemon_server_module,
            "repair_failing_managed_harness_hooks",
            lambda _store: (_ for _ in ()).throw(RuntimeError("hook discovery failed")),
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
            with pytest.raises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(request, timeout=5)
            payload = json.loads(error.value.read().decode("utf-8"))
        finally:
            daemon.stop()

        assert error.value.code == 409
        assert payload["failed_check_ids"] == [
            "harness_hooks",
            "decision_plane_compatibility",
            "containment_compatibility",
            "sandbox",
        ]
        assert payload["failed_harnesses"] == []
        assert payload["message"] == (
            "Repair paused before every supported protection layer could be confirmed. Retry repair here."
        )
