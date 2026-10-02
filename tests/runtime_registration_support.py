"""Shared fixtures for runtime-registration self-heal tests."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from codex_plugin_scanner.guard.daemon import manager as daemon_manager_module
from codex_plugin_scanner.guard.daemon import server as daemon_server_module
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.models import GuardRuntimeRegistration
from codex_plugin_scanner.guard.runtime.containment_contract import (
    CONTAINMENT_POLICY_VERSION,
    CONTAINMENT_SCHEMA_VERSION,
)
from codex_plugin_scanner.guard.runtime.containment_health import (
    CONTAINMENT_HEALTH_SCHEMA_VERSION,
    CONTAINMENT_POLICY_CONTRACT_DIGEST,
)
from codex_plugin_scanner.guard.runtime.effect_contract import EFFECT_CONTRACT_SCHEMA_VERSION
from codex_plugin_scanner.guard.runtime.effect_decision import EFFECT_DECISION_SCHEMA_VERSION
from codex_plugin_scanner.guard.store import GuardStore

T0 = "2026-07-25T00:00:00+00:00"
T1 = "2026-07-25T00:00:01+00:00"
CONTAINMENT_CHECK_IDS = (
    "policy_engine",
    "decision_plane_compatibility",
    "containment_compatibility",
    "sandbox",
)


def registration() -> GuardRuntimeRegistration:
    return GuardRuntimeRegistration(daemon_host="127.0.0.1", daemon_port=9100, started_at=T0)


def passing_containment_health() -> dict[str, object]:
    fingerprint = hashlib.sha256(b"daemon-runtime").hexdigest()
    return {
        "backend": "macos-sandbox",
        "backend_digest": hashlib.sha256(b"backend").hexdigest(),
        "policy_contract_digest": CONTAINMENT_POLICY_CONTRACT_DIGEST,
        "daemon_fingerprint": fingerprint,
        "runtime_fingerprint": fingerprint,
        "probe_at": datetime.now(timezone.utc).isoformat(),
        "probe_enforced": True,
        "containment_schema_version": CONTAINMENT_SCHEMA_VERSION,
        "policy_version": CONTAINMENT_POLICY_VERSION,
        "effect_contract_schema_version": EFFECT_CONTRACT_SCHEMA_VERSION,
        "effect_decision_schema_version": EFFECT_DECISION_SCHEMA_VERSION,
        "schema_version": CONTAINMENT_HEALTH_SCHEMA_VERSION,
    }


def delete_runtime_row(store: GuardStore) -> None:
    with sqlite3.connect(store.path) as connection:
        connection.execute("delete from guard_runtime_state")


def protection_check(snapshot: dict[str, object], check_id: str) -> dict[str, str]:
    health = cast(dict[str, object], snapshot["protection_health"])
    checks = cast(list[dict[str, str]], health["checks"])
    return next(check for check in checks if check["check_id"] == check_id)


def serving_runtime(daemon: GuardDaemonServer) -> dict[str, object]:
    server = daemon._server  # pyright: ignore[reportPrivateUsage]
    return {
        "session_id": server.runtime_session_id,
        "daemon_host": server.runtime_host,
        "daemon_port": server.daemon_port(),
        "started_at": server.runtime_started_at,
        "last_heartbeat_at": datetime.now(timezone.utc).isoformat(),
    }


def get_json(daemon: GuardDaemonServer, path: str) -> dict[str, object]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{daemon.port}{path}",
        headers={"X-Guard-Token": daemon._server.auth_token},  # pyright: ignore[reportPrivateUsage]
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return cast(dict[str, object], json.loads(response.read().decode("utf-8")))


def post_repair(daemon: GuardDaemonServer, check_id: str) -> tuple[int, dict[str, object]]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{daemon.port}/v1/protection/repair",
        data=json.dumps({"check_id": check_id}).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-Guard-Token": daemon._server.auth_token,  # pyright: ignore[reportPrivateUsage]
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, cast(dict[str, object], json.loads(response.read().decode("utf-8")))
    except urllib.error.HTTPError as error:
        return error.code, cast(dict[str, object], json.loads(error.read().decode("utf-8")))


def start_daemon(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[GuardStore, GuardDaemonServer]:
    monkeypatch.setattr(
        daemon_manager_module,
        "_guard_daemon_process_inventory_for_guard_home",
        lambda _home: [],
    )
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    return store, daemon


def stub_supported_repair(
    monkeypatch: pytest.MonkeyPatch,
    *,
    stub_evidence_health: bool = True,
) -> None:
    monkeypatch.setattr(
        GuardStore,
        "setup_policy_integrity",
        lambda self, **_kwargs: {"mode": "protected"},
    )
    monkeypatch.setattr(
        daemon_server_module._GuardDaemonHandler,  # pyright: ignore[reportPrivateUsage]
        "_containment_health_payload",
        lambda self, **_kwargs: passing_containment_health(),
    )
    monkeypatch.setattr(GuardStore, "maintain_command_activity", lambda self, **_kwargs: None)
    if stub_evidence_health:
        monkeypatch.setattr(
            GuardStore,
            "get_command_activity_persistence_health",
            lambda self: SimpleNamespace(active_error_count=0),
        )
    monkeypatch.setattr(daemon_server_module, "repair_failing_managed_harness_hooks", lambda _store: ((), ()))
    monkeypatch.setattr(GuardStore, "list_managed_installs", lambda self: [{"harness": "codex", "active": True}])


def assert_row_reappears_with_daemon_identity(store: GuardStore, daemon: GuardDaemonServer) -> None:
    server = daemon._server  # pyright: ignore[reportPrivateUsage]
    deadline = time.monotonic() + 2
    state: dict[str, object] | None = None
    while time.monotonic() < deadline:
        get_json(daemon, "/healthz")
        state = store.get_runtime_state()
        if state is not None:
            break
        time.sleep(0.02)
    assert state is not None
    assert state["session_id"] == server.runtime_session_id
    assert state["daemon_host"] == server.runtime_host
    assert state["daemon_port"] == server.daemon_port()
    assert state["started_at"] == server.runtime_started_at
    snapshot = get_json(daemon, "/v1/runtime")
    assert protection_check(snapshot, "daemon")["status"] == "pass"
