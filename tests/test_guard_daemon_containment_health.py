from __future__ import annotations

import json
import urllib.error
import urllib.request
from http.client import HTTPResponse
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.daemon.client import GuardSurfaceDaemonClient
from codex_plugin_scanner.guard.daemon.manager import (
    current_guard_daemon_runtime_fingerprint,
    load_guard_daemon_auth_token,
)
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.runtime.containment_health import ContainmentHealthEvidence
from codex_plugin_scanner.guard.store import GuardStore


def test_authenticated_daemon_returns_fresh_execution_owned_health(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    daemon = GuardDaemonServer(GuardStore(guard_home), host="127.0.0.1", port=0)
    daemon.start()
    try:
        auth_token = load_guard_daemon_auth_token(guard_home)
        assert auth_token is not None
        client = GuardSurfaceDaemonClient(
            f"http://127.0.0.1:{daemon.port}",
            auth_token,
        )
        payload = client.containment_health()
        runtime_request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/runtime?include_items=false&include_receipts=false",
            headers={"X-Guard-Token": auth_token},
            method="GET",
        )
        with cast(HTTPResponse, urllib.request.urlopen(runtime_request, timeout=5)) as response:
            raw_runtime_payload = cast(object, json.loads(response.read().decode("utf-8")))
    finally:
        daemon.stop()

    evidence = ContainmentHealthEvidence.from_mapping(payload)
    assert (
        evidence.compatibility_errors(
            now=_parsed_probe_time(evidence),
            runtime_fingerprint=current_guard_daemon_runtime_fingerprint(),
        )
        == ()
    )
    serialized = json.dumps(payload, sort_keys=True)
    assert str(tmp_path) not in serialized
    assert "command" not in serialized
    assert "environment" not in serialized
    assert isinstance(raw_runtime_payload, dict)
    runtime_payload = cast(dict[str, object], raw_runtime_payload)
    protection_health = runtime_payload.get("protection_health")
    assert isinstance(protection_health, dict)
    raw_checks = cast(dict[str, object], protection_health).get("checks")
    assert isinstance(raw_checks, list)
    checks: dict[str, dict[str, object]] = {}
    for raw_item in cast(list[object], raw_checks):
        assert isinstance(raw_item, dict)
        item = cast(dict[str, object], raw_item)
        check_id = item.get("check_id")
        assert isinstance(check_id, str)
        checks[check_id] = item
    assert checks["containment_compatibility"]["status"] == "pass"
    assert checks["sandbox"]["status"] == "pass"


def test_containment_health_endpoint_rejects_missing_token(tmp_path: Path) -> None:
    daemon = GuardDaemonServer(GuardStore(tmp_path / "guard-home"), host="127.0.0.1", port=0)
    daemon.start()
    try:
        request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/runtime/containment-health",
            method="GET",
        )
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request, timeout=5)
    finally:
        daemon.stop()

    assert error.value.code == 401


def _parsed_probe_time(evidence: ContainmentHealthEvidence):
    from datetime import datetime

    return datetime.fromisoformat(evidence.probe_at)
