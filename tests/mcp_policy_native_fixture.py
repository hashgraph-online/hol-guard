"""Authenticated, default-off policy admission for resident MCP decision tests."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

_ADMITTED: dict[Path, float] = {}
_FIXTURE_KEYS: dict[Path, bytes] = {}
_BINDINGS: dict[Path, dict] = {}


def admit_mcp_policy_home(home: Path) -> None:
    """Publish a real signed baseline; request layers never activate a pack."""
    from codex_plugin_scanner.guard.config import GuardConfig
    from codex_plugin_scanner.guard.native_policy_snapshot import (
        _policy_snapshot_push_bytes_v3,
        native_policy_snapshot_v3,
    )
    from codex_plugin_scanner.guard.native_policy_snapshot_publisher import provision_native_verifier_key_for_store
    from codex_plugin_scanner.guard.native_resident_client import native_resident_client_request
    from codex_plugin_scanner.guard.native_runtime import _isolated_environment, native_runtime_status
    from codex_plugin_scanner.guard.store import GuardStore

    if _ADMITTED.get(home, 0) > time.monotonic():
        return
    master_key = _FIXTURE_KEYS.get(home)
    if master_key is None:
        store = GuardStore(home)
        material = store._policy_integrity_secret_material(create=True)
        assert material is not None
        provision_native_verifier_key_for_store(store)
        master_key = material[0]
    status = native_runtime_status()
    assert status.identity is not None and status.capabilities is not None, status
    snapshot = native_policy_snapshot_v3(
        config=GuardConfig(guard_home=home, workspace=None),
        guard_home=home,
        runtime_identity=status.identity.sha256,
        rule_digest=status.capabilities.rule_digest,
        policy_integrity_key=master_key,
        command_extensions=_BINDINGS.get(home),
    )
    output = native_resident_client_request(
        executable=status.identity.path,
        guard_home=home,
        environment=_isolated_environment(),
        payload=_policy_snapshot_push_bytes_v3(snapshot, deadline_budget_ms=9000),
        deadline_monotonic=time.monotonic() + 10,
    )
    assert output is not None, "MCP fixture policy admission transport failed"
    ack = json.loads(output)
    assert ack.get("generation") == snapshot["generation"], ack
    _ADMITTED[home] = time.monotonic() + 30


@pytest.fixture(autouse=True)
def native_mcp_policy_admission(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch):
    """Supply daemon publication for decision tests that run without a daemon."""
    module = request.module.__name__.rsplit(".", 1)[-1]
    if module.startswith("test_native") and module != "test_native_mcp_tool_policy_lookup_inprocess":
        return
    from codex_plugin_scanner.guard import native_mcp_tool_policy, native_runtime

    real_request = native_mcp_tool_policy._resident_request

    def admitted_request(**kwargs):
        if native_runtime.native_mode() == "force":
            admit_mcp_policy_home(kwargs["guard_home"])
        return real_request(**kwargs)

    monkeypatch.setattr(native_mcp_tool_policy, "_resident_request", admitted_request)
