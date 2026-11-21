"""Actual warm hooks during authenticated resident metadata work.

Only publisher/credential IO is synthetic. The native resident, policy push,
metadata preparation/read, hook adapter and both hook decisions are real.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard import native_catalog_read as native
from codex_plugin_scanner.guard import store as store_module
from codex_plugin_scanner.guard.catalog_delivery import discovery
from codex_plugin_scanner.guard.catalog_delivery.authority import VerifiedDistribution
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_resident_client import close_native_residents
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_extension_control_authority_fixtures import MemorySecretStore
from tests.test_native_command_control_binding_publisher import (
    _pinned_integrity_material_and_resident_key as _pinned_integrity_material_and_resident_key,
)


@pytest.mark.skipif(not os.environ.get("HOL_GUARD_CATALOG_EXPORT"), reason="requires exported native metadata fixture")
def test_warm_hooks_keep_decisions_during_large_metadata_scans(tmp_path, monkeypatch, native_hook_force):
    home = tmp_path.resolve()
    backend = MemorySecretStore()
    monkeypatch.setattr(store_module, "_build_policy_integrity_secret_store", lambda *args, **kwargs: backend)
    (home / "config.toml").write_text(
        'protection_posture = "protected"\ndefault_action = "allow"\n'
        'subprocess_action = "allow"\nsandbox_analysis = "off"\n'
    )
    store = GuardStore(home)
    publisher = NativePolicySnapshotPublisher(store=store)
    event = home / "event.json"

    def hook(command):
        event.write_text(
            json.dumps(
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": command},
                    "cwd": str(home),
                }
            )
        )
        output = io.StringIO()
        started = time.monotonic()
        with contextlib.redirect_stdout(output):
            main(
                [
                    "guard",
                    "hook",
                    "--guard-home",
                    str(home),
                    "--home",
                    str(home),
                    "--harness",
                    "claude-code",
                    "--event-file",
                    str(event),
                    "--json",
                ]
            )
        value = json.loads(output.getvalue())
        return value["hookSpecificOutput"]["permissionDecision"], time.monotonic() - started

    timings = {"baseline": [], "during": [], "after": []}
    try:
        publisher._publish_once()
        assert publisher.is_ready(), publisher.last_error
        for command, expected in [("pwd", "allow"), ("rm -rf /", "deny")]:
            decision, elapsed = hook(command)
            assert decision == expected
            timings["baseline"].append(elapsed)
        fixture = Path(os.environ["HOL_GUARD_CATALOG_EXPORT"]) / "16600"
        data = (fixture / "root.json").read_bytes()
        root = json.loads(data)
        authority = object.__new__(VerifiedDistribution)
        for name, value in {
            "data": data,
            "digest": hashlib.sha256(data).hexdigest(),
            "source_sha": root["source_sha"],
            "expires_at": root["expires_at"],
        }.items():
            object.__setattr__(authority, name, value)

        def fetch(location, maximum):
            value = (fixture / "origin" / location["asset"][7:]).read_bytes()
            assert len(value) == maximum
            return value

        handle = discovery.prepare_discovery(home, authority, fetch=fetch)
        ready = native.native_catalog_read(
            guard_home=home,
            discovery_handle=handle,
            route="index",
            query="limit=1",
            if_none_match=None,
            expected_catalog_digest="b" * 64,
            timeout_seconds=2,
        )
        assert ready is not None and ready.status == 200
        barrier = threading.Barrier(9)

        def scan(index):
            barrier.wait(timeout=10)
            statuses = []
            for _ in range(2):
                result = native.native_catalog_read(
                    guard_home=home,
                    discovery_handle=handle,
                    route="index" if index % 2 else "permissions",
                    query="limit=1",
                    if_none_match=None,
                    expected_catalog_digest="b" * 64,
                    timeout_seconds=2,
                )
                statuses.append(result.status if result is not None else 501)
            return statuses

        with ThreadPoolExecutor(max_workers=8) as pool:
            work = [pool.submit(scan, index) for index in range(8)]
            barrier.wait(timeout=10)
            time.sleep(0.1)
            for command, expected in [("pwd", "allow"), ("rm -rf /", "deny")] * 3:
                decision, elapsed = hook(command)
                timings["during"].append(elapsed)
                assert decision == expected, (command, decision, timings)
                assert elapsed < 2, timings
            statuses = [future.result(timeout=30) for future in work]
            assert all(status in {200, 503} for results in statuses for status in results), statuses
        for command, expected in [("pwd", "allow"), ("rm -rf /", "deny")]:
            decision, elapsed = hook(command)
            assert decision == expected
            timings["after"].append(elapsed)
        print("native-catalog-fairness " + json.dumps({"timings": timings, "metadata_statuses": statuses}))
    finally:
        assert publisher.close()
        close_native_residents(guard_home=home)
