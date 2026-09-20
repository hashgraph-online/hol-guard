"""Actual cross-process installation retirement of source-built native authority.

HTTP, enrollment and V4 capability negotiation are explicit test fixtures.
Control selection, key access, signed IPC, retirement, SQL and hooks are real.
These cases do not establish installed-artifact or production V4 support.
"""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_hook_edge
from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_policy_snapshot_codec import derive_native_policy_verifier_key
from codex_plugin_scanner.guard.native_policy_snapshot_constants import _PUBLISH_TIMEOUT_SECONDS
from codex_plugin_scanner.guard.native_policy_snapshot_contract import _policy_snapshot_push_bytes_v3
from codex_plugin_scanner.guard.native_policy_snapshot_control import observe_native_authority
from codex_plugin_scanner.guard.native_policy_snapshot_storage import _read_v3_generation_state
from codex_plugin_scanner.guard.native_policy_snapshot_v4_transport import snapshot_push_bytes_v4
from codex_plugin_scanner.guard.native_resident_client import native_resident_client_request
from codex_plugin_scanner.guard.native_runtime import _isolated_environment
from codex_plugin_scanner.guard.policy_bundle_materialization import POLICY_BUNDLE_MATERIALIZATION_KEY
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.sqlite_tuning import sqlite_connect_timeout_seconds
from codex_plugin_scanner.guard.store import GuardStore
from scripts.native_slo_session import stop_native_resident
from tests.native_sensitive_resident_fixtures import sensitive_test_status
from tests.support.network import stub_authenticated_urlopen
from tests.test_native_generic_sync_resident import _source
from tests.test_policy_bundle_v2_runtime_admission import _SyncResponse

_ROTATION_PROCESS = """
import json
import os
import sqlite3
import sys
from pathlib import Path
from codex_plugin_scanner.guard.store import GuardStore

store = GuardStore(Path(sys.argv[1]))
before = store.get_device_metadata()
try:
    result = store.rotate_installation_id(sys.argv[2])
except sqlite3.IntegrityError as error:
    if str(error) != "synthetic_retirement_sql_refusal":
        raise
    result = None
    status = "sql-refused"
else:
    status = "rotated"
print(json.dumps({"status": status, "pid": os.getpid(), "before": before,
                  "after": store.get_device_metadata(), "result": result}))
"""


def _rotate_in_another_process(store: GuardStore) -> dict[str, Any]:
    # This is an outer fixture containment bound. The child uses the unchanged
    # public operation budget; no timeout override or injected control peer.
    result = subprocess.run(
        [sys.executable, "-c", _ROTATION_PROCESS, str(store.guard_home), datetime.now(timezone.utc).isoformat()],
        cwd=Path(__file__).resolve().parents[1],
        check=False,
        capture_output=True,
        text=True,
        timeout=sqlite_connect_timeout_seconds(),
    )
    assert result.returncode == 0, "the actual rotation subprocess must complete"
    value = json.loads(result.stdout)
    assert isinstance(value, dict) and value["pid"] != os.getpid()
    return value


def test_rotation_probe_calls_actual_store_in_a_new_process(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "cold")
    before = store.get_device_metadata()
    outcome = _rotate_in_another_process(store)
    assert outcome["status"] == "rotated" and outcome["before"] == before
    assert outcome["after"] == outcome["result"] == store.get_device_metadata()
    assert outcome["after"]["installation_id"] != before["installation_id"]
    assert not (store.guard_home / "native-runtime").exists()


@pytest.mark.slow
@pytest.mark.parametrize("shape", ["v3", "v4"])
@pytest.mark.parametrize("sql_failure", [False, True], ids=["commit", "sql-refusal"])
def test_installation_retirement_fences_actual_resident_across_processes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, shape: str, sql_failure: bool
) -> None:
    for name in ("HOL_GUARD_TEST_MODE", "HOL_GUARD_PYTHON_ORACLE", "HOL_GUARD_NATIVE_DIAGNOSTIC"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")
    status = sensitive_test_status()
    assert status.identity is not None and status.capabilities is not None
    assert "policy-snapshot-control-v1" in status.capabilities.features
    executable, runtime_identity = status.identity.path, status.identity.sha256
    # Only V4 publication/edge negotiation is staged. The child rotation uses
    # fresh ordinary native selection and the actually advertised control API.
    monkeypatch.setattr(native_hook_edge, "native_runtime_status", lambda: status)
    store, workspace, bundle = _source(tmp_path, "scoped")
    publisher = NativePolicySnapshotPublisher(store=store, status_provider=lambda: status)
    current: NativePolicySnapshotPublisher | None = None

    def exchange(request: Any, timeout: object = None) -> _SyncResponse:
        if request.full_url.endswith("/api/guard/receipts/sync"):
            return _SyncResponse(
                {"syncedAt": datetime.now(timezone.utc).isoformat(), "receiptsStored": 0, "policyBundle": bundle}
            )
        return _SyncResponse({"accepted": 0, "rejected": 0, "statuses": []})

    stub_authenticated_urlopen(monkeypatch, exchange)

    def sync() -> dict[str, object]:
        return runner.sync_receipts(
            store,
            auth_context={
                "sync_url": "https://hol.org/api/guard/receipts/sync",
                "access_token": "synthetic-test-token",
                "dpop_key_material": None,
            },
        )

    def edge(binding: dict[str, object], event: str) -> dict[str, Any] | None:
        return native_hook_edge.review_raw_hook_native(
            payload={"tool_name": "Shell", "tool_input": {"command": "printf synthetic"}, "tool_response": "synthetic"},
            harness="codex",
            event=event,
            guard_home=store.guard_home,
            home_dir=tmp_path,
            cwd=workspace,
            source_ref_external_allowed=False,
            observe_mode=False,
            deadline=time.monotonic() + 5,
            policy_snapshot=binding,
        )

    try:
        if shape == "v4":
            publisher.start()
            assert publisher.wait_until_ready(), publisher.last_error
            admitted = sync()
            assert admitted["policy_application_status"] == "applied", (admitted, publisher.last_error)
        else:
            publisher._publish_once()
        assert publisher.is_ready(), publisher.last_error
        previous = publisher.current_snapshot_binding()
        assert previous is not None
        assert ("source_input_digest" in previous) is (shape == "v4")
        old_generation = previous["generation"]
        assert isinstance(old_generation, int)
        if shape == "v4":
            publication = publisher._v4_publication
            assert publication is not None
            assert publication.candidate.inputs.authority.rows
            replay = snapshot_push_bytes_v4(publication.candidate)
        else:
            snapshot = publisher.current_snapshot()
            assert snapshot is not None
            replay = _policy_snapshot_push_bytes_v3(snapshot)
        for event in ("PreToolUse", "PostToolUse"):
            accepted = edge(previous, event)
            if shape == "v4" and event == "PostToolUse":
                # Active scoped rows have no supported post-tool producer.
                assert accepted is None, (shape, event)
            else:
                assert accepted is not None and accepted["authority"] == "rust", (shape, event)
                assert accepted["receipt"]["policy_generation"] == old_generation
        # Stop publication, retaining the native resident and captured binding.
        # A remote process cannot invalidate this process's in-memory object.
        publisher.close()
        before = store.get_device_metadata()
        preserved = ("policy_bundle", "policy_bundle_last_good", "policy_bundle_keyring", "policy_bundle_checkpoint")
        source_before = {key: store.get_sync_payload(key) for key in preserved}
        derived = ("policy_bundle_ack", POLICY_BUNDLE_MATERIALIZATION_KEY, "native_policy_bundle_ack_acceptance")
        derived_before = {key: store.get_sync_payload(key) for key in derived}
        rows_before = store.list_policy_decisions()
        master, _ = store._policy_integrity_secret_material(create=False)
        assert type(master) is bytes and len(master) == 32
        verifier = derive_native_policy_verifier_key(master)

        def observe():
            return observe_native_authority(
                executable=executable,
                guard_home=store.guard_home,
                runtime_identity=runtime_identity,
                verifier_key=verifier,
                deadline_monotonic=time.monotonic() + _PUBLISH_TIMEOUT_SECONDS,
            )

        initial = observe()
        assert initial.authority is not None and initial.authority.usable_snapshot
        assert initial.authority.generation_floor == old_generation
        if sql_failure:
            with sqlite3.connect(store.path) as connection:
                connection.execute(
                    "create trigger refuse_rotation before update of installation_id on guard_devices "
                    "begin select raise(abort, 'synthetic_retirement_sql_refusal'); end"
                )
        outcome = _rotate_in_another_process(store)
        assert outcome["before"] == before
        assert outcome["after"] == store.get_device_metadata()
        assert {key: store.get_sync_payload(key) for key in preserved} == source_before
        if sql_failure:
            assert outcome["status"] == "sql-refused" and outcome["result"] is None
            assert outcome["after"] == before
            assert {key: store.get_sync_payload(key) for key in derived} == derived_before
            assert store.list_policy_decisions() == rows_before
        else:
            assert outcome["status"] == "rotated" and outcome["result"] == outcome["after"]
            assert outcome["after"]["installation_id"] != before["installation_id"]
            assert all(store.get_sync_payload(key) is None for key in derived)
            assert all(row["source"] == "local" for row in store.list_policy_decisions())
        reserved = _read_v3_generation_state(store.guard_home)
        assert reserved is not None and reserved[0] > old_generation
        retired = observe()
        assert retired.resident_generation == initial.resident_generation
        assert retired.authority is not None and not retired.authority.usable_snapshot
        assert (retired.authority.generation_floor, retired.authority.policy_digest) == reserved

        for restart in (False, True):
            if restart:
                assert stop_native_resident(executable, store.guard_home, write_diagnostic=False).contained
                restarted = observe()
                assert restarted.resident_generation != initial.resident_generation
                assert restarted.authority is not None and not restarted.authority.usable_snapshot
                assert (restarted.authority.generation_floor, restarted.authority.policy_digest) == reserved
            for event in ("PreToolUse", "PostToolUse"):
                assert edge(previous, event) is None
            output = native_resident_client_request(
                executable=executable,
                guard_home=store.guard_home,
                environment=_isolated_environment(),
                payload=replay,
                deadline_monotonic=time.monotonic() + _PUBLISH_TIMEOUT_SECONDS,
            )
            assert output is not None, "native replay must return an explicit refusal"
            refused = json.loads(output)
            if shape == "v3":
                assert refused["status"] == "native_policy_snapshot_requires_new_generation"
                assert (refused["generation"], refused["policy_digest"]) == reserved
            else:
                assert refused["error"] == "native_policy_snapshot_generation_reused"
            assert _read_v3_generation_state(store.guard_home) == reserved
            assert observe().authority == retired.authority

        if sql_failure:
            with sqlite3.connect(store.path) as connection:
                connection.execute("drop trigger refuse_rotation")
        current = NativePolicySnapshotPublisher(store=store, status_provider=lambda: status)
        if shape == "v4":
            current.start()
            readmitted = sync()
            assert readmitted["policy_application_status"] == "applied", (readmitted, current.last_error)
            ack = store.get_sync_payload("policy_bundle_ack")
            assert isinstance(ack, dict) and ack["deviceId"] == outcome["after"]["installation_id"]
        else:
            current._publish_once()
        assert current.is_ready(), current.last_error
        fresh = current.current_snapshot_binding()
        assert fresh is not None
        assert isinstance(fresh["generation"], int) and fresh["generation"] > reserved[0]
        if shape == "v4":
            assert current._v4_publication is not None
            assert current._v4_publication.candidate.inputs.authority.rows
        for event in ("PreToolUse", "PostToolUse"):
            accepted = edge(fresh, event)
            if shape == "v4" and event == "PostToolUse":
                assert accepted is None, (shape, event)
            else:
                assert accepted is not None and accepted["authority"] == "rust", (shape, event)
                assert accepted["receipt"]["policy_generation"] == fresh["generation"]
            assert edge(previous, event) is None
    finally:
        publisher.close()
        if current is not None:
            current.close()
        assert stop_native_resident(executable, store.guard_home, write_diagnostic=False).contained
