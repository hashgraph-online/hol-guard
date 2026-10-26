"""Real native hook admission remains denied until adapter-owned delivery."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters._modules.pi.pi_extension_bound_bash_source import _ENVIRONMENT_NAMES
from codex_plugin_scanner.guard.config import update_guard_settings
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.hook_execution_environment import (
    HOOK_EXECUTION_ENVIRONMENT_KEY,
    collect_hook_execution_environment,
)
from codex_plugin_scanner.guard.native_resident_client import close_native_residents
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_native_bash_sink_integration import _Secrets

pytestmark = pytest.mark.skipif(sys.platform != "darwin", reason="native Bash owner is macOS-only")


@pytest.mark.parametrize("harness", ["omp", "pi"])
@pytest.mark.parametrize(
    "case",
    [
        "owner",
        "old-client",
        "old-owner",
        "old-result-owner",
        "wrong-host",
        "hard-deny",
        "unbound-helper",
        "delete-mode",
        "ordinary",
    ],
)
def test_native_hook_routes_only_supported_bound_owners(native_context_digest, tmp_path, monkeypatch, harness, case):
    del native_context_digest
    project, home, guard = tmp_path / "project", tmp_path / "home", tmp_path / "guard"
    project.mkdir()
    home.mkdir()
    fixtures = Path(__file__).parent / "fixtures" / "script_approvals"
    for name in ("maintenance.sh", "fixture-registry"):
        target = project / name
        target.write_bytes((fixtures / name).read_bytes())
        target.chmod(0o700)
    if case == "unbound-helper":
        (project / "fixture-registry").write_text('#!/bin/bash\neval "$1"\n')
    monkeypatch.chdir(project)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("PATH", f"{project}:/usr/bin:/bin")
    if case == "hard-deny":
        update_guard_settings(guard, {"subprocess_action": "block"})
    store = GuardStore(guard, prime_policy_integrity=False)
    store._policy_integrity_secret_store = _Secrets()
    worker = HookWorker(store=store, workspace=project, home_dir=home, wait_for_native_policy=False)
    try:
        assert worker.prepare_workspace_policy(project, deadline=time.monotonic() + 25) is not None, (
            worker.policy_snapshot_publisher.last_error
        )
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "bash",
            "session_id": "delivery-session",
            "tool_call_id": "delivery-call",
            "cwd": str(project),
            "tool_input": {"command": f"/bin/bash '{project / 'maintenance.sh'}' dry"},
            HOOK_EXECUTION_ENVIRONMENT_KEY: collect_hook_execution_environment(),
            "guard_bound_bash_host": {
                "schema": "guard-native-bash-host-delivery.v3",
                "owner_pid": os.getpid(),
                "host": "omp-input-rewrite-v1" if harness == "omp" else "pi-input-mutation-v1",
                "environment": {name: os.environ[name] for name in _ENVIRONMENT_NAMES if os.environ.get(name)},
                "file_creation_mask": 0o022,
            },
        }
        if case == "old-client":
            del payload["guard_bound_bash_host"]
        elif case == "old-owner":
            payload["guard_bound_bash_host"]["schema"] = "guard-native-bash-host-delivery.v1"
            del payload["guard_bound_bash_host"]["owner_pid"]
        elif case == "wrong-host":
            payload["guard_bound_bash_host"]["host"] = "unsupported-host"
        elif case == "old-result-owner":
            payload["guard_bound_bash_host"]["schema"] = "guard-native-bash-host-delivery.v2"
        elif case == "delete-mode":
            payload["tool_input"]["command"] = f"/bin/bash '{project / 'maintenance.sh'}' delete"
        elif case == "ordinary":
            payload["tool_input"]["command"] = "printf harmless"
        response = worker.review_http_payload(
            payload=payload,
            params={},
            default_harness=harness,
            workspace=project,
            home_dir=home,
            guard_home=guard,
        )
        if case != "ordinary":
            assert response["decision"] == "deny"
        if case == "owner":
            assert response["policy_action"] == "sandbox-required"
            assert response["reason_code"] == "native_bash_owner_required"
            assert response["required_execution_profile"] == "native-bash-owner-v1"
            assert store.list_approval_requests() == []
        else:
            assert response.get("reason_code") != "native_bash_owner_required"
            assert response.get("required_execution_profile") != "native-bash-owner-v1"
            if case == "hard-deny":
                assert response["policy_action"] == "block"
            elif case in {"old-owner", "old-result-owner", "wrong-host", "unbound-helper", "delete-mode"}:
                assert response["policy_action"] == "block"
                assert response["reason_code"] == "native_bash_owner_unavailable"
                assert "required_execution_profile" not in response
        assert not (home / "maintenance-report.tsv").exists()
        with store._connect() as connection:
            assert connection.execute("select count(*) from guard_bash_operations").fetchone()[0] == 0
            assert connection.execute("select count(*) from guard_local_once_approvals").fetchone()[0] == 0
    finally:
        worker.close()
        assert close_native_residents(guard_home=guard)
