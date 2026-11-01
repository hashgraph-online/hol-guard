"""Qualify the actual HTTP effect barrier before longer optional-runtime cases."""

from __future__ import annotations

import io
import json
import os
import sys

import pytest

from codex_plugin_scanner.guard.approval_scope_support import request_scope_contract
from codex_plugin_scanner.guard.approvals import apply_approval_resolution
from codex_plugin_scanner.guard.native_bash_protocol import runtime_status
from codex_plugin_scanner.guard.native_context_assistance import control
from codex_plugin_scanner.guard.native_resident_client import close_native_residents
from codex_plugin_scanner.guard.runtime.bound_bash_sink import run_bound_bash
from codex_plugin_scanner.guard.store import GuardStore
from tests.context_execution_barrier import NativeEffectBarrier
from tests.context_persistence_installed_support import operator


@pytest.mark.integration
@pytest.mark.installed
@pytest.mark.skipif(
    sys.platform != "darwin" or os.environ.get("HOL_GUARD_TEST_USE_INSTALLED") != "1",
    reason="requires the explicitly selected installed macOS native executor",
)
def test_supported_http_barrier_requires_native_consent_and_delivers(native_context_digest, tmp_path, monkeypatch):
    del native_context_digest
    status = runtime_status()
    assert status.identity is not None
    project, home, guard = tmp_path / "project", tmp_path / "profile", tmp_path / "guard"
    project.mkdir(mode=0o700)
    home.mkdir(mode=0o700)
    monkeypatch.chdir(project)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("PATH", f"{project}:/usr/bin:/bin")
    store = GuardStore(guard, prime_policy_integrity=False)
    entry = project / "execution.sh"
    with NativeEffectBarrier() as barrier:
        entry.write_text(
            ': > "$HOME/execution-report.txt"\nprintf "installed-cigar-owner\\n" >> "$HOME/execution-report.txt"\n'
            f'/usr/bin/curl -q -fsS --max-time 30 "{barrier.endpoint}"\n'
            'printf "native-effect-completed\\n" >> "$HOME/execution-report.txt"\n'
        )
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "bash",
            "cwd": str(project),
            "tool_input": {"command": f"/bin/bash '{entry}'"},
        }

        def run():
            errors = io.StringIO()
            result = run_bound_bash(
                payload,
                store=store,
                workspace=project,
                harness="omp",
                operation_id="native-http-barrier-preflight-0001",
                output=io.StringIO(),
                errors=errors,
            )
            return result, errors.getvalue()

        try:
            configured = operator(
                status.identity.path,
                "guard-config-update",
                {
                    "schema": "guard-config-update.v1",
                    "guard_home": str(guard),
                    "kind": "settings",
                    "value_text": json.dumps({"subprocess_action": "review"}),
                },
            )
            assert configured["ok"]
            result, error = run()
            assert result == 125 and "native_bash_consent_required" in error
            assert not barrier.entered.is_set() and not (home / "execution-report.txt").exists()
            (queued,) = store.list_approval_requests()
            contract = request_scope_contract(queued, guard_home=guard)
            assert contract.can_run_once and contract.can_persist_exact_version
            apply_approval_resolution(
                store=store,
                request_id=queued["request_id"],
                action="allow",
                scope="artifact",
                workspace=str(project),
                reason="Owned HTTP execution barrier preflight",
                persist_policy=False,
                scope_contract_version=queued["scope_contract_version"],
                scope_contract_digest=queued["scope_contract_digest"],
            )
            barrier.release.set()
            result, error = run()
            assert result == 0, error
            assert barrier.entered.is_set()
            assert (home / "execution-report.txt").read_text() == "installed-cigar-owner\nnative-effect-completed\n"
            assert control("status", guard_home=guard)["runtime"] is None
        finally:
            assert close_native_residents(guard)
