"""Real CLI parent death, separate from whole SDK-host and installed proof."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import selectors
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.approvals import apply_approval_resolution
from codex_plugin_scanner.guard.cli.commands_dispatch_local import _run_guard_execute_bound_bash_command
from codex_plugin_scanner.guard.native_bash_protocol import activity
from codex_plugin_scanner.guard.runtime.bound_bash_sink import run_bound_bash
from tests.test_native_bash_review_validation import pending as pending

pytestmark = pytest.mark.skipif(sys.platform != "darwin", reason="native Bash owner currently supports macOS")


def _wait_activity(operation_id, guard_home, predicate, *, seconds=4):
    deadline = time.monotonic() + seconds
    latest = None
    while time.monotonic() < deadline:
        latest = activity(operation_id, guard_home=guard_home)
        if predicate(latest):
            return latest
        time.sleep(0.02)
    raise AssertionError(f"native activity did not reach the required state: {latest}")


def test_real_cli_parent_death_cancels_authenticated_owner_before_once_claim(pending, tmp_path):
    store, request, contract, home = pending
    workspace = Path(request["workspace"])
    operation_id = "descriptor-fixture-operation"
    apply_approval_resolution(
        store=store,
        request_id=request["request_id"],
        action="allow",
        scope="artifact",
        workspace=str(workspace),
        reason="Lane-owned parent-death consent",
        persist_policy=False,
        scope_contract_version=contract.version,
        scope_contract_digest=contract.digest,
    )
    assert activity(operation_id, guard_home=store.guard_home) == {
        "operation_id": operation_id,
        "active": False,
        "cancellation_requested": False,
    }
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "bash",
        "cwd": str(workspace),
        "tool_input": {"command": request["raw_command_text"]},
    }
    directory = tmp_path / "hol-guard-contained-test-parent-death"
    directory.mkdir(mode=0o700)
    request_file = directory / "request.json"
    raw = json.dumps({"schema": "guard-contained-test-request.v1", "workspace": str(workspace), "payload": payload})
    request_file.write_text(raw)
    request_file.chmod(0o600)
    arguments = {
        "request_file": str(request_file),
        "request_sha256": hashlib.sha256(raw.encode()).hexdigest(),
        "harness": "omp",
        "operation_id": operation_id,
        "timeout_seconds": 30,
    }
    child = r"""
import argparse, json, sys
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0, sys.argv[1])
from codex_plugin_scanner.guard.cli.commands_dispatch_local import _run_guard_execute_bound_bash_command
from codex_plugin_scanner.guard.runtime import bound_bash_sink
from codex_plugin_scanner.guard.store import GuardStore
configuration = json.loads(sys.stdin.readline())
class FixtureSecrets:
    def __init__(self, values): self.values = values
    def get_secret(self, key): return self.values.get(key)
    def set_secret(self, key, value): self.values[key] = value
    def delete_secret(self, key): self.values.pop(key, None)
store = GuardStore(Path(configuration['guard_home']), prime_policy_integrity=False)
store._policy_integrity_secret_store = FixtureSecrets(configuration['fixture_secrets'])
execute = bound_bash_sink.execute
def synchronized_execute(request, **options):
    assert request['operation_id'] == configuration['arguments']['operation_id']
    assert request['authorization']['kind'] == 'saved_grant'
    print('ready-for-native-execute', flush=True)
    assert sys.stdin.readline() == 'dispatch\n'
    return execute(request, **options)
bound_bash_sink.execute = synchronized_execute
raise SystemExit(_run_guard_execute_bound_bash_command(
    argparse.Namespace(**configuration['arguments']), guard_home=store.guard_home,
    workspace=Path(configuration['workspace']), store=store,
    context=SimpleNamespace(home_dir=Path.home()),
))
"""
    configuration = {
        "guard_home": str(store.guard_home),
        "workspace": str(workspace),
        "arguments": arguments,
        # Only this isolated fixture's fake provider crosses the trusted pipe;
        # the adapter request file carries no integrity key or execution grant.
        "fixture_secrets": store._policy_integrity_secret_store.values,
    }
    process = subprocess.Popen(
        [sys.executable, "-c", child, str(Path(__file__).resolve().parents[1] / "src")],
        cwd=workspace,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    blocker = sqlite3.connect(store.path, timeout=5, isolation_level=None)
    try:
        process.stdin.write(json.dumps(configuration) + "\n")
        process.stdin.flush()
        with selectors.DefaultSelector() as readable:
            readable.register(process.stdout, selectors.EVENT_READ)
            assert readable.select(timeout=20), "real CLI did not prepare its saved authorization"
        ready = process.stdout.readline()
        assert ready == "ready-for-native-execute\n", (ready, process.poll())
        blocker.execute("BEGIN IMMEDIATE")
        process.stdin.write("dispatch\n")
        process.stdin.flush()
        observed = _wait_activity(operation_id, store.guard_home, lambda item: item["active"])
        assert observed["cancellation_requested"] is False
        assert not (home / "maintenance-report.tsv").exists()
        assert blocker.execute("select claimed_at from guard_local_once_approvals").fetchone()[0] is None
        process.kill()
        assert process.wait(timeout=3) < 0
        _wait_activity(operation_id, store.guard_home, lambda item: item["cancellation_requested"])
        blocker.execute("COMMIT")
        _wait_activity(operation_id, store.guard_home, lambda item: not item["active"])
        with store._connect() as connection:
            assert connection.execute("select claimed_at from guard_local_once_approvals").fetchone()[0] is None
            assert connection.execute("select count(*) from guard_bash_operations").fetchone()[0] == 0
        assert not (home / "maintenance-report.tsv").exists()
        assert (
            _run_guard_execute_bound_bash_command(
                argparse.Namespace(**arguments),
                guard_home=store.guard_home,
                workspace=workspace,
                context=SimpleNamespace(home_dir=home),
                store=store,
            )
            == 0
        )
        assert "local metadata" in (home / "maintenance-report.tsv").read_text()
        with store._connect() as connection:
            assert connection.execute("select claimed_at from guard_local_once_approvals").fetchone()[0] is not None
            assert connection.execute("select count(*) from guard_bash_operations").fetchone()[0] == 1
    finally:
        if blocker.in_transaction:
            blocker.execute("ROLLBACK")
        blocker.close()
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=5)


@pytest.mark.parametrize("owner", ["python-ancestor", "unrelated-child"])
def test_native_host_locator_refusal_is_specific_and_leaves_once_unspent(pending, owner):
    store, request, contract, home = pending
    workspace = Path(request["workspace"])
    apply_approval_resolution(
        store=store,
        request_id=request["request_id"],
        action="allow",
        scope="artifact",
        workspace=str(workspace),
        reason="Lane-owned host locator refusal",
        persist_policy=False,
        scope_contract_version=contract.version,
        scope_contract_digest=contract.digest,
    )
    unrelated = subprocess.Popen(["/bin/sleep", "30"]) if owner == "unrelated-child" else None
    try:
        pid = unrelated.pid if unrelated is not None else os.getpid()
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "bash",
            "cwd": str(workspace),
            "tool_input": {"command": request["raw_command_text"]},
        }
        errors = io.StringIO()
        assert (
            run_bound_bash(
                payload,
                store=store,
                workspace=workspace,
                harness="omp",
                operation_id="descriptor-fixture-operation",
                host_owner_pid=pid,
                output=io.StringIO(),
                errors=errors,
            )
            == 125
        )
        assert "native_bash_host_owner_unavailable" in errors.getvalue()
        assert not (home / "maintenance-report.tsv").exists()
        with store._connect() as connection:
            assert connection.execute("select claimed_at from guard_local_once_approvals").fetchone()[0] is None
            assert connection.execute("select count(*) from guard_bash_operations").fetchone()[0] == 0
        # A direct CLI caller retains its separate inherited-pipe supervision.
        assert (
            run_bound_bash(
                payload,
                store=store,
                workspace=workspace,
                harness="omp",
                operation_id="descriptor-fixture-operation",
                output=io.StringIO(),
                errors=io.StringIO(),
            )
            == 0
        )
        assert "local metadata" in (home / "maintenance-report.tsv").read_text()
    finally:
        if unrelated is not None:
            unrelated.kill()
            unrelated.wait(timeout=3)
