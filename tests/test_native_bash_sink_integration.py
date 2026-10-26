"""Source-built CLI-sink/resident proof; separate from installed OMP evidence."""

from __future__ import annotations

import argparse
import copy
import hashlib
import io
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.approval_scope_support import request_scope_contract
from codex_plugin_scanner.guard.approvals import apply_approval_resolution
from codex_plugin_scanner.guard.cli.commands_dispatch_local import _run_guard_execute_bound_bash_command
from codex_plugin_scanner.guard.daemon.hook_native_review_approval import queue_native_pre_tool_review
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.native_bash_protocol import ARTIFACT_ID, ARTIFACT_TYPE, runtime_status
from codex_plugin_scanner.guard.native_resident_client import close_native_residents
from codex_plugin_scanner.guard.runtime import bound_bash_sink
from codex_plugin_scanner.guard.runtime.bound_bash_sink import run_bound_bash
from codex_plugin_scanner.guard.store import GuardStore


class _Secrets:
    def __init__(self):
        self.values = {}

    def get_secret(self, key):
        return self.values.get(key)

    def set_secret(self, key, value):
        self.values[key] = value

    def delete_secret(self, key):
        self.values.pop(key, None)


@pytest.mark.skipif(sys.platform != "darwin", reason="native immutable Bash owner currently supports macOS")
@pytest.mark.parametrize(
    "duration,home_in_workspace",
    [
        ("quiet", True),
        ("quiet-raced-block", True),
        ("once", False),
        ("once-default", False),
        ("persistent", False),
        ("keep-blocked", False),
        ("keep-blocked-default", False),
        ("keep-blocked-saved-allow", False),
    ],
)
def test_real_sink_quiet_replay_and_current_persistence_review(
    native_context_digest,
    tmp_path,
    monkeypatch,
    home_in_workspace,
    duration,
):
    del native_context_digest
    runtime_status()  # A lane with an old binary must fail, not count a skipped proof.
    original_prepare = HookWorker.prepare_workspace_policy

    def checked_prepare(worker, *args, **kwargs):
        result = original_prepare(worker, *args, **kwargs)
        assert result is not None, worker.policy_snapshot_publisher.last_error
        return result

    monkeypatch.setattr(HookWorker, "prepare_workspace_policy", checked_prepare)
    project, guard = tmp_path / "project", tmp_path / "guard"
    home = (project if home_in_workspace else tmp_path) / "home"
    project.mkdir()
    home.mkdir()
    fixtures = Path(__file__).parent / "fixtures" / "script_approvals"
    for name in ("maintenance.sh", "fixture-registry"):
        target = project / name
        target.write_bytes((fixtures / name).read_bytes())
        target.chmod(0o700)
    monkeypatch.chdir(project)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("PATH", f"{project}:/usr/bin:/bin")
    store = GuardStore(guard, prime_policy_integrity=False)
    store._policy_integrity_secret_store = _Secrets()
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "bash",
        "tool_input": {"command": f"/bin/bash '{project / 'maintenance.sh'}' dry"},
        "cwd": str(project),
    }
    output, errors = io.StringIO(), io.StringIO()
    try:
        if not home_in_workspace:
            prepared_evidence = []
            native_prepare = bound_bash_sink.prepare

            def capture_prepared(*args, **kwargs):
                prepared = native_prepare(*args, **kwargs)
                prepared_evidence.append(prepared)
                return prepared

            monkeypatch.setattr(bound_bash_sink, "prepare", capture_prepared)
            assert (
                run_bound_bash(
                    payload,
                    store=store,
                    workspace=project,
                    harness="omp",
                    operation_id="sink-fixture-operation-1",
                    output=output,
                    errors=errors,
                )
                == 125
            )
            assert "native_bash_consent_required" in errors.getvalue()
            assert not (home / "maintenance-report.tsv").exists()
            with store._connect() as connection:
                assert connection.execute("select count(*) from guard_bash_operations").fetchone()[0] == 0
            pending = store.list_approval_requests()
            assert len(pending) == 1
            prepared = prepared_evidence[-1]
            prepared["review_lineage"] = pending[0]["action_envelope_json"]["native_bash"]["review_lineage"]
            altered = copy.deepcopy(prepared["review"]["decision"])
            altered["reason_code"] = "forged_review_reason"
            assert (
                queue_native_pre_tool_review(
                    store,
                    harness="omp",
                    payload=payload,
                    native_result=altered,
                    native_receipt=prepared["review"]["receipt"],
                    workspace=project,
                    guard_home=guard,
                    home_dir=home,
                    exact_token=prepared["artifact_hash"],
                    review_binding=prepared["artifact_hash"],
                    bound_bash=prepared,
                )
                is None
            )
            assert len(store.list_approval_requests()) == 1
            monkeypatch.setattr(bound_bash_sink, "prepare", native_prepare)
            queued = pending[0]
            assert queued["artifact_id"] == ARTIFACT_ID and queued["artifact_type"] == ARTIFACT_TYPE
            assert queued["action_envelope_json"]["native_bash"]["subject"]["schema"] == "guard.bash-subject.v1"
            if duration.startswith("keep-blocked"):
                lineage = queued["action_envelope_json"]["native_bash"]["review_lineage"]
                assert lineage["operation_id"] == "sink-fixture-operation-1"
                assert lineage["expires_at_ms"] - lineage["created_at_ms"] == 86_400_000
                assert (
                    run_bound_bash(
                        payload,
                        store=store,
                        workspace=project,
                        harness="omp",
                        operation_id="sink-fixture-operation-1",
                        output=output,
                        errors=errors,
                    )
                    == 125
                )
                assert [row["request_id"] for row in store.list_approval_requests()] == [queued["request_id"]]
                assert (
                    run_bound_bash(
                        payload,
                        store=store,
                        workspace=project,
                        harness="omp",
                        operation_id="sink-existing-other-intent",
                        output=output,
                        errors=errors,
                    )
                    == 125
                )
                other = [row for row in store.list_approval_requests() if row["request_id"] != queued["request_id"]]
                assert len(other) == 1
                other_id = other[0]["request_id"]
                apply_approval_resolution(
                    store=store,
                    request_id=queued["request_id"],
                    action="block",
                    scope="artifact",
                    workspace=str(project),
                    reason="Lane-owned Keep blocked",
                    persist_policy=None if duration == "keep-blocked-default" else False,
                    scope_contract_version=queued["scope_contract_version"],
                    scope_contract_digest=queued["scope_contract_digest"],
                )
                pending_after_block = [other_id]
                if duration == "keep-blocked-saved-allow":
                    apply_approval_resolution(
                        store=store,
                        request_id=other_id,
                        action="allow",
                        scope="artifact",
                        workspace=str(project),
                        reason="Lane-owned other intent exact-version allow",
                        persist_policy=True,
                        scope_contract_version=other[0]["scope_contract_version"],
                        scope_contract_digest=other[0]["scope_contract_digest"],
                    )
                    pending_after_block = []
                for iteration in range(2):
                    assert close_native_residents(guard_home=guard)
                    errors.seek(0)
                    errors.truncate()
                    assert (
                        run_bound_bash(
                            {**payload, "tool_call_id": f"reissued-{iteration}"},
                            store=store,
                            workspace=project,
                            harness="omp",
                            operation_id="sink-fixture-operation-1",
                            output=output,
                            errors=errors,
                        )
                        == 125
                    )
                    assert "native_bash_operation_kept_blocked" in errors.getvalue()
                    assert "requires consent" not in errors.getvalue()
                    assert [row["request_id"] for row in store.list_approval_requests()] == pending_after_block
                assert not (home / "maintenance-report.tsv").exists()
                if duration == "keep-blocked-saved-allow":
                    assert (
                        run_bound_bash(
                            payload,
                            store=store,
                            workspace=project,
                            harness="omp",
                            operation_id="sink-fresh-saved-allow",
                            output=output,
                            errors=errors,
                        )
                        == 0
                    )
                    assert "local metadata" in (home / "maintenance-report.tsv").read_text()
                    assert store.list_approval_requests() == []
                    return
                assert (
                    run_bound_bash(
                        payload,
                        store=store,
                        workspace=project,
                        harness="omp",
                        operation_id="sink-fixture-new-intent",
                        output=output,
                        errors=errors,
                    )
                    == 125
                )
                assert len(store.list_approval_requests()) == 2
                assert all(row["request_id"] != queued["request_id"] for row in store.list_approval_requests())
                with store._connect() as connection:
                    assert connection.execute("select count(*) from guard_bash_operations").fetchone()[0] == 0
                    assert connection.execute("select count(*) from policy_decisions").fetchone()[0] == 0
                    assert connection.execute("select count(*) from guard_local_once_approvals").fetchone()[0] == 0
                return
            contract = request_scope_contract(queued, guard_home=guard)
            assert contract.can_run_once and contract.can_persist_exact_version
            # Resolve only the lane-owned row from this disposable store,
            # using the normal resolution/contract/integrity machinery.
            apply_approval_resolution(
                store=store,
                request_id=queued["request_id"],
                action="allow",
                scope="artifact",
                workspace=str(project),
                reason="Lane-owned script consent",
                persist_policy=None if duration == "once-default" else duration == "persistent",
                scope_contract_version=queued["scope_contract_version"],
                scope_contract_digest=queued["scope_contract_digest"],
            )
            if duration in {"once", "once-default"}:
                with store._connect() as connection:
                    pending_record = tuple(
                        connection.execute(
                            "select operation_id,payload,integrity from guard_bash_reviews where operation_id=?",
                            ("sink-fixture-operation-1",),
                        ).fetchone()
                    )
                    connection.execute("delete from guard_bash_reviews where operation_id=?", (pending_record[0],))
                assert (
                    run_bound_bash(
                        payload,
                        store=store,
                        workspace=project,
                        harness="omp",
                        operation_id="sink-fixture-operation-1",
                        output=output,
                        errors=errors,
                    )
                    == 125
                )
                assert not (home / "maintenance-report.tsv").exists()
                with store._connect() as connection:
                    assert connection.execute("select claimed_at from guard_local_once_approvals").fetchone()[0] is None
                    assert connection.execute("select count(*) from guard_bash_operations").fetchone()[0] == 0
                    connection.execute("insert into guard_bash_reviews values (?,?,?)", pending_record)
                assert (
                    run_bound_bash(
                        payload,
                        store=store,
                        workspace=project,
                        harness="omp",
                        operation_id="sink-unrelated-operation",
                        output=output,
                        errors=errors,
                    )
                    == 125
                )
                assert not (home / "maintenance-report.tsv").exists()
                with store._connect() as connection:
                    assert connection.execute("select claimed_at from guard_local_once_approvals").fetchone()[0] is None
            assert (
                run_bound_bash(
                    payload,
                    store=store,
                    workspace=project,
                    harness="omp",
                    operation_id="sink-fixture-operation-1",
                    output=output,
                    errors=errors,
                )
                == 0
            )
            report = home / "maintenance-report.tsv"
            assert "local metadata" in report.read_text()
            if duration == "persistent":
                for iteration in range(2, 11):
                    if iteration in {2, 6, 10}:
                        assert close_native_residents(guard_home=guard)
                    (project / "maintenance.sh").touch()
                    (project / "unrelated.txt").write_text(str(iteration))
                    assert (
                        run_bound_bash(
                            payload,
                            store=store,
                            workspace=project,
                            harness="omp",
                            operation_id=f"sink-fixture-operation-{iteration}",
                            output=output,
                            errors=errors,
                        )
                        == 0
                    )
                report.write_text("preserved after persistent runs")
                helper = project / "fixture-registry"
                helper.write_text(helper.read_text() + "\nprintf changed\n")
                assert (
                    run_bound_bash(
                        payload,
                        store=store,
                        workspace=project,
                        harness="omp",
                        operation_id="sink-fixture-operation-changed",
                        output=output,
                        errors=errors,
                    )
                    == 125
                )
                assert report.read_text() == "preserved after persistent runs"
                with store._connect() as connection:
                    assert connection.execute("select count(*) from guard_local_once_approvals").fetchone()[0] == 0
                    assert connection.execute("select count(*) from guard_bash_operations").fetchone()[0] == 10
                return
            with store._connect() as connection:
                row = connection.execute("select claimed_at, request_id from guard_local_once_approvals").fetchone()
                assert row[0] is not None and row[1] == queued["request_id"]
                assert connection.execute("select count(*) from policy_decisions").fetchone()[0] == 0
            report.write_text("preserved once report")
            assert close_native_residents(guard_home=guard)
            assert (
                run_bound_bash(
                    payload,
                    store=store,
                    workspace=project,
                    harness="omp",
                    operation_id="sink-fixture-operation-1",
                    output=output,
                    errors=errors,
                )
                == 0
            )
            assert "output_not_retained" in errors.getvalue()
            assert (
                run_bound_bash(
                    payload,
                    store=store,
                    workspace=project,
                    harness="omp",
                    operation_id="sink-fixture-operation-2",
                    output=output,
                    errors=errors,
                )
                == 125
            )
            assert report.read_text() == "preserved once report"
            with store._connect() as connection:
                assert connection.execute("select count(*) from guard_bash_operations").fetchone()[0] == 1
            return
        if duration == "quiet-raced-block":
            native_execute = bound_bash_sink.execute

            def insert_block_after_python_lookup(request, **kwargs):
                assert request["authorization"]["kind"] == "current_policy"
                store.upsert_policy(
                    PolicyDecision(
                        harness="omp",
                        scope="artifact",
                        action="block",
                        artifact_id=ARTIFACT_ID,
                        reason="Lane-owned concurrent block",
                    ),
                    datetime.now(timezone.utc).isoformat(),
                )
                return native_execute(request, **kwargs)

            monkeypatch.setattr(bound_bash_sink, "execute", insert_block_after_python_lookup)
            assert (
                run_bound_bash(
                    payload,
                    store=store,
                    workspace=project,
                    harness="omp",
                    operation_id="sink-fixture-raced-block",
                    output=output,
                    errors=errors,
                )
                == 125
            )
            assert "native_bash_saved_authority_changed" in errors.getvalue()
            assert not (home / "maintenance-report.tsv").exists()
            with store._connect() as connection:
                assert connection.execute("select count(*) from guard_bash_operations").fetchone()[0] == 0
            return
        request_directory = tmp_path / "hol-guard-contained-test-sink-fixture"
        request_directory.mkdir(mode=0o700)
        request_file = request_directory / "request.json"
        raw = json.dumps({"schema": "guard-contained-test-request.v1", "workspace": str(project), "payload": payload})
        request_file.write_text(raw)
        request_file.chmod(0o600)
        args = argparse.Namespace(
            harness="omp",
            operation_id="sink-fixture-operation-1",
            timeout_seconds=120,
            request_file=str(request_file),
            request_sha256=hashlib.sha256(raw.encode()).hexdigest(),
        )
        assert (
            _run_guard_execute_bound_bash_command(
                args,
                guard_home=guard,
                workspace=project,
                store=store,
                context=SimpleNamespace(home_dir=home),
            )
            == 0
        )
        assert not request_file.exists() and not request_directory.exists()
        report = home / "maintenance-report.tsv"
        assert report.is_file()
        assert output.getvalue() == ""
        assert "alpha/current" in report.read_text() and "local metadata" in report.read_text()
        report.write_text("preserved after lost reply")
        assert (
            run_bound_bash(
                payload,
                store=store,
                workspace=project,
                harness="omp",
                operation_id="sink-fixture-operation-1",
                output=output,
                errors=errors,
            )
            == 0
        )
        assert report.read_text() == "preserved after lost reply"
        assert "output_not_retained" in errors.getvalue()
        with store._connect() as connection:
            assert connection.execute("select count(*) from guard_local_once_approvals").fetchone()[0] == 0
            assert connection.execute("select count(*) from guard_bash_operations").fetchone()[0] == 1
    finally:
        assert close_native_residents(guard_home=guard)
