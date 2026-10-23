"""Real scope reads and consent writes require the owner's pending evidence."""

from __future__ import annotations

import copy
import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.approval_scope_support import request_scope_contract
from codex_plugin_scanner.guard.approvals import apply_approval_resolution
from codex_plugin_scanner.guard.config import update_guard_settings
from codex_plugin_scanner.guard.native_approval_resolution import (
    ApprovalResolutionPlanUnavailableError,
    native_approval_resolution_plan,
)
from codex_plugin_scanner.guard.native_resident_client import close_native_residents
from codex_plugin_scanner.guard.runtime.bound_bash_sink import run_bound_bash
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_native_bash_sink_integration import _Secrets

pytestmark = pytest.mark.skipif(sys.platform != "darwin", reason="native Bash owner currently supports macOS")


@pytest.fixture
def pending(native_context_digest, tmp_path, monkeypatch):
    del native_context_digest
    project, home, guard = tmp_path / "project", tmp_path / "home", tmp_path / "guard"
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
    update_guard_settings(guard, {"subprocess_action": "require-reapproval"})
    store = GuardStore(guard, prime_policy_integrity=False)
    store._policy_integrity_secret_store = _Secrets()
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "bash",
        "cwd": str(project),
        "tool_input": {"command": f"/bin/bash '{project / 'maintenance.sh'}' dry"},
    }
    try:
        result = run_bound_bash(
            payload,
            store=store,
            workspace=project,
            harness="omp",
            operation_id="descriptor-fixture-operation",
            output=io.StringIO(),
            errors=io.StringIO(),
        )
        assert result == 125
        request = store.list_approval_requests()[0]
        assert request["execution_approval"]["can_run_once"] is True
        baseline = request_scope_contract(request, guard_home=guard)
        assert baseline.can_run_once and baseline.can_persist_exact_version
        yield store, request, baseline, home
    finally:
        assert close_native_residents(guard_home=guard)


@pytest.mark.parametrize(
    "mutation",
    [
        "legacy",
        "previous-owner",
        "wrong-type",
        "missing",
        "unknown-field",
        "host",
        "mode",
        "nonce",
        "expired",
        "missing-native-record",
        "tampered-native-record",
        "copied-pending-row",
    ],
)
def test_forged_or_unavailable_review_cannot_offer_or_write_execution_consent(pending, mutation):
    store, original, baseline, home = pending
    envelope = copy.deepcopy(original["action_envelope_json"])
    descriptor = envelope["native_bash"]
    artifact_id, artifact_type = original["artifact_id"], original["artifact_type"]
    if mutation == "legacy":
        artifact_id, artifact_type = "native-bash-launch:v1", "tool_call"
    elif mutation == "previous-owner":
        artifact_id = "native-bash-owner:native-pretool:v1"
    elif mutation == "wrong-type":
        artifact_type = "tool_call"
    elif mutation == "missing":
        del envelope["native_bash"]
    elif mutation == "unknown-field":
        descriptor["caller_allows_execution"] = True
    elif mutation == "host":
        descriptor["subject"]["context"]["host"] = "pi-input-mutation-v1"
    elif mutation == "mode":
        descriptor["subject"]["argv"][-1] = "delete"
    elif mutation == "nonce":
        descriptor["review_lineage"]["lineage_id"] = "e" * 64
    elif mutation == "expired":
        descriptor["review_lineage"].update(created_at_ms=1, expires_at_ms=86_400_001)
    with store._connect() as connection:
        connection.execute(
            "update approval_requests set artifact_id=?,artifact_type=?,action_envelope_json=? where request_id=?",
            (artifact_id, artifact_type, json.dumps(envelope), original["request_id"]),
        )
        if mutation == "missing-native-record":
            connection.execute("delete from guard_bash_reviews")
        elif mutation == "tampered-native-record":
            connection.execute("update guard_bash_reviews set payload=json_set(payload,'$.blocked',1)")
        elif mutation == "copied-pending-row":
            columns = [row[1] for row in connection.execute("pragma table_info(approval_requests)")]
            fields = ",".join(columns)
            selections = ",".join("'duplicate-request'" if column == "request_id" else column for column in columns)
            connection.execute(
                f"insert into approval_requests ({fields}) select {selections} "
                "from approval_requests where request_id=?",
                (original["request_id"],),
            )
    current = store.get_approval_request(original["request_id"])
    assert current["execution_approval"]["can_run_once"] is False
    assert current["execution_approval"]["can_persist_exact_version"] is False
    contract = request_scope_contract(current, guard_home=store.guard_home)
    assert not contract.can_run_once and not contract.can_persist_exact_version
    assert contract.digest != baseline.digest
    for duration in (False, True, None):
        with pytest.raises(ValueError):
            apply_approval_resolution(
                store=store,
                request_id=original["request_id"],
                action="allow",
                scope="artifact",
                workspace=original["workspace"],
                reason="Lane-owned forged review attempt",
                persist_policy=duration,
                scope_contract_version=contract.version,
                scope_contract_digest=contract.digest,
            )
        with store._connect() as connection:
            assert connection.execute("select count(*) from policy_decisions").fetchone()[0] == 0
            assert connection.execute("select count(*) from guard_local_once_approvals").fetchone()[0] == 0
            assert connection.execute("select count(*) from guard_bash_operations").fetchone()[0] == 0
    assert store.get_approval_request(original["request_id"])["status"] == "pending"
    assert not (home / "maintenance-report.tsv").exists()


@pytest.mark.parametrize("refusal_duration", [None, False])
def test_previous_native_executable_cannot_offer_or_write_new_descriptor_consent(pending, refusal_duration):
    previous = os.environ.get("HOL_GUARD_TEST_PREVIOUS_NATIVE_BINARY")
    if previous is None:
        pytest.skip("set HOL_GUARD_TEST_PREVIOUS_NATIVE_BINARY for the executable compatibility lane")
    assert Path(previous).is_absolute() and Path(previous).is_file()
    store, original, _baseline, _home = pending
    assert close_native_residents(guard_home=store.guard_home)
    child = r"""
import json, sys
from pathlib import Path
from codex_plugin_scanner.guard.approvals import apply_approval_resolution
from codex_plugin_scanner.guard.native_bash_protocol import (
    DESCRIPTOR_FEATURE, HOST_LIVENESS_FEATURE, NativeBashError, runtime_status,
)
from codex_plugin_scanner.guard.native_runtime import native_runtime_status
from codex_plugin_scanner.guard.native_resident_client import close_native_residents
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_native_bash_sink_integration import _Secrets
configuration = json.load(sys.stdin)
status = native_runtime_status()
assert status.available and status.compatible and status.capabilities is not None
required = {DESCRIPTOR_FEATURE, HOST_LIVENESS_FEATURE, 'native-bash-invocation-lifetime-v1'}
assert not required.issubset(status.capabilities.features)
try:
    runtime_status()
except NativeBashError as error:
    assert str(error) == 'native_bash_owner_unavailable'
else:
    raise AssertionError('new client accepted a runtime without the current owner delivery')
store = GuardStore(Path(configuration['guard_home']), prime_policy_integrity=False)
store._policy_integrity_secret_store = _Secrets()
try:
    request = store.get_approval_request(configuration['request_id'])
    assert request['execution_approval']['can_run_once'] is False, 'older delivery exposed Run once'
    assert request['execution_approval']['can_persist_exact_version'] is False, 'older delivery exposed Always'
    assert request['allowed_scopes_by_action']['allow'] == []
    for duration in (None, False, True):
        try:
            apply_approval_resolution(
                store=store, request_id=request['request_id'], action='allow', scope='artifact',
                workspace=request['workspace'], reason='Lane-owned compatibility attempt', persist_policy=duration,
                scope_contract_version=request['scope_contract_version'],
                scope_contract_digest=request['scope_contract_digest'],
            )
        except ValueError:
            pass
        else:
            raise AssertionError('unsupported runtime wrote an execution decision')
    with store._connect() as connection:
        for table in ('policy_decisions', 'guard_local_once_approvals', 'guard_bash_operations'):
            assert connection.execute('select count(*) from ' + table).fetchone()[0] == 0
    assert store.get_approval_request(request['request_id'])['status'] == 'pending'
    apply_approval_resolution(
        store=store, request_id=request['request_id'], action='block', scope='artifact',
        workspace=request['workspace'], reason='Lane-owned compatibility refusal',
        persist_policy=configuration['refusal_duration'],
        scope_contract_version=request['scope_contract_version'],
        scope_contract_digest=request['scope_contract_digest'],
    )
    resolved = store.get_approval_request(request['request_id'])
    assert resolved['status'] == 'resolved' and resolved['resolution_action'] == 'block'
    with store._connect() as connection:
        for table in ('policy_decisions', 'guard_local_once_approvals', 'guard_bash_operations'):
            assert connection.execute('select count(*) from ' + table).fetchone()[0] == 0
finally:
    assert close_native_residents(guard_home=store.guard_home)
print('previous executable withheld both execution durations and wrote no consent')
"""
    repo = Path(__file__).resolve().parents[1]
    environment = {
        **os.environ,
        "HOL_GUARD_NATIVE_BINARY": previous,
        "PYTHONPATH": os.pathsep.join((str(repo / "src"), str(repo))),
    }
    completed = subprocess.run(
        [sys.executable, "-c", child],
        input=json.dumps(
            {
                "guard_home": str(store.guard_home),
                "request_id": original["request_id"],
                "refusal_duration": refusal_duration,
            }
        ),
        env=environment,
        text=True,
        capture_output=True,
        timeout=60,
    )
    assert completed.returncode == 0, completed.stderr[-2000:]
    assert "wrote no consent" in completed.stdout
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "bash",
        "cwd": original["workspace"],
        "tool_input": {"command": original["raw_command_text"]},
    }
    errors = io.StringIO()
    assert (
        run_bound_bash(
            payload,
            store=store,
            workspace=Path(original["workspace"]),
            harness="omp",
            operation_id="descriptor-fixture-operation",
            output=io.StringIO(),
            errors=errors,
        )
        == 125
    )
    assert "native_bash_operation_kept_blocked" in errors.getvalue()
    assert store.list_approval_requests() == []
    assert not (_home / "maintenance-report.tsv").exists()
    fresh_errors = io.StringIO()
    assert (
        run_bound_bash(
            payload,
            store=store,
            workspace=Path(original["workspace"]),
            harness="omp",
            operation_id="fresh-descriptor-fixture-operation",
            output=io.StringIO(),
            errors=fresh_errors,
        )
        == 125
    )
    assert "native_bash_consent_required" in fresh_errors.getvalue()
    requests = store.list_approval_requests()
    assert len(requests) == 1 and requests[0]["request_id"] != original["request_id"]
    assert not (_home / "maintenance-report.tsv").exists()


def test_native_resolution_rejects_legacy_server_envelope_even_with_real_exact_token(pending):
    store, original, _baseline, _home = pending
    legacy = copy.deepcopy(original)
    del legacy["action_envelope_json"]["native_bash"]
    options = {
        "guard_home": store.guard_home,
        "scope": "artifact",
        "temporary_mcp": False,
        "local_tool": False,
        "resolve_scope_matches": True,
        "requires_local_once": True,
        "resolved_workspace": original["workspace"],
        "native_exact_token": original["artifact_hash"],
        "resolved_at": original["created_at"],
    }
    for duration in (None, False, True):
        with pytest.raises(ApprovalResolutionPlanUnavailableError):
            native_approval_resolution_plan(legacy, action="allow", persist_policy=duration, **options)
    for duration in (None, False):
        plan = native_approval_resolution_plan(legacy, action="block", persist_policy=duration, **options)
        assert plan["persistence"] == "none"
        assert plan["local_once"] is None and plan["matching"] is None
    assert store.get_approval_request(original["request_id"])["status"] == "pending"
    with store._connect() as connection:
        assert connection.execute("select count(*) from policy_decisions").fetchone()[0] == 0
        assert connection.execute("select count(*) from guard_local_once_approvals").fetchone()[0] == 0


def test_remote_review_binding_uses_native_owner_home_once(pending, monkeypatch):
    from codex_plugin_scanner.guard import native_approval_scope
    from codex_plugin_scanner.guard.review_contracts import (
        build_local_review_request_claim,
        validate_remote_approval_request_binding,
    )
    from codex_plugin_scanner.guard.review_oauth_binding import GuardReviewOAuthMetadata

    store, request, _baseline, _home = pending
    oauth = GuardReviewOAuthMetadata(
        device_id="fixture-device",
        dpop_thumbprint=None,
        grant_id="fixture-grant",
        installation_id="fixture-installation",
        machine_id="fixture-machine",
        runtime_id="fixture-runtime",
        workspace_id="fixture-workspace",
    )
    claim = build_local_review_request_claim(request_row=request, oauth=oauth, store=store)
    envelope = {
        **claim,
        "sourceClaimHash": claim["claimHash"],
        "receiptId": "fixture-receipt",
        "nonce": f"{claim['nonce']}:fixture-receipt",
        "reviewerRole": "owner",
        "reviewerUserId": "fixture-reviewer",
        "scope": "artifact",
        "decision": "allow_once",
    }
    homes = []

    def require_owner_home(guard_home):
        assert guard_home == store.guard_home, "native review must not use a default or another owner's home"
        homes.append(guard_home)
        return guard_home

    monkeypatch.setattr(native_approval_scope, "_resolve_digest_home", require_owner_home)
    # The signed-envelope verifier is exercised separately; this binding stage
    # must use the real pending owner record and must not itself grant execution.
    validate_remote_approval_request_binding(
        envelope=envelope,
        request_row=request,
        oauth=oauth,
        store=store,
    )
    assert homes == [store.guard_home]
    assert store.get_approval_request(request["request_id"])["status"] == "pending"
    with store._connect() as connection:
        assert connection.execute("select count(*) from policy_decisions").fetchone()[0] == 0
        assert connection.execute("select count(*) from guard_local_once_approvals").fetchone()[0] == 0


@pytest.mark.parametrize("mutation", ["policy", "once", "siblings", "action"])
def test_refusal_rejects_native_plan_that_would_write_more_than_the_pending_refusal(pending, monkeypatch, mutation):
    from codex_plugin_scanner.guard import native_approval_resolution

    store, request, baseline, _home = pending
    transport = native_approval_resolution._resident_request

    def unexpected_plan(**arguments):
        response = transport(**arguments)
        assert isinstance(response, dict) and isinstance(response.get("payload"), dict)
        plan = response["payload"]
        if mutation == "policy":
            plan["persistence"] = "persisted"
        elif mutation == "once":
            plan["local_once"] = {"approval_id": "unexpected-once"}
        elif mutation == "siblings":
            plan["matching"] = {"harness": "omp", "scope": "artifact"}
        else:
            plan["decision"]["action"] = "allow"
        return response

    monkeypatch.setattr(native_approval_resolution, "_resident_request", unexpected_plan)
    with pytest.raises(ApprovalResolutionPlanUnavailableError):
        apply_approval_resolution(
            store=store,
            request_id=request["request_id"],
            action="block",
            scope="artifact",
            workspace=request["workspace"],
            reason="Lane-owned refusal authority regression",
            persist_policy=False,
            scope_contract_version=baseline.version,
            scope_contract_digest=baseline.digest,
        )
    assert store.get_approval_request(request["request_id"])["status"] == "pending"
    with store._connect() as connection:
        assert connection.execute("select count(*) from policy_decisions").fetchone()[0] == 0
        assert connection.execute("select count(*) from guard_local_once_approvals").fetchone()[0] == 0
