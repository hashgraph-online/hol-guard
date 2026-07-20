# pyright: reportPrivateUsage=false, reportUnknownArgumentType=false
# pyright: reportUnknownLambdaType=false, reportUnusedCallResult=false

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from collections.abc import Mapping
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.approval_scope_support import request_scope_contract
from codex_plugin_scanner.guard.approvals import _artifact_scope_runtime_exact_match_key, apply_approval_resolution
from codex_plugin_scanner.guard.cli.commands_hook_runtime_eval import _evaluate_runtime_artifact_hook
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.models import GuardApprovalRequest, GuardArtifact
from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from codex_plugin_scanner.guard.runtime.effect_decision import FinalDisposition
from codex_plugin_scanner.guard.runtime.github_capability_interaction import GITHUB_MAINTENANCE_ACTION_CLASS
from codex_plugin_scanner.guard.runtime.github_workflow_approval_record import GitHubWorkflowApprovalRecord
from codex_plugin_scanner.guard.runtime.github_workflow_authorization import (
    GitHubWorkflowBindingContext,
    github_repository_sha256,
)
from codex_plugin_scanner.guard.runtime.github_workflow_context import (
    GITHUB_WORKFLOW_DESCRIPTOR_SCHEMA,
    GitHubWorkflowDescriptor,
    build_github_workflow_descriptor,
)
from codex_plugin_scanner.guard.runtime.github_workflow_operations import parse_github_workflow_operation
from codex_plugin_scanner.guard.runtime.github_workflow_runtime import (
    claim_resolved_github_workflow_authorization,
    github_workflow_capability_required,
    issue_resolved_github_workflow_capability,
)
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_workflow_capability_common import WORKFLOW_CAPABILITY_STORE_CLOCK
from codex_plugin_scanner.guard.workflow_capabilities import (
    WorkflowCapabilityRuleBinding,
    canonical_framed_payload,
    format_utc_timestamp,
)

_ISSUED = datetime(2026, 7, 20, 12, tzinfo=timezone.utc)
_COMMAND = f"{Path(sys.executable).resolve()} issue lock 17 --repo example/repo"
_GRAPHQL_COMMAND = (
    f"{Path(sys.executable).resolve()} api graphql -f "
    "query='mutation($threadId:ID!){resolveReviewThread(input:{threadId:$threadId}){thread{id}}}' "
    "-f threadId=THREAD_1"
)


@pytest.fixture(autouse=True)
def fixed_authority(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        GuardStore,
        "_policy_integrity_secret_material",
        lambda _store, *, create: (b"r" * 32, "guard-policy-integrity-key:github-runtime-test"),
    )
    monkeypatch.setattr(WORKFLOW_CAPABILITY_STORE_CLOCK, "now", lambda: format_utc_timestamp(_ISSUED))


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _framed_digest(purpose: str, payload: object) -> str:
    return hashlib.sha256(canonical_framed_payload(purpose, payload)).hexdigest()


def _descriptor(command: str = _COMMAND) -> GitHubWorkflowDescriptor:
    executable = str(Path(sys.executable).resolve())
    operation = parse_github_workflow_operation(
        parse_shell_command(command),
        repository="example/repo",
        expected_executable=executable,
    )
    assert operation is not None
    return GitHubWorkflowDescriptor(
        schema_version=GITHUB_WORKFLOW_DESCRIPTOR_SCHEMA,
        operation=operation,
        binding_context=GitHubWorkflowBindingContext(
            repository_sha256=github_repository_sha256("example/repo"),
            workspace_sha256=_framed_digest("github-workspace", str(Path("/workspace").resolve())),
            executable_sha256=hashlib.sha256(Path(executable).read_bytes()).hexdigest(),
            cwd_sha256=_digest("cwd"),
            environment_sha256=_digest("environment"),
            configuration_sha256=_digest("configuration"),
            manifest_sha256=_digest("manifest"),
            lockfile_sha256=_digest("lockfile"),
            sandbox_sha256=_digest("sandbox"),
            policy_id="guard.command-policy",
            policy_version="policy.v1",
            effect_id="github.maintain-remote",
            effect_version="effect.v1",
            decision_id="github.workflow-authorized",
            decision_version="decision.v1",
            rules=(WorkflowCapabilityRuleBinding("github.maintain-remote", "rule.v1"),),
        ),
        viewer_sha256=_digest("viewer"),
    )


def _seed_resolved_request(
    store: GuardStore,
    descriptor: GitHubWorkflowDescriptor,
    *,
    request_id: str = "request-github-1",
    action: str = "allow",
    linked: bool = True,
    resolved: bool = True,
) -> dict[str, object]:
    request = GuardApprovalRequest(
        request_id=request_id,
        harness="codex",
        artifact_id="codex:project:tool-action:github",
        artifact_name="Bash GitHub maintenance",
        artifact_hash="guard-approval-context:v1:test",
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("tool_action_request",),
        source_scope="project",
        config_path="/guard/config.toml",
        workspace="/workspace",
        artifact_type="tool_action_request",
        review_command=f"hol-guard approvals approve {request_id}",
        approval_url=f"http://127.0.0.1/requests/{request_id}",
        scanner_evidence=(
            {
                "source": "github_workflow_approval_record",
                "record": GitHubWorkflowApprovalRecord.from_descriptor(descriptor).to_dict(),
            },
        ),
        raw_command_text=_COMMAND,
    )
    store.add_approval_request(request, format_utc_timestamp(_ISSUED))
    session = store.upsert_guard_session(
        session_id="session-github-1",
        harness="codex",
        surface="harness-adapter",
        status="waiting_on_approval",
        client_name="codex-hook",
        client_title=None,
        client_version=None,
        workspace="/workspace",
        capabilities=["approval-resolution"],
        now=format_utc_timestamp(_ISSUED),
    )
    if linked:
        _ = store.upsert_guard_operation(
            operation_id="operation-github-1",
            session_id=str(session["session_id"]),
            harness="codex",
            operation_type="tool_call",
            status="waiting_on_approval",
            approval_request_ids=[request_id],
            resume_token="resume-token",
            metadata={
                "command_text": _COMMAND,
                "hook_event_name": "PreToolUse",
                "workspace": "/workspace",
            },
            now=format_utc_timestamp(_ISSUED),
        )
    if resolved:
        with store._connect() as connection:
            connection.execute(
                """update approval_requests
                set status = 'resolved', resolution_action = ?, resolved_at = ?
                where request_id = ?""",
                (action, format_utc_timestamp(_ISSUED), request_id),
            )
    stored = store.get_approval_request(request_id)
    assert stored is not None
    return stored


def test_approval_resolution_issues_from_guard_owned_operation_lineage(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    descriptor = _descriptor()
    request = _seed_resolved_request(store, descriptor, resolved=False)

    resolved = apply_approval_resolution(
        store=store,
        request_id="request-github-1",
        action="allow",
        scope="artifact",
        workspace=None,
        reason="reviewed exact maintenance task",
        now=format_utc_timestamp(_ISSUED),
    )

    assert resolved["resolution_action"] == "allow"
    lookup = store.resolve_policy_decision_lookup(
        "codex",
        "codex:project:tool-action:github",
        artifact_hash=_artifact_scope_runtime_exact_match_key(request, "artifact"),
        now=format_utc_timestamp(_ISSUED),
        consume_one_shot=False,
    )
    saved_decision = cast(Mapping[str, object], lookup["decision"])
    assert saved_decision["source"] == "approval-gate-once"
    assert saved_decision["request_id"] == "request-github-1"
    assert claim_resolved_github_workflow_authorization(store, "request-github-1", descriptor) is not None


def test_workflow_marker_lookup_errors_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)

    def fail_lookup(_request_id: str) -> None:
        raise OSError("unavailable")

    monkeypatch.setattr(store, "get_approval_request", fail_lookup)
    assert github_workflow_capability_required(store, "request-github-1")


def test_resolved_guard_lineage_issues_bounded_retry_capability(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    descriptor = _descriptor()
    request = _seed_resolved_request(store, descriptor)

    contract = request_scope_contract(request)
    assert contract.task_capability_eligible
    assert contract.task_capability_reason_codes == ("exact_github_workflow_record",)
    assert issue_resolved_github_workflow_capability(store, request, resolved_at=format_utc_timestamp(_ISSUED))
    assert issue_resolved_github_workflow_capability(store, request, resolved_at=format_utc_timestamp(_ISSUED))
    authorization = claim_resolved_github_workflow_authorization(store, "request-github-1", descriptor)
    assert authorization is not None
    evaluation = evaluate_command(
        _COMMAND,
        compatibility_action_class=GITHUB_MAINTENANCE_ACTION_CLASS,
        workflow_authorization=authorization,
    )
    assert evaluation.decision_plane.disposition is FinalDisposition.WORKFLOW_AUTHORIZED
    assert all(
        claim_resolved_github_workflow_authorization(store, "request-github-1", descriptor) is not None
        for _ in range(9)
    )
    assert claim_resolved_github_workflow_authorization(store, "request-github-1", descriptor) is None


@pytest.mark.parametrize("action,linked", (("block", True), ("allow", False)))
def test_blocked_or_unlinked_approval_never_issues(tmp_path: Path, action: str, linked: bool) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    request = _seed_resolved_request(store, _descriptor(), action=action, linked=linked)
    assert not issue_resolved_github_workflow_capability(store, request, resolved_at=format_utc_timestamp(_ISSUED))


def test_spoofed_ids_and_binding_drift_fail_closed(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    descriptor = _descriptor()
    request = _seed_resolved_request(store, descriptor)
    assert issue_resolved_github_workflow_capability(store, request, resolved_at=format_utc_timestamp(_ISSUED))
    assert claim_resolved_github_workflow_authorization(store, "payload-spoof", descriptor) is None
    drifted = replace(
        descriptor,
        binding_context=replace(descriptor.binding_context, workspace_sha256=_digest("other-workspace")),
    )
    assert claim_resolved_github_workflow_authorization(store, "request-github-1", drifted) is None


def test_claimed_saved_allow_cannot_bypass_failed_workflow_capability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import codex_plugin_scanner.guard.cli.commands_hook_github_workflow as workflow_hook

    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(guard_home)
    descriptor = _descriptor()
    monkeypatch.setattr(workflow_hook, "_runtime_github_workflow_descriptor", lambda *_args, **_kwargs: descriptor)
    monkeypatch.setattr(workflow_hook, "github_workflow_capability_required", lambda *_args: True)
    monkeypatch.setattr(workflow_hook, "claim_resolved_github_workflow_authorization", lambda *_args: None)
    artifact = GuardArtifact(
        artifact_id="codex:project:tool-action:github",
        name="Bash GitHub maintenance",
        harness="codex",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path=str(workspace / ".codex" / "config.toml"),
        command=_COMMAND,
        metadata={"action_class": GITHUB_MAINTENANCE_ACTION_CLASS},
    )
    config = GuardConfig(guard_home=guard_home, workspace=workspace, default_action="review")
    args = argparse.Namespace(harness="codex", policy_action=None, json=True)
    context = HarnessContext(home_dir=tmp_path, workspace_dir=workspace, guard_home=guard_home)

    def evaluate(claimed_hash: str | None = None, request_id: str | None = None):
        return _evaluate_runtime_artifact_hook(
            args,
            action_envelope=None,
            config=config,
            context=context,
            data_flow_signals=(),
            guard_home=guard_home,
            payload={"hook_event_name": "PreToolUse", "tool_name": "Bash"},
            runtime_artifact=artifact,
            runtime_workspace=workspace,
            store=store,
            _claimed_saved_allow_hash=claimed_hash,
            _claimed_approval_request_id=request_id,
            _claim_saved_approval=claimed_hash is None,
        )

    initial = evaluate()
    assert not isinstance(initial, int)
    result = evaluate(initial.runtime_artifact_hash, "request-github-1")
    assert not isinstance(result, int)
    assert result.policy_action == "require-reapproval"
    reuse = cast(Mapping[str, object], result.response_payload["approval_reuse"])
    assert reuse["reason_code"] == "approval_reuse_integrity_failure"


def test_workflow_events_do_not_expose_remote_identity(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    descriptor = _descriptor()
    request = _seed_resolved_request(store, descriptor)
    assert issue_resolved_github_workflow_capability(store, request, resolved_at=format_utc_timestamp(_ISSUED))
    assert claim_resolved_github_workflow_authorization(store, "request-github-1", descriptor) is not None
    events = store.list_events(event_name="workflow_capability.issued") + store.list_events(
        event_name="workflow_capability.claimed"
    )
    encoded = json.dumps(events)
    assert "example/repo" not in encoded
    assert "issue lock 17" not in encoded


def test_cli_descriptor_requires_workspace_remote_and_authenticated_viewer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import codex_plugin_scanner.guard.runtime.github_workflow_context as context_module

    monkeypatch.setattr(context_module, "_resolve_executable", lambda _name, _env: Path(sys.executable).resolve())

    def response(arguments: tuple[str, ...], **_kwargs: object) -> bytes:
        if "remote.origin.url" in arguments:
            return b"https://github.com/example/repo.git\n"
        return b'{"login":"reviewer"}'

    monkeypatch.setattr(context_module, "_run_bounded", response)
    descriptor = build_github_workflow_descriptor(
        _COMMAND,
        workspace=tmp_path,
        config_path=str(tmp_path / "config.toml"),
        configuration={"mode": "enforce"},
        sandbox={"analysis": True},
        environment={"PATH": os.environ.get("PATH", "")},
    )
    assert descriptor is not None
    assert descriptor.operation.repository == "example/repo"


def test_review_thread_descriptor_uses_exact_identity_bound_locator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import codex_plugin_scanner.guard.runtime.github_workflow_context as context_module

    monkeypatch.setattr(context_module, "_resolve_executable", lambda _name, _env: Path(sys.executable).resolve())
    located = {
        "data": {
            "node": {
                "__typename": "PullRequestReviewThread",
                "id": "THREAD_1",
                "pullRequest": {"number": 17, "repository": {"nameWithOwner": "example/repo"}},
            },
            "viewer": {"login": "reviewer"},
        }
    }

    def response(arguments: tuple[str, ...], **_kwargs: object) -> bytes:
        if "remote.origin.url" in arguments:
            return b"git@github.com:example/repo.git\n"
        assert arguments[1:3] == ("api", "graphql")
        assert "threadId=THREAD_1" in arguments
        return json.dumps(located, separators=(",", ":")).encode("utf-8")

    monkeypatch.setattr(context_module, "_run_bounded", response)
    descriptor = build_github_workflow_descriptor(
        _GRAPHQL_COMMAND,
        workspace=tmp_path,
        config_path=str(tmp_path / "config.toml"),
        configuration={},
        sandbox={},
        environment={"PATH": os.environ.get("PATH", "")},
    )
    assert descriptor is not None
    assert descriptor.operation.resource_type == "github-review-thread"
    assert descriptor.operation.resource_id == "THREAD_1"


@pytest.mark.parametrize(
    "locator_payload",
    (
        b'{"data":{"node":{"__typename":"Issue","id":"THREAD_1","pullRequest":{}},"viewer":{"login":"u"}}}',
        b'{"data":{"node":{"__typename":"PullRequestReviewThread","id":"OTHER","pullRequest":{}},"viewer":{"login":"u"}}}',
        b'{"data":{"node":null,"viewer":{"login":"u"}}}',
        b'{"data":{"node":null,"node":null,"viewer":{"login":"u"}}}',
        b'{"data":{"node":{"__typename":"PullRequestReviewThread","id":"THREAD_1","pullRequest":{"number":17,"repository":{"nameWithOwner":"other/repo"}}},"viewer":{"login":"u"}}}',
        b'{"data":{"node":{"__typename":"PullRequestReviewThread","id":"THREAD_1","pullRequest":{"number":17,"repository":{"nameWithOwner":"example/repo"}}},"viewer":{}}}',
        b"{" + b"x" * (64 * 1024) + b"}",
    ),
)
def test_review_thread_locator_malformed_or_oversized_response_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, locator_payload: bytes
) -> None:
    import codex_plugin_scanner.guard.runtime.github_workflow_context as context_module

    monkeypatch.setattr(context_module, "_resolve_executable", lambda _name, _env: Path(sys.executable).resolve())

    def response(arguments: tuple[str, ...], **_kwargs: object) -> bytes:
        if "remote.origin.url" in arguments:
            return b"https://github.com/example/repo.git\n"
        return locator_payload

    monkeypatch.setattr(context_module, "_run_bounded", response)
    assert (
        build_github_workflow_descriptor(
            _GRAPHQL_COMMAND,
            workspace=tmp_path,
            config_path=str(tmp_path / "config.toml"),
            configuration={},
            sandbox={},
            environment={"PATH": os.environ.get("PATH", "")},
        )
        is None
    )


def test_destructive_operation_never_gets_a_descriptor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import codex_plugin_scanner.guard.runtime.github_workflow_context as context_module

    monkeypatch.setattr(context_module, "_resolve_executable", lambda _name, _env: Path(sys.executable).resolve())
    monkeypatch.setattr(
        context_module,
        "_run_bounded",
        lambda arguments, **_kwargs: (
            b"https://github.com/example/repo.git\n" if "remote.origin.url" in arguments else b'{"login":"reviewer"}'
        ),
    )
    assert (
        build_github_workflow_descriptor(
            "gh pr merge 17 --squash --repo example/repo",
            workspace=tmp_path,
            config_path=str(tmp_path / "config.toml"),
            configuration={},
            sandbox={},
            environment={"PATH": os.environ.get("PATH", "")},
        )
        is None
    )


def test_bounded_locator_rejects_oversized_output_and_timeout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import codex_plugin_scanner.guard.runtime.github_workflow_context as context_module

    env = {"HOME": str(tmp_path), "PATH": os.environ.get("PATH", "")}
    with pytest.raises(subprocess.SubprocessError):
        _ = context_module._run_bounded(
            (sys.executable, "-c", "import sys;sys.stdout.write('x'*65537)"),
            cwd=tmp_path,
            env=env,
        )
    monkeypatch.setattr(context_module, "_TIMEOUT_SECONDS", 0.05)
    with pytest.raises(subprocess.TimeoutExpired):
        _ = context_module._run_bounded(
            (sys.executable, "-c", "import time;time.sleep(1)"),
            cwd=tmp_path,
            env=env,
        )
