# pyright: reportAny=false, reportMissingImports=false, reportPrivateUsage=false
# pyright: reportUnknownArgumentType=false, reportUnknownLambdaType=false
# pyright: reportUnknownMemberType=false, reportUnknownParameterType=false
# pyright: reportUntypedFunctionDecorator=false, reportUnusedCallResult=false

from __future__ import annotations

import hashlib
import sys
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from codex_plugin_scanner.guard.runtime.github_workflow_approval_record import GitHubWorkflowApprovalRecord
from codex_plugin_scanner.guard.runtime.github_workflow_authorization import (
    GitHubWorkflowBindingContext,
    github_repository_sha256,
)
from codex_plugin_scanner.guard.runtime.github_workflow_context import (
    GITHUB_WORKFLOW_DESCRIPTOR_SCHEMA,
    GitHubWorkflowDescriptor,
)
from codex_plugin_scanner.guard.runtime.github_workflow_operations import parse_github_workflow_operation
from codex_plugin_scanner.guard.runtime.github_workflow_runtime import (
    claim_resolved_github_workflow_authorization,
    issue_resolved_github_workflow_capability,
)
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_workflow_capability_common import WORKFLOW_CAPABILITY_STORE_CLOCK
from codex_plugin_scanner.guard.workflow_capabilities import (
    WorkflowCapabilityRuleBinding,
    canonical_framed_payload,
    format_utc_timestamp,
    parse_utc_timestamp,
)

_ISSUED = datetime(2026, 7, 20, 12, tzinfo=timezone.utc)
_EXECUTABLE = str(Path(sys.executable).resolve())
_COMMAND = f"{_EXECUTABLE} issue lock 17 --repo example/repo"


@pytest.fixture(autouse=True)
def fixed_authority(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        GuardStore,
        "_policy_integrity_secret_material",
        lambda _store, *, create: (b"r" * 32, "guard-policy-integrity-key:github-retry-test"),
    )
    monkeypatch.setattr(WORKFLOW_CAPABILITY_STORE_CLOCK, "now", lambda: format_utc_timestamp(_ISSUED))


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _framed_digest(purpose: str, payload: object) -> str:
    return hashlib.sha256(canonical_framed_payload(purpose, payload)).hexdigest()


def _descriptor(command: str = _COMMAND, *, repository: str = "example/repo") -> GitHubWorkflowDescriptor:
    operation = parse_github_workflow_operation(
        parse_shell_command(command), repository=repository, expected_executable=_EXECUTABLE
    )
    assert operation is not None
    return GitHubWorkflowDescriptor(
        schema_version=GITHUB_WORKFLOW_DESCRIPTOR_SCHEMA,
        operation=operation,
        binding_context=GitHubWorkflowBindingContext(
            repository_sha256=github_repository_sha256(repository),
            workspace_sha256=_framed_digest("github-workspace", str(Path("/workspace").resolve())),
            executable_sha256=hashlib.sha256(Path(_EXECUTABLE).read_bytes()).hexdigest(),
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


def _seed(store: GuardStore, descriptor: GitHubWorkflowDescriptor) -> None:
    request_id = "request-github-retry"
    request = GuardApprovalRequest(
        request_id=request_id,
        harness="codex",
        artifact_id="codex:project:tool-action:github-retry",
        artifact_name="Bash GitHub maintenance",
        artifact_hash="guard-approval-context:v1:retry",
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
    now = format_utc_timestamp(_ISSUED)
    store.add_approval_request(request, now)
    store.upsert_guard_session(
        session_id="session-github-retry",
        harness="codex",
        surface="harness-adapter",
        status="waiting_on_approval",
        client_name="codex-hook",
        client_title=None,
        client_version=None,
        workspace="/workspace",
        capabilities=["approval-resolution"],
        now=now,
    )
    store.upsert_guard_operation(
        operation_id="operation-github-retry",
        session_id="session-github-retry",
        harness="codex",
        operation_type="tool_call",
        status="waiting_on_approval",
        approval_request_ids=[request_id],
        resume_token="resume-token",
        metadata={"command_text": _COMMAND, "hook_event_name": "PreToolUse", "workspace": "/workspace"},
        now=now,
    )
    with store._connect() as connection:
        connection.execute(
            """update approval_requests set status = 'resolved', resolution_action = 'allow', resolved_at = ?
            where request_id = ?""",
            (now, request_id),
        )
    stored = store.get_approval_request(request_id)
    assert stored is not None
    assert issue_resolved_github_workflow_capability(store, stored, resolved_at=now)


def _claim(store: GuardStore, descriptor: GitHubWorkflowDescriptor) -> bool:
    return claim_resolved_github_workflow_authorization(store, "request-github-retry", descriptor) is not None


def _capability_id(store: GuardStore) -> str:
    with store._connect() as connection:
        row = connection.execute("select capability_id from guard_workflow_capabilities").fetchone()
    assert row is not None
    return str(row[0])


def _capability_state(store: GuardStore) -> tuple[int, bool]:
    with store._connect() as connection:
        row = connection.execute(
            "select used_count, revoked_at is not null from guard_workflow_capabilities"
        ).fetchone()
    assert row is not None
    return int(row[0]), bool(row[1])


def test_exact_retry_allows_ten_of_thirty_two_concurrent_attempts(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    descriptor = _descriptor()
    _seed(store, descriptor)

    with ThreadPoolExecutor(max_workers=32) as executor:
        results = tuple(executor.map(lambda _index: _claim(store, descriptor), range(32)))

    assert results.count(True) == 10
    assert results.count(False) == 22
    assert not _claim(store, descriptor)


def test_retry_expires_at_unchanged_ten_minute_ttl(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    descriptor = _descriptor()
    _seed(store, descriptor)
    signed = store.lookup_workflow_capability(_capability_id(store))
    assert signed is not None
    assert signed.claim.max_uses == 10
    assert parse_utc_timestamp(signed.claim.expires_at) - parse_utc_timestamp(signed.claim.issued_at) == timedelta(
        minutes=10
    )
    monkeypatch.setattr(
        WORKFLOW_CAPABILITY_STORE_CLOCK,
        "now",
        lambda: format_utc_timestamp(_ISSUED + timedelta(minutes=10)),
    )
    assert not _claim(store, descriptor)


def test_retry_revocation_stops_remaining_uses(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    descriptor = _descriptor()
    _seed(store, descriptor)
    assert [_claim(store, descriptor) for _ in range(3)] == [True, True, True]
    assert store.revoke_workflow_capability(_capability_id(store), reason_code="operator.revoked")
    assert not _claim(store, descriptor)


def test_claim_and_revocation_race_preserves_atomic_cutoff(tmp_path: Path) -> None:
    home = tmp_path / "guard-home"
    store = GuardStore(home, prime_policy_integrity=False)
    descriptor = _descriptor()
    _seed(store, descriptor)
    barrier = threading.Barrier(2)

    def race_claim() -> bool:
        barrier.wait()
        return _claim(GuardStore(home, prime_policy_integrity=False), descriptor)

    def race_revoke() -> bool:
        barrier.wait()
        return GuardStore(home, prime_policy_integrity=False).revoke_workflow_capability(
            _capability_id(store), reason_code="operator.revoked"
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        claim_future = executor.submit(race_claim)
        revoke_future = executor.submit(race_revoke)
    assert revoke_future.result()
    claimed = claim_future.result()
    assert _capability_state(store) == (int(claimed), True)
    assert not _claim(store, descriptor)


def _context_drift(descriptor: GitHubWorkflowDescriptor, field: str, value: object) -> GitHubWorkflowDescriptor:
    return replace(descriptor, binding_context=replace(descriptor.binding_context, **{field: value}))


def test_all_binding_drift_fails_without_consuming_uses(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    descriptor = _descriptor()
    _seed(store, descriptor)
    drifts: tuple[Callable[[], GitHubWorkflowDescriptor], ...] = (
        lambda: _descriptor(f"{_EXECUTABLE} issue unlock 17 --repo example/repo"),
        lambda: _descriptor(f"{_EXECUTABLE} issue lock 18 --repo example/repo"),
        lambda: _descriptor(f"{_EXECUTABLE} issue lock 17 --repo other/repo", repository="other/repo"),
        lambda: _context_drift(descriptor, "policy_version", "policy.v2"),
        lambda: _context_drift(descriptor, "effect_version", "effect.v2"),
        lambda: _context_drift(descriptor, "decision_version", "decision.v2"),
        lambda: _context_drift(
            descriptor,
            "rules",
            (WorkflowCapabilityRuleBinding("github.maintain-remote", "rule.v2"),),
        ),
        lambda: _context_drift(descriptor, "cwd_sha256", _digest("other-cwd")),
        lambda: _context_drift(descriptor, "environment_sha256", _digest("other-environment")),
        lambda: _context_drift(descriptor, "configuration_sha256", _digest("other-configuration")),
        lambda: _context_drift(descriptor, "manifest_sha256", _digest("other-manifest")),
        lambda: _context_drift(descriptor, "lockfile_sha256", _digest("other-lockfile")),
        lambda: _context_drift(descriptor, "sandbox_sha256", _digest("other-sandbox")),
    )
    assert all(not _claim(store, drift()) for drift in drifts)
    assert [_claim(store, descriptor) for _ in range(10)] == [True] * 10
    assert not _claim(store, descriptor)
