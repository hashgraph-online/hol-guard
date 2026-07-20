# pyright: reportPrivateUsage=false, reportUnknownArgumentType=false
# pyright: reportUnknownLambdaType=false, reportUnusedCallResult=false

from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.commands_hook_github_workflow import prepare_github_workflow_hook_state
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.models import GuardApprovalRequest, GuardArtifact, GuardReceipt
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from codex_plugin_scanner.guard.runtime.github_workflow_approval_record import GitHubWorkflowApprovalRecord
from codex_plugin_scanner.guard.runtime.github_workflow_authorization import (
    GitHubWorkflowBindingContext,
    claim_github_workflow_authorization,
    github_repository_sha256,
    issue_github_workflow_capability_binding,
)
from codex_plugin_scanner.guard.runtime.github_workflow_context import (
    GITHUB_WORKFLOW_DESCRIPTOR_SCHEMA,
    GitHubWorkflowDescriptor,
    _resolve_executable,
    build_github_workflow_descriptor,
)
from codex_plugin_scanner.guard.runtime.github_workflow_operations import parse_github_workflow_operation
from codex_plugin_scanner.guard.runtime.github_workflow_runtime import (
    _persisted_command_matches_record,
    approval_record_from_approval_request,
)
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.workflow_capabilities import (
    WorkflowCapabilityRuleBinding,
    canonical_framed_payload,
    format_utc_timestamp,
)

_NOW = datetime.now(timezone.utc)
_REPOSITORY = "privacy-owner/privacy-repo"
_THREAD = "PRRT_PRIVACY_SENTINEL"
_PATH_SENTINEL = "/private/privacy-path-sentinel"
_VIEWER = "privacy-viewer-sentinel"


def _digest(purpose: str, payload: object) -> str:
    return hashlib.sha256(canonical_framed_payload(purpose, payload)).hexdigest()


def _descriptor(executable: Path, *, command: str | None = None) -> GitHubWorkflowDescriptor:
    command = command or (
        f"{executable} api graphql -f "
        "query='mutation($threadId:ID!){resolveReviewThread(input:{threadId:$threadId}){thread{id}}}' "
        f"-f threadId={_THREAD}"
    )
    operation = parse_github_workflow_operation(
        parse_shell_command(command),
        repository=_REPOSITORY,
        expected_executable=str(executable),
    )
    assert operation is not None
    context = GitHubWorkflowBindingContext(
        repository_sha256=github_repository_sha256(_REPOSITORY),
        workspace_sha256=_digest("github-workspace", _PATH_SENTINEL),
        executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
        cwd_sha256=_digest("github-cwd", _PATH_SENTINEL),
        environment_sha256=_digest("github-environment", {"sentinel": _PATH_SENTINEL}),
        configuration_sha256=_digest("github-configuration", {"sentinel": _PATH_SENTINEL}),
        manifest_sha256=_digest("github-manifest", _PATH_SENTINEL),
        lockfile_sha256=_digest("github-lockfile", _PATH_SENTINEL),
        sandbox_sha256=_digest("github-sandbox", _PATH_SENTINEL),
        policy_id="guard.command-policy",
        policy_version="policy.v1",
        effect_id="github.maintain-remote",
        effect_version="effect.v1",
        decision_id="github.workflow-authorized",
        decision_version="decision.v1",
        rules=(WorkflowCapabilityRuleBinding("github.maintain-remote", "rule.v1"),),
    )
    return GitHubWorkflowDescriptor(GITHUB_WORKFLOW_DESCRIPTOR_SCHEMA, operation, context, _digest("viewer", _VIEWER))


def test_persisted_approval_receipt_and_events_expose_only_sanitized_record(tmp_path: Path) -> None:
    executable = Path(sys.executable).resolve()
    record = GitHubWorkflowApprovalRecord.from_descriptor(_descriptor(executable))
    evidence: tuple[dict[str, object], ...] = (
        {"source": "github_workflow_approval_record", "record": record.to_dict()},
    )
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    store.add_approval_request(
        GuardApprovalRequest(
            request_id="request-privacy",
            harness="codex",
            artifact_id="codex:project:tool-action:github",
            artifact_name="GitHub workflow",
            artifact_hash="guard-approval-context:v1:privacy",
            policy_action="require-reapproval",
            recommended_scope="artifact",
            changed_fields=("tool_action_request",),
            source_scope="project",
            config_path="redacted",
            workspace=None,
            artifact_type="tool_action_request",
            review_command="hol-guard approvals approve request-privacy",
            approval_url="http://127.0.0.1/requests/request-privacy",
            scanner_evidence=evidence,
            raw_command_text=None,
        ),
        format_utc_timestamp(_NOW),
    )
    store.add_receipt(
        GuardReceipt(
            receipt_id="receipt-privacy",
            timestamp=format_utc_timestamp(_NOW),
            harness="codex",
            artifact_id="codex:project:tool-action:github",
            artifact_hash="guard-approval-context:v1:privacy",
            policy_decision="require-reapproval",
            capabilities_summary="GitHub workflow",
            changed_capabilities=(),
            provenance_summary="Guard",
            scanner_evidence=evidence,
        )
    )
    key, key_id = store._policy_integrity_secret_material(create=True)
    assert key is not None and key_id is not None
    issue_github_workflow_capability_binding(
        store,
        record.binding,
        capability_id="privacy-capability",
        approval_provenance_id="request-privacy",
        task_id="operation-privacy",
        nonce="a" * 32,
        issuer_id="guard.local",
        subject_id="session-privacy",
        issued_at=format_utc_timestamp(_NOW),
        not_before=format_utc_timestamp(_NOW),
        expires_at=format_utc_timestamp(_NOW + timedelta(minutes=10)),
        max_uses=1,
        key=key,
        key_id=key_id,
    )
    approval = store.get_approval_request("request-privacy")
    assert approval is not None
    surfaces = {
        "approval_api": approval["scanner_evidence"],
        "receipt_api": store.list_receipts(limit=1)[0]["scanner_evidence"],
        "events": store.list_events(event_name="workflow_capability.issued"),
    }
    encoded = json.dumps(surfaces, sort_keys=True)
    for sentinel in (_REPOSITORY, _THREAD, _PATH_SENTINEL, _VIEWER):
        assert sentinel not in encoded
    assert "resource_sha256" in encoded
    assert "repository_sha256" in encoded


def test_raw_descriptor_or_extra_sensitive_record_fields_fail_closed() -> None:
    descriptor = _descriptor(Path(sys.executable).resolve())
    assert (
        approval_record_from_approval_request(
            {"scanner_evidence": [{"source": "github_workflow_descriptor", "descriptor": descriptor.to_dict()}]}
        )
        is None
    )
    payload = GitHubWorkflowApprovalRecord.from_descriptor(descriptor).to_dict()
    payload["repository"] = _REPOSITORY
    with pytest.raises(ValueError):
        GitHubWorkflowApprovalRecord.from_dict(payload)


def test_hook_artifact_metadata_persists_only_sanitized_record(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import codex_plugin_scanner.guard.cli.commands_hook_github_workflow as workflow_hook

    descriptor = _descriptor(Path(sys.executable).resolve())
    monkeypatch.setattr(workflow_hook, "_runtime_github_workflow_descriptor", lambda *_args, **_kwargs: descriptor)
    artifact = GuardArtifact(
        artifact_id="codex:project:tool-action:github",
        name="GitHub workflow",
        harness="codex",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path="redacted",
        command=None,
    )
    state = prepare_github_workflow_hook_state(
        artifact,
        workspace=tmp_path,
        config=GuardConfig(guard_home=tmp_path / "guard", workspace=tmp_path),
        store=GuardStore(tmp_path / "guard", prime_policy_integrity=False),
        approval_request_id=None,
    )
    encoded = json.dumps(state.artifact.metadata, sort_keys=True)
    for sentinel in (_REPOSITORY, _THREAD, _PATH_SENTINEL, _VIEWER):
        assert sentinel not in encoded
    assert "github_workflow_approval_record" in encoded


@pytest.mark.parametrize(
    "key",
    ("HTTP_PROXY", "SSL_CERT_FILE", "GH_TOKEN", "GH_CONFIG_DIR", "BASH_ENV", "ENV", "ZDOTDIR", "PATH"),
)
def test_full_launch_environment_drift_changes_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, key: str
) -> None:
    import codex_plugin_scanner.guard.runtime.github_workflow_context as context_module

    executable = Path(sys.executable).resolve()
    monkeypatch.setattr(context_module, "_resolve_executable", lambda _name, _env: executable)
    monkeypatch.setattr(
        context_module,
        "_run_bounded",
        lambda arguments, **_kwargs: (
            f"https://github.com/{_REPOSITORY}.git\n".encode()
            if "remote.origin.url" in arguments
            else json.dumps({"login": _VIEWER}).encode()
        ),
    )
    command = f"{executable} issue lock 17 --repo {_REPOSITORY}"
    base_environment = {"PATH": "/usr/bin", "HOME": str(tmp_path), key: "before"}
    before = build_github_workflow_descriptor(
        command,
        workspace=tmp_path,
        config_path="redacted",
        configuration={},
        sandbox={},
        environment=base_environment,
    )
    after = build_github_workflow_descriptor(
        command,
        workspace=tmp_path,
        config_path="redacted",
        configuration={},
        sandbox={},
        environment={**base_environment, key: "after"},
    )
    assert before is not None and after is not None
    assert before.binding_context.environment_sha256 != after.binding_context.environment_sha256


@pytest.mark.parametrize(
    "command",
    (
        f"gh issue lock 17 --repo {_REPOSITORY}",
        f"./gh issue lock 17 --repo {_REPOSITORY}",
        f"../bin/gh issue lock 17 --repo {_REPOSITORY}",
        f"command {Path(sys.executable).resolve()} issue lock 17 --repo {_REPOSITORY}",
        f"{Path(sys.executable).resolve()} issue lock 17 --repo {_REPOSITORY} &",
    ),
)
def test_noncanonical_launch_forms_are_ineligible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, command: str
) -> None:
    import codex_plugin_scanner.guard.runtime.github_workflow_context as context_module

    executable = Path(sys.executable).resolve()
    monkeypatch.setattr(context_module, "_resolve_executable", lambda _name, _env: executable)
    monkeypatch.setattr(
        context_module,
        "_run_bounded",
        lambda arguments, **_kwargs: (
            f"https://github.com/{_REPOSITORY}.git\n".encode()
            if "remote.origin.url" in arguments
            else json.dumps({"login": _VIEWER}).encode()
        ),
    )
    assert (
        build_github_workflow_descriptor(
            command,
            workspace=tmp_path,
            config_path="redacted",
            configuration={},
            sandbox={},
        )
        is None
    )


def test_symlinked_gh_is_ineligible(tmp_path: Path) -> None:
    binary = tmp_path / "real-gh"
    binary.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
    binary.chmod(0o755)
    (tmp_path / "gh").symlink_to(binary)
    with pytest.raises(OSError):
        _resolve_executable("gh", {"PATH": str(tmp_path)})


def test_executable_byte_drift_does_not_consume_capability(tmp_path: Path) -> None:
    executable = tmp_path / "gh"
    original = b"#!/bin/sh\nexit 0\n"
    executable.write_bytes(original)
    executable.chmod(0o755)
    descriptor = _descriptor(executable)
    record = GitHubWorkflowApprovalRecord.from_descriptor(descriptor)
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    key, key_id = store._policy_integrity_secret_material(create=True)
    assert key is not None and key_id is not None
    issue_github_workflow_capability_binding(
        store,
        record.binding,
        capability_id="drift-capability",
        approval_provenance_id="request-drift",
        task_id="operation-drift",
        nonce="b" * 32,
        issuer_id="guard.local",
        subject_id="session-drift",
        issued_at=format_utc_timestamp(_NOW),
        not_before=format_utc_timestamp(_NOW),
        expires_at=format_utc_timestamp(_NOW + timedelta(minutes=10)),
        max_uses=1,
        key=key,
        key_id=key_id,
    )
    command = (
        f"{executable} api graphql -f "
        "query='mutation($threadId:ID!){resolveReviewThread(input:{threadId:$threadId}){thread{id}}}' "
        f"-f threadId={_THREAD}"
    )
    executable.write_bytes(b"#!/bin/sh\nexit 1\n")
    assert not _persisted_command_matches_record(command, record)
    executable.write_bytes(original)
    assert _persisted_command_matches_record(command, record)
    assert (
        claim_github_workflow_authorization(
            store,
            "drift-capability",
            descriptor.operation,
            descriptor.binding_context,
            invocation_id="invocation-drift",
            subject_id="session-drift",
            task_id="operation-drift",
            issuer_id="guard.local",
            approval_provenance_id="request-drift",
        )
        is not None
    )
