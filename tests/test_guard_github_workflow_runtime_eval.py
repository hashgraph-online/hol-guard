# pyright: reportPrivateUsage=false, reportUnknownArgumentType=false
# pyright: reportUnknownLambdaType=false, reportUnusedCallResult=false

from __future__ import annotations

import hashlib
import shlex
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

import codex_plugin_scanner.guard.approvals as approvals_module
from codex_plugin_scanner.guard.approvals import apply_approval_resolution
from codex_plugin_scanner.guard.cli.commands_support_runtime_policy import _runtime_hook_approval_context_token
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.runtime.approval_context import approval_context_tokens_validation_reason
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.runtime.github_workflow_approval_record import GitHubWorkflowApprovalRecord
from codex_plugin_scanner.guard.runtime.github_workflow_operations import parse_github_workflow_operation
from codex_plugin_scanner.guard.runtime.github_workflow_runtime import (
    _capability_id,
    claim_resolved_github_workflow_authorization,
)
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_workflow_capability_common import WORKFLOW_CAPABILITY_STORE_CLOCK
from codex_plugin_scanner.guard.workflow_capabilities import canonical_framed_payload, format_utc_timestamp
from tests.test_guard_github_workflow_runtime import _descriptor, _seed_resolved_request

_ISSUED = datetime(2026, 7, 20, 12, tzinfo=timezone.utc)


def _protected_control_authority() -> ExtensionControlAuthorityView:
    return ExtensionControlAuthorityView(
        health=AuthorityHealth.PROTECTED,
        revision=1,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        layers=(),
    )


@pytest.fixture(autouse=True)
def fixed_authority(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        GuardStore,
        "_policy_integrity_secret_material",
        lambda _store, *, create: (b"r" * 32, "guard-policy-integrity-key:github-runtime-eval-test"),
    )
    monkeypatch.setattr(WORKFLOW_CAPABILITY_STORE_CLOCK, "now", lambda: format_utc_timestamp(_ISSUED))


def _descriptor_for_workspace(workspace: Path):
    descriptor = _descriptor()
    return replace(
        descriptor,
        binding_context=replace(
            descriptor.binding_context,
            workspace_sha256=hashlib.sha256(
                canonical_framed_payload("github-workspace", str(workspace.resolve()))
            ).hexdigest(),
        ),
    )


def test_approval_resolution_implicit_timestamp_issues_claimable_capability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    descriptor = _descriptor()
    _ = _seed_resolved_request(store, descriptor, resolved=False)
    monkeypatch.setattr(approvals_module, "_now", lambda: _ISSUED.isoformat())

    resolved = apply_approval_resolution(
        store=store,
        request_id="request-github-1",
        action="allow",
        scope="artifact",
        workspace=None,
        reason="reviewed exact maintenance task",
    )

    assert resolved["resolved_at"] == _ISSUED.isoformat()
    authorization = claim_resolved_github_workflow_authorization(store, "request-github-1", descriptor)
    assert authorization is not None
    signed = store.lookup_workflow_capability(_capability_id("request-github-1"))
    assert signed is not None
    assert signed.claim.issued_at == format_utc_timestamp(_ISSUED)


def test_workflow_approval_identity_accepts_exact_bytes_restored_after_drift(
    tmp_path: Path, native_context_digest: Path
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    executable = workspace / "gh"
    original = b"#!/bin/sh\nexit 0\n"
    executable.write_bytes(original)
    executable.chmod(0o755)
    command = f"{shlex.quote(executable.as_posix())} issue lock 17 --repo example/repo"
    artifact = GuardArtifact(
        artifact_id="codex:project:tool-action:github-restored",
        name="Bash GitHub maintenance",
        harness="codex",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path=str(workspace / ".codex" / "config.toml"),
        command=command,
    )
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        default_action="require-reapproval",
    )

    def record() -> GitHubWorkflowApprovalRecord:
        operation = parse_github_workflow_operation(
            parse_shell_command(command),
            repository="example/repo",
            expected_executable=executable.as_posix(),
        )
        assert operation is not None
        base = _descriptor_for_workspace(workspace)
        descriptor = replace(
            base,
            operation=operation,
            binding_context=replace(
                base.binding_context,
                executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
            ),
        )
        return GitHubWorkflowApprovalRecord.from_descriptor(descriptor)

    def token() -> str:
        return _runtime_hook_approval_context_token(
            artifact=artifact,
            content_hash=hashlib.sha256(executable.read_bytes()).hexdigest(),
            runtime_workspace=workspace,
            action_envelope=None,
            config=config,
            current_config_action="require-reapproval",
            trusted_cli_action=None,
            untrusted_payload_action=None,
            package_action=None,
            data_flow_action=None,
            scanner_action=None,
            current_action="require-reapproval",
            data_flow_signals=(),
            scanner_evidence=(),
            workflow_approval_record=record(),
        )

    approved = token()
    executable.write_bytes(b"#!/bin/sh\nexit 1\n")
    drifted = token()
    executable.write_bytes(original)
    restored = token()

    assert approval_context_tokens_validation_reason(approved, drifted) is not None
    assert restored == approved
