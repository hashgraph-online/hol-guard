"""Current-policy-first regressions for the resident sensitive-read context."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.consumer import artifact_hash
from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.runtime.approval_context import (
    APPROVAL_CONTEXT_TOKEN_PREFIX,
)
from tests.guard_sensitive_read_support import sensitive_read_current_action, sensitive_read_token


def _sensitive_read_artifact(workspace: Path, *, publisher: str | None = None) -> GuardArtifact:
    """The review the resident builds for ``read_file .env`` in ``workspace``."""

    path = str(workspace / ".env")
    fingerprint = hashlib.sha256(
        json.dumps({"harness": "codex", "normalized_path": path, "tool_name": "read_file"}, sort_keys=True).encode()
    ).hexdigest()
    return GuardArtifact(
        artifact_id=f"codex:project:file-read:{fingerprint}",
        name="read_file .env",
        harness="codex",
        artifact_type="file_read_request",
        source_scope="project",
        config_path=str(workspace / ".mcp.json"),
        publisher=publisher,
        metadata={
            "tool_name": "read_file",
            "normalized_path": path,
            "path_class": "local .env file",
            "request_summary": f"Requested `read_file` access to `{path}` (local .env file).",
            "runtime_request_signals": ["requests access to a sensitive local file"],
            "runtime_request_summary": "Requests access to a sensitive local file: local .env file.",
        },
    )


@pytest.mark.parametrize("override_scope", ["artifact", "harness", "publisher"])
def test_sensitive_read_context_binds_exact_configured_override(
    tmp_path: Path,
    override_scope: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    publisher = "trusted-publisher" if override_scope == "publisher" else None
    artifact = _sensitive_read_artifact(workspace, publisher=publisher)
    base_config = GuardConfig(
        blocked_request_mode="ask",
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        security_level="custom",
        risk_actions={"local_secret_read": "review"},
    )
    changed_kwargs: dict[str, object]
    if override_scope == "artifact":
        changed_kwargs = {"artifact_actions": {artifact.artifact_id: "block"}}
    elif override_scope == "harness":
        changed_kwargs = {"harness_actions": {"codex": "block"}}
    else:
        changed_kwargs = {"publisher_actions": {"trusted-publisher": "block"}}
    changed_config = replace(base_config, **changed_kwargs)
    base_action = sensitive_read_current_action(base_config, artifact=artifact, harness="codex")
    changed_action = sensitive_read_current_action(changed_config, artifact=artifact, harness="codex")

    base_token = sensitive_read_token(
        artifact,
        config=base_config,
        cwd=workspace,
        current_action=base_action,
    )
    changed_token = sensitive_read_token(
        artifact,
        config=changed_config,
        cwd=workspace,
        current_action=changed_action,
    )

    assert base_action == "review"
    assert changed_action == "block"
    assert base_token != changed_token


def test_sensitive_read_exact_allow_overrides_global_block_before_independent_risk_review(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    artifact = _sensitive_read_artifact(workspace)
    config = GuardConfig(
        blocked_request_mode="ask",
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        default_action="block",
        artifact_actions={artifact.artifact_id: "allow"},
        risk_actions={"local_secret_read": "review"},
    )

    action = sensitive_read_current_action(config, artifact=artifact, harness="codex")

    assert action == "review"


def test_sensitive_read_risk_block_outranks_exact_allow(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    artifact = _sensitive_read_artifact(workspace)
    config = GuardConfig(
        blocked_request_mode="ask",
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        default_action="block",
        artifact_actions={artifact.artifact_id: "allow"},
        risk_actions={"local_secret_read": "block"},
    )

    action = sensitive_read_current_action(config, artifact=artifact, harness="codex")

    assert action == "block"


def test_sensitive_read_legacy_artifact_digest_is_not_approval_authority(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    artifact = _sensitive_read_artifact(workspace)
    config = GuardConfig(
        blocked_request_mode="ask",
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        security_level="custom",
        risk_actions={"local_secret_read": "review"},
    )

    context_token = sensitive_read_token(
        artifact,
        config=config,
        cwd=workspace,
        current_action="review",
    )

    assert context_token.startswith(APPROVAL_CONTEXT_TOKEN_PREFIX)
    assert context_token != artifact_hash(artifact)
