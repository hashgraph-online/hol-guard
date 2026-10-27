"""Current-policy-first regressions for the resident sensitive-read context."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.consumer import artifact_hash
from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.runtime.approval_context import (
    APPROVAL_CONTEXT_TOKEN_PREFIX,
)
from codex_plugin_scanner.guard.runtime.secret_file_requests import (
    extract_sensitive_file_read_request_artifact,
)
from tests.guard_sensitive_read_support import sensitive_read_current_action, sensitive_read_token


def _sensitive_read_artifact(workspace: Path, *, publisher: str | None = None) -> GuardArtifact:
    _request, artifact = extract_sensitive_file_read_request_artifact(
        "read_file",
        {"path": ".env"},
        cwd=workspace,
        harness="codex",
        config_path=str(workspace / ".mcp.json"),
        source_scope="project",
    )
    assert artifact is not None
    return replace(artifact, publisher=publisher) if publisher is not None else artifact


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
