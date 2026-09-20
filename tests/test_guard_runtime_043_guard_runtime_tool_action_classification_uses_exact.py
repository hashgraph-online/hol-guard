"""Runtime regression tests: guard runtime tool action classification uses exact."""

from __future__ import annotations

from tests.guard_runtime_test_dependencies import (
    GuardApprovalRequest,
    GuardArtifact,
    GuardConfig,
    GuardStore,
    Path,
    _runtime_scoped_exact_match_key,
    apply_approval_resolution,
    guard_commands_module,
    pytest,
    runtime_tool_action_exact_match_context,
)
from tests.guard_runtime_test_support import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)


def test_guard_runtime_tool_action_classification_uses_exact_action_classes():
    artifact = GuardArtifact(
        artifact_id="codex:test:tool-action:non-destructive",
        name="Bash non-destructive shell command",
        harness="codex",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path="/dev/null",
        metadata={"action_class": "non-destructive shell command"},
    )

    assert guard_commands_module._runtime_artifact_risk_classes(artifact) == []


def test_guard_runtime_tool_action_classification_emits_network_and_docker_risks():
    upload_artifact = GuardArtifact(
        artifact_id="codex:test:tool-action:upload",
        name="Bash shell file upload command",
        harness="codex",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path="/dev/null",
        metadata={"action_class": "shell file upload command"},
    )
    docker_artifact = GuardArtifact(
        artifact_id="codex:test:tool-action:docker",
        name="Bash docker-sensitive command",
        harness="codex",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path="/dev/null",
        metadata={"action_class": "docker-sensitive command"},
    )
    docker_config_artifact = GuardArtifact(
        artifact_id="codex:test:tool-action:docker-config",
        name="Bash Docker client config access",
        harness="codex",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path="/dev/null",
        metadata={"action_class": "Docker client config access"},
    )

    assert guard_commands_module._runtime_artifact_risk_classes(upload_artifact) == [
        "credential_exfiltration",
        "network_egress",
    ]
    assert guard_commands_module._runtime_artifact_risk_classes(docker_artifact) == [
        "network_egress",
        "destructive_shell",
    ]
    assert guard_commands_module._runtime_artifact_risk_classes(docker_config_artifact) == ["local_secret_read"]


def test_guard_runtime_tool_action_policy_uses_network_egress_when_stricter(tmp_path):
    artifact = GuardArtifact(
        artifact_id="codex:test:tool-action:upload",
        name="Bash shell file upload command",
        harness="codex",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path="/dev/null",
        metadata={"action_class": "shell file upload command"},
    )
    config = GuardConfig(
        guard_home=tmp_path,
        workspace=None,
        security_level="custom",
        risk_actions={
            "credential_exfiltration": "allow",
            "network_egress": "block",
        },
    )

    assert guard_commands_module._runtime_artifact_policy_action(config, artifact, "codex") == "block"


@pytest.mark.parametrize(
    "scope",
    [
        "harness",
        "global",
    ],
)
def test_guard_runtime_requires_exact_context_for_saved_broad_risky_tool_action(
    tmp_path: Path,
    scope: str,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    workspace = tmp_path / "workspace"
    request = GuardApprovalRequest(
        request_id=f"req-opencode-{scope}",
        harness="opencode",
        artifact_id="opencode:project:tool-action:docker-compose-postgres",
        artifact_name="Bash docker-sensitive command",
        artifact_type="tool_action_request",
        artifact_hash="hash-request",
        publisher=None,
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("tool_action_request",),
        source_scope="project",
        config_path=str(workspace / "opencode.json"),
        workspace=str(workspace),
        launch_target="docker compose -f scripts/guard-cloud/docker-lab/docker-compose.yml up -d postgres",
        review_command=f"hol-guard approvals approve req-opencode-{scope}",
        approval_url=f"http://127.0.0.1:5474/requests/req-opencode-{scope}",
        action_envelope_json={
            "schema_version": 1,
            "action_id": f"req-opencode-{scope}",
            "harness": "opencode",
            "event_name": "PreToolUse",
            "action_type": "shell_command",
            "workspace": str(workspace),
            "workspace_hash": "workspace-hash",
            "tool_name": "Bash",
            "command": "docker compose -f scripts/guard-cloud/docker-lab/docker-compose.yml up -d postgres",
            "prompt_excerpt": None,
            "target_paths": [],
            "network_hosts": [],
            "mcp_server": None,
            "mcp_tool": None,
            "package_manager": None,
            "package_name": None,
            "script_name": None,
            "raw_payload_redacted": {"tool_name": "Bash"},
        },
    )
    store.add_approval_request(request, "2026-06-12T00:00:00+00:00")

    resolution = apply_approval_resolution(
        store=store,
        request_id=request.request_id,
        action="allow",
        scope=scope,
        workspace=request.workspace,
        reason=f"saved for {scope}",
        now="2026-06-12T00:01:00+00:00",
    )

    assert resolution["requested_scope"] == scope
    assert resolution["applied_scope"] == scope
    assert "scope_warning" not in resolution

    runtime_artifact = GuardArtifact(
        artifact_id=request.artifact_id,
        name=request.artifact_name,
        harness="opencode",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path=request.config_path,
        publisher=None,
        metadata={"action_class": "docker-sensitive command"},
    )

    assert (
        guard_commands_module._runtime_stored_policy_action(
            store=store,
            harness="opencode",
            artifact=runtime_artifact,
            artifact_id=runtime_artifact.artifact_id,
            artifact_hash="hash-retry",
            workspace=str(workspace),
        )
        is None
    )


@pytest.mark.parametrize(
    "scope",
    [
        "harness",
        "global",
    ],
)
def test_guard_runtime_rejects_saved_allows_for_different_risky_tool_action(
    tmp_path: Path,
    scope: str,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    workspace = tmp_path / "workspace"
    request = GuardApprovalRequest(
        request_id=f"req-opencode-{scope}",
        harness="opencode",
        artifact_id="opencode:project:tool-action:docker-compose-postgres",
        artifact_name="Bash docker-sensitive command",
        artifact_type="tool_action_request",
        artifact_hash="hash-request",
        publisher=None,
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("tool_action_request",),
        source_scope="project",
        config_path=str(workspace / "opencode.json"),
        workspace=str(workspace),
        launch_target="docker compose -f scripts/guard-cloud/docker-lab/docker-compose.yml up -d postgres",
        review_command=f"hol-guard approvals approve req-opencode-{scope}",
        approval_url=f"http://127.0.0.1:5474/requests/req-opencode-{scope}",
        action_envelope_json={
            "schema_version": 1,
            "action_id": f"req-opencode-{scope}",
            "harness": "opencode",
            "event_name": "PreToolUse",
            "action_type": "shell_command",
            "workspace": str(workspace),
            "workspace_hash": "workspace-hash",
            "tool_name": "Bash",
            "command": "docker compose -f scripts/guard-cloud/docker-lab/docker-compose.yml up -d postgres",
            "prompt_excerpt": None,
            "target_paths": [],
            "network_hosts": [],
            "mcp_server": None,
            "mcp_tool": None,
            "package_manager": None,
            "package_name": None,
            "script_name": None,
            "raw_payload_redacted": {"tool_name": "Bash"},
        },
    )
    store.add_approval_request(request, "2026-06-12T00:00:00+00:00")

    resolution = apply_approval_resolution(
        store=store,
        request_id=request.request_id,
        action="allow",
        scope=scope,
        workspace=request.workspace,
        reason=f"saved for {scope}",
        now="2026-06-12T00:01:00+00:00",
    )

    assert resolution["requested_scope"] == scope
    assert resolution["applied_scope"] == scope
    assert "scope_warning" not in resolution

    later_artifact = GuardArtifact(
        artifact_id="opencode:project:tool-action:credential-upload",
        name="Bash shell file upload command",
        harness="opencode",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path=request.config_path,
        publisher=None,
        metadata={"action_class": "shell file upload command"},
    )
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=None,
        security_level="balanced",
    )

    assert (
        guard_commands_module._runtime_stored_policy_action(
            store=store,
            harness="opencode",
            artifact=later_artifact,
            artifact_id=later_artifact.artifact_id,
            artifact_hash="hash-later",
            workspace=str(workspace),
        )
        is None
    )
    assert (
        guard_commands_module._runtime_artifact_policy_action(config, later_artifact, "opencode")
        == "require-reapproval"
    )


def test_guard_runtime_accepts_contextual_harness_tool_action_policy(tmp_path):
    workspace = tmp_path / "workspace"
    artifact_id = "opencode:project:tool-action:docker-compose-postgres"
    wrapper_chain = ["bash", "zsh"]
    context = runtime_tool_action_exact_match_context(
        config_path=str(workspace / "opencode.json"),
        source_scope="project",
        raw_command_text="docker compose up -d postgres",
        wrapper_chain=wrapper_chain,
    )
    contextual_key = _runtime_scoped_exact_match_key(artifact_id, context)
    assert contextual_key is not None
    expected_workspace = str(workspace)

    class _Store:
        def resolve_policy_decision(
            self,
            harness: str,
            requested_artifact_id: str,
            artifact_hash: str | None = None,
            workspace: str | None = None,
            publisher: str | None = None,
            now: str | None = None,
            runtime_exact_match_context: str | None = None,
        ) -> dict[str, object]:
            assert harness == "opencode"
            assert requested_artifact_id == artifact_id
            assert artifact_hash == "hash-retry"
            assert workspace == expected_workspace
            assert publisher is None
            assert now is None
            assert runtime_exact_match_context == context
            return {
                "action": "allow",
                "scope": "harness",
                "artifact_id": artifact_id,
                "artifact_hash": contextual_key,
            }

    runtime_artifact = GuardArtifact(
        artifact_id=artifact_id,
        name="Bash docker-sensitive command",
        harness="opencode",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path=str(workspace / "opencode.json"),
        publisher=None,
        metadata={
            "action_class": "docker-sensitive command",
            "raw_command_text": "docker compose up -d postgres",
            "wrapper_chain": wrapper_chain,
        },
    )

    assert (
        guard_commands_module._runtime_stored_policy_action(
            store=_Store(),
            harness="opencode",
            artifact=runtime_artifact,
            artifact_id=runtime_artifact.artifact_id,
            artifact_hash="hash-retry",
            workspace=str(workspace),
        )
        == "allow"
    )


def test_guard_runtime_contextual_tool_action_lookup_skips_legacy_fallback_after_integrity_rejection(tmp_path):
    workspace = tmp_path / "workspace"
    artifact_id = "opencode:project:tool-action:docker-compose-postgres"
    runtime_artifact = GuardArtifact(
        artifact_id=artifact_id,
        name="Bash docker-sensitive command",
        harness="opencode",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path=str(workspace / "opencode.json"),
        publisher=None,
        metadata={
            "action_class": "docker-sensitive command",
            "raw_command_text": "docker compose up -d postgres",
            "wrapper_chain": ["bash", "zsh"],
        },
    )

    class _Store:
        def resolve_policy_decision(self, *args, **kwargs) -> dict[str, object] | None:
            raise AssertionError("legacy fallback should not re-query after an integrity rejection lookup")

    assert (
        guard_commands_module._runtime_stored_policy_action(
            store=_Store(),
            harness="opencode",
            artifact=runtime_artifact,
            artifact_id=runtime_artifact.artifact_id,
            artifact_hash="hash-retry",
            workspace=str(workspace),
            decision_lookup={
                "decision": None,
                "ignored_local_integrity": {
                    "source": "local_rule",
                    "scope": "harness",
                },
                "trust_status": {
                    "remembered_rules": "disabled_degraded",
                },
            },
        )
        is None
    )


def test_guard_runtime_tool_action_policy_prefers_configured_risk_action_over_default(tmp_path):
    artifact = GuardArtifact(
        artifact_id="codex:test:tool-action:upload",
        name="Codex credential-looking output",
        harness="codex",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path="/dev/null",
        metadata={
            "action_class": "credential exfiltration shell command",
            "guard_default_action": "warn",
        },
    )
    config = GuardConfig(
        guard_home=tmp_path,
        workspace=None,
        security_level="custom",
        risk_actions={"credential_exfiltration": "block"},
    )

    assert guard_commands_module._runtime_artifact_policy_action(config, artifact, "codex") == "block"


def test_guard_runtime_tool_action_policy_includes_defaults_for_unconfigured_risks(tmp_path):
    artifact = GuardArtifact(
        artifact_id="codex:test:tool-action:upload",
        name="Codex credential-looking output",
        harness="codex",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path="/dev/null",
        metadata={
            "action_class": "credential exfiltration shell command",
            "guard_default_action": "warn",
        },
    )
    config = GuardConfig(
        guard_home=tmp_path,
        workspace=None,
        security_level="balanced",
        risk_actions={"network_egress": "allow"},
    )

    assert guard_commands_module._runtime_artifact_policy_action(config, artifact, "codex") == "require-reapproval"
