from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.cli.commands_support_runtime_policy import _runtime_artifact_policy_action
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.runtime import secret_file_requests
from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.native_command_extension_evidence import NativeCommandExtensionEvidenceError
from tests.test_guard_command_decision_routing import _synthetic_native_fixture


def test_matcher_failure_central_block_reaches_final_runtime_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry, snapshot, command, payload = _synthetic_native_fixture(mode="disabled", uncertainty=True)
    evaluation = evaluate_command(
        command.normalized_text,
        canonical_command=command,
        registry=registry,
        extension_control_snapshot=snapshot,
        native_extension_evidence=payload,
    )
    assert evaluation.extension_observations[0].to_dict()["uncertainty_reasons"] == ["matcher-failure"]
    monkeypatch.setattr(secret_file_requests, "BUILT_IN_COMMAND_EXTENSION_REGISTRY", registry)
    request = secret_file_requests.extract_sensitive_tool_action_request(
        "Shell",
        {"command": command.normalized_text},
        canonical_command=command,
        native_evaluation=evaluation,
    )
    assert request is not None
    artifact = secret_file_requests.build_tool_action_request_artifact(
        "codex",
        request,
        config_path="guard-config",
        source_scope="project",
        extension_control_snapshot=snapshot,
        native_extension_evidence=payload,
        native_evaluation=evaluation,
    )

    assert artifact.metadata["command_action_floor"] == "block"
    decision = cast(dict[str, object], artifact.metadata["command_decision_plane"])
    assert decision["action"] == "block"
    config = GuardConfig(guard_home=tmp_path / "guard-home", workspace=tmp_path, default_action="allow")
    assert _runtime_artifact_policy_action(config, artifact, "codex") == "block"
    assert "private matcher detail" not in repr(artifact.metadata)

    floor = artifact.metadata.pop("command_action_floor")
    assert _runtime_artifact_policy_action(config, artifact, "codex") == "require-reapproval"
    artifact.metadata["command_action_floor"] = None
    assert _runtime_artifact_policy_action(config, artifact, "codex") == "block"
    artifact.metadata["command_action_floor"] = "invalid"
    assert _runtime_artifact_policy_action(config, artifact, "codex") == "block"
    artifact.metadata["command_action_floor"] = floor
    assert _runtime_artifact_policy_action(config, artifact, "codex") == "block"

    # Only the typed native failure reaches policy. Private matcher diagnostics
    # must be rejected even when the observation digest is internally valid.
    native = payload["command_extensions"]
    native["observations"][0]["matcher_evidence"][0]["detail"] = "private matcher detail"
    canonical = json.dumps(
        {key: native[key] for key in ("observations", "permission_observations", "evaluation_error")},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    native["binding"]["observations_digest"] = hashlib.sha256(
        b"hol-guard.native-command-observations.v1\0" + canonical
    ).hexdigest()
    with pytest.raises(NativeCommandExtensionEvidenceError, match="native_command_extension_evidence_invalid") as error:
        evaluate_command(
            command.normalized_text,
            canonical_command=command,
            registry=registry,
            extension_control_snapshot=snapshot,
            native_extension_evidence=payload,
        )
    assert "private matcher detail" not in str(error.value)


def test_verified_pytest_restricted_profile_overrides_generic_execution_floor(tmp_path: Path) -> None:
    artifact = GuardArtifact(
        artifact_id="codex:test:tool-action:pytest",
        name="Bash pytest repository-code execution",
        harness="codex",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path="/dev/null",
        metadata={
            "action_class": "pytest repository-code execution",
            "command_action_floor": "block",
            "guard_default_action": "sandbox-required",
            "reason_code": "pytest_restricted_profile_required",
            "restricted_profile_version": "pytest-restricted-v1",
        },
    )
    config = GuardConfig(guard_home=tmp_path / "guard-home", workspace=tmp_path, default_action="allow")

    assert _runtime_artifact_policy_action(config, artifact, "codex") == "sandbox-required"

    artifact.metadata.pop("restricted_profile_version")
    assert _runtime_artifact_policy_action(config, artifact, "codex") == "block"
