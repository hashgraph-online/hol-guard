from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_command_model import _canonical_command_from_native
from codex_plugin_scanner.guard.runtime import native_command_evaluation
from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntimeSnapshot
from codex_plugin_scanner.guard.runtime.native_command_extension_evidence import observations_from_native_evidence
from tests.native_command_test_support import real_native_review_fixture


@pytest.mark.parametrize(
    ("command", "force_rule_ids", "controls", "expected_rules"),
    [
        (
            "printf hello",
            (),
            (),
            (),
        ),
        (
            "ollama push model",
            ("command.ollama.push",),
            (("extension", "command.ollama", "enabled"),),
            ("command.ollama.push",),
        ),
        (
            "ollama rm old-model --help",
            ("command.ollama.rm",),
            (("extension", "command.ollama", "enabled"),),
            ("command.ollama.rm",),
        ),
        (
            "ollama push model && ollama rm old-model",
            ("command.ollama.push", "command.ollama.rm"),
            (("extension", "command.ollama", "enabled"),),
            ("command.ollama.push", "command.ollama.rm"),
        ),
        (
            "ollama push model",
            ("command.ollama.push",),
            (("extension", "command.ollama", "enabled"), ("permission", "command.ollama.permission.push", "disabled")),
            ("command.ollama.push",),
        ),
    ],
    ids=("benign-read", "cataloged-unsafe", "safe-variant", "compound", "permission-disabled"),
)
def test_real_native_payload_projects_with_exact_bound_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
    force_rule_ids: tuple[str, ...],
    controls: tuple[tuple[str, str, str], ...],
    expected_rules: tuple[str, ...],
) -> None:
    fixture = real_native_review_fixture(command, force_rule_ids=force_rule_ids, controls=controls)
    payload, snapshot = fixture.payload, fixture.snapshot
    model = payload.get("command_model")
    assert isinstance(model, dict), payload
    assert model["normalized_text"] == command
    assert payload["authority"] == "rust"
    evidence = payload.get("command_extensions")
    assert isinstance(evidence, dict)
    assert tuple(item["rule_id"] for item in evidence["observations"]) == expected_rules

    canonical = _canonical_command_from_native(command, model)
    assert canonical is not None
    observations = observations_from_native_evidence(
        payload, BUILT_IN_COMMAND_EXTENSION_REGISTRY, command=canonical, control_snapshot=snapshot
    )
    assert tuple(item.rule.rule_id for item in observations) == expected_rules
    projected = evaluate_command(
        command,
        canonical_command=canonical,
        extension_control_snapshot=snapshot,
        native_extension_evidence=payload,
    )
    assert projected.minimum_action == payload["minimum_action"]

    monkeypatch.setattr(native_command_evaluation, "review_pre_tool_native", lambda *_args, **_kwargs: payload)
    reviewed = native_command_evaluation.review_command_native(
        command, guard_home=tmp_path, extension_control_snapshot=snapshot
    )
    assert reviewed is not None
    assert reviewed.payload is payload
    assert reviewed.snapshot is snapshot
    assert tuple(item.rule.rule_id for item in reviewed.evaluation.extension_observations) == expected_rules
    assert reviewed.evaluation.private_control_evidence == snapshot.private_evidence


def test_real_native_payload_rejects_stale_snapshot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = real_native_review_fixture(
        "ollama push model",
        force_rule_ids=("command.ollama.push",),
        controls=(("extension", "command.ollama", "enabled"),),
    )
    monkeypatch.setattr(native_command_evaluation, "review_pre_tool_native", lambda *_args, **_kwargs: fixture.payload)
    snapshot = fixture.snapshot
    stale = ExtensionControlRuntimeSnapshot(
        snapshot.health,
        snapshot.revision + 1,
        snapshot.catalog_digest,
        snapshot.effective_digest,
        snapshot.layers,
        snapshot.managed_revision,
    )
    assert (
        native_command_evaluation.review_command_native(
            fixture.command, guard_home=tmp_path, extension_control_snapshot=stale
        )
        is None
    )


def test_real_native_transparent_wrapper_preserves_uncertain_envelope() -> None:
    fixture = real_native_review_fixture("zsh -lc 'git stash list'")
    model = fixture.payload.get("command_model")
    assert isinstance(model, dict)
    canonical = _canonical_command_from_native(fixture.command, model)
    assert canonical is not None
    assert canonical.confidence == "uncertain"
    assert canonical.segments == ()
    assert canonical.wrapper_chain == ()
    assert canonical.uncertainty_reason == "transparent_wrapper_not_yet_supported"


def test_real_native_review_classification_accepts_explicit_stash_permission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = real_native_review_fixture(
        "git stash list",
        force_rule_ids=("command.git.stash",),
        controls=(("permission", "command.git.permission.stash", "enabled"),),
    )
    assert fixture.payload["minimum_action"] == "review"
    monkeypatch.setattr(native_command_evaluation, "review_pre_tool_native", lambda *_args, **_kwargs: fixture.payload)
    reviewed = native_command_evaluation.review_command_native(
        fixture.command,
        guard_home=tmp_path,
        extension_control_snapshot=fixture.snapshot,
    )
    assert reviewed is not None
    assert reviewed.native_minimum_action == "review"
    assert reviewed.evaluation.minimum_action == "allow"
    assert reviewed.evaluation.control_resolution.explicitly_enabled_permission_ids == ("command.git.permission.stash",)


def test_native_privileged_wrapper_floor_survives_explicit_command_permission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = real_native_review_fixture(
        "sudo -n git push --force origin feature",
        controls=(("permission", "command.git.permission.force-push", "enabled"),),
    )
    assert fixture.payload["minimum_action"] == "require-reapproval"
    assert fixture.payload["reason_code"] == "native_privileged_wrapper_reapproval"
    monkeypatch.setattr(native_command_evaluation, "review_pre_tool_native", lambda *_args, **_kwargs: fixture.payload)

    reviewed = native_command_evaluation.review_command_native(
        fixture.command, guard_home=tmp_path, extension_control_snapshot=fixture.snapshot
    )

    assert reviewed is not None
    assert reviewed.evaluation.decision_plane.action == "require-reapproval"
    assert any(
        reason.reason_code == "native.privileged-wrapper-reapproval"
        for reason in reviewed.evaluation.decision_plane.controlling_reasons
    )


def test_native_unsupported_heredoc_remains_bound_blocking_unavailability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = real_native_review_fixture("cat <<'EOF'\n$(sh -c 'rm -rf /tmp/example')\nEOF")
    model = fixture.payload.get("command_model")
    assert isinstance(model, dict)
    assert model["confidence"] == "uncertain"
    assert model["segments"] == []
    assert model["uncertainty_reason"] == "command_redirect_not_yet_supported"
    evidence = fixture.payload.get("command_extensions")
    assert isinstance(evidence, dict)
    assert evidence["evaluation_error"] == "native_command_evaluation_failed"
    assert evidence["observations"] == []
    binding = evidence["binding"]
    assert isinstance(binding, dict)
    assert binding["observation_count"] == 0
    assert binding["uncertainty_count"] == 1
    assert fixture.payload["minimum_action"] == "block"

    monkeypatch.setattr(native_command_evaluation, "review_pre_tool_native", lambda *_args, **_kwargs: fixture.payload)
    reviewed = native_command_evaluation.review_command_native(
        fixture.command,
        guard_home=tmp_path,
        extension_control_snapshot=fixture.snapshot,
    )
    assert reviewed is not None
    assert reviewed.payload is fixture.payload
    assert reviewed.snapshot is fixture.snapshot
    assert reviewed.evaluation.minimum_action == "block"
    assert reviewed.evaluation.decision_plane.action == "block"
    assert reviewed.evaluation.matches == ()
    assert reviewed.evaluation.decision_plane.proof_routes == frozenset()
