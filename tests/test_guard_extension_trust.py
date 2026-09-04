"""Trust-class map, catalog defaults, and inert-external evaluation."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.daemon.extension_control_projection import (
    build_effective_extension_control_projection,
)
from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)
from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntimeSnapshot
from codex_plugin_scanner.guard.runtime.extension_trust import (
    catalog_enabled,
    ids_for_class,
    mapped_ids,
    trust_class_for,
)

_NOODLE = "noodle request run users/get --collection ./my-api --env staging"
_AWS = "aws --profile prod --region us-east-1 ec2 terminate-instances --instance-ids i-123"
_GIT = "git push --force origin main"


def _enable_layer(extension_id: str) -> ExtensionControlLayer:
    return ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=False,
        controls=(
            ExtensionControl(
                target=ControlTarget(ControlTargetKind.EXTENSION, extension_id),
                state=ControlState.ENABLED,
            ),
        ),
    )


def _layer(kind: ControlLayerKind, extension_id: str, state: ControlState) -> ExtensionControlLayer:
    return ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=kind,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=False,
        controls=(
            ExtensionControl(
                target=ControlTarget(ControlTargetKind.EXTENSION, extension_id),
                state=state,
            ),
        ),
    )


def _disable_layer(extension_id: str) -> ExtensionControlLayer:
    return ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=False,
        controls=(
            ExtensionControl(
                target=ControlTarget(ControlTargetKind.EXTENSION, extension_id),
                state=ControlState.DISABLED,
            ),
        ),
    )


def test_trust_map_covers_every_builtin_extension() -> None:
    registry_ids = {extension.extension_id for extension in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions}
    assert mapped_ids() == registry_ids
    assert ids_for_class("external") == {
        "command.blitcp",
        "command.noodle",
        "command.probe",
        "command.repo2nb",
        "command.skill-sunset",
    }
    assert trust_class_for("command.git") == "first-party"
    assert trust_class_for("command.cloud.aws") == "trusted-library"
    assert trust_class_for("command.cloud.azure") == "trusted-library"
    assert trust_class_for("command.noodle") == "external"
    assert trust_class_for("command.unmapped-community") == "external"
    assert trust_class_for("command.test") == "first-party"


def test_local_catalog_marks_external_off_and_libraries_on() -> None:
    noodle = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.noodle")
    aws = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.cloud.aws")
    git = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.git")
    assert noodle is not None and aws is not None and git is not None
    noodle_payload = noodle.to_dict()
    aws_payload = aws.to_dict()
    git_payload = git.to_dict()
    assert noodle_payload["enabled"] is False
    assert noodle_payload["trust_class"] == "external"
    assert noodle_payload["activation"] == "opt-in"
    assert noodle_payload["publisher"]["id"] == "community.wilfredinni"
    assert noodle_payload["icon"]["kind"] == "react-icon"
    assert noodle_payload["icon"]["name"] == "HiMiniBolt"
    assert aws_payload["enabled"] is True
    assert aws_payload["trust_class"] == "trusted-library"
    assert git_payload["enabled"] is True
    assert git_payload["trust_class"] == "first-party"
    assert catalog_enabled("command.noodle", required=False) is False


def test_noodle_stays_inert_until_explicitly_enabled(tmp_path: Path) -> None:
    inert = evaluate_command(_NOODLE, cwd=tmp_path, home_dir=tmp_path)
    assert all(item.extension.extension_id != "command.noodle" for item in inert.extension_observations)
    assert inert.controlling_rule_id != "command.noodle.run"

    enabled = evaluate_command(
        _NOODLE,
        cwd=tmp_path,
        home_dir=tmp_path,
        extension_control_layers=(_enable_layer("command.noodle"),),
    )
    assert any(item.extension.extension_id == "command.noodle" for item in enabled.extension_observations)
    assert enabled.controlling_rule_id == "command.noodle.run"

    disabled = evaluate_command(
        _NOODLE,
        cwd=tmp_path,
        home_dir=tmp_path,
        extension_control_layers=(_disable_layer("command.noodle"),),
    )
    assert all(item.extension.extension_id != "command.noodle" for item in disabled.extension_observations)
    assert disabled.controlling_rule_id != "command.noodle.run"


def test_aws_and_git_stay_on_without_opt_in(tmp_path: Path) -> None:
    aws = evaluate_command(_AWS, cwd=tmp_path, home_dir=tmp_path)
    git = evaluate_command(_GIT, cwd=tmp_path, home_dir=tmp_path)
    assert any(item.extension.extension_id == "command.cloud.aws" for item in aws.extension_observations)
    assert any(item.extension.extension_id == "command.git" for item in git.extension_observations)


def test_cloud_catalog_wire_omits_local_trust_fields() -> None:
    from codex_plugin_scanner.guard.runtime.extension_catalog_sync import build_builtin_extension_catalog_wire

    wire = build_builtin_extension_catalog_wire(guard_version="3.0.51", generated_at="2026-09-04T00:00:00Z")
    extension = next(item for item in wire["extensions"] if item["id"] == "command.noodle")
    assert "trustClass" not in extension
    assert "trust_class" not in extension
    assert "activation" not in extension
    assert "publisher" not in extension
    assert "icon" not in extension
    assert set(extension) == {
        "id",
        "version",
        "name",
        "source",
        "executables",
        "ecosystemIds",
        "riskClasses",
        "delegatedProtection",
        "deprecated",
        "replacementId",
        "permissions",
    }


def test_signed_cloud_enable_does_not_activate_external(tmp_path: Path) -> None:
    evaluation = evaluate_command(
        _NOODLE,
        cwd=tmp_path,
        home_dir=tmp_path,
        extension_control_layers=(_layer(ControlLayerKind.SIGNED_CLOUD, "command.noodle", ControlState.ENABLED),),
    )
    assert all(item.extension.extension_id != "command.noodle" for item in evaluation.extension_observations)


def test_compatibility_class_does_not_revive_inert_external(tmp_path: Path) -> None:
    evaluation = evaluate_command(
        _NOODLE,
        cwd=tmp_path,
        home_dir=tmp_path,
        compatibility_action_class="Noodle request execution command",
    )
    assert all(item.extension.extension_id != "command.noodle" for item in evaluation.extension_observations)
    assert all(owned.extension.extension_id != "command.noodle" for owned in evaluation.matches)
    assert evaluation.controlling_rule_id != "command.noodle.run"


def test_projection_marks_inert_external_blocked_until_local_enable() -> None:
    empty = ExtensionControlRuntimeSnapshot.from_authority_view(
        ExtensionControlAuthorityView(
            AuthorityHealth.PROTECTED,
            1,
            BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
            (),
        )
    )
    inert = build_effective_extension_control_projection(BUILT_IN_COMMAND_EXTENSION_REGISTRY, empty)
    noodle = next(item for item in inert["extensions"] if item["extension_id"] == "command.noodle")
    git = next(item for item in inert["extensions"] if item["extension_id"] == "command.git")
    assert noodle["effective_state"] == "blocked"
    assert git["effective_state"] == "allowed"

    enabled = ExtensionControlRuntimeSnapshot.from_authority_view(
        ExtensionControlAuthorityView(
            AuthorityHealth.PROTECTED,
            2,
            BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
            (_enable_layer("command.noodle"),),
        )
    )
    active = build_effective_extension_control_projection(BUILT_IN_COMMAND_EXTENSION_REGISTRY, enabled)
    noodle_on = next(item for item in active["extensions"] if item["extension_id"] == "command.noodle")
    assert noodle_on["effective_state"] == "allowed"
    assert noodle_on["local_state"] == "enabled"


def test_disabling_aws_still_blocks(tmp_path: Path) -> None:
    evaluation = evaluate_command(
        _AWS,
        cwd=tmp_path,
        home_dir=tmp_path,
        extension_control_layers=(_disable_layer("command.cloud.aws"),),
    )
    assert evaluation.minimum_action == "block"
