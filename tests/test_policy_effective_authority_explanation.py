"""HGP-155: effective-authority copy matches execution."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.policy_effective_authority import EFFECTIVE_AUTHORITY_EXAMPLES
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)
from codex_plugin_scanner.guard.runtime.extension_control_resolver import compose_control_layers
from codex_plugin_scanner.guard.store import GuardStore


def test_effective_authority_examples_cover_required_paths() -> None:
    ids = {example["id"] for example in EFFECTIVE_AUTHORITY_EXAMPLES}
    assert ids == {
        "newer-local-allow-vs-generic-cloud-block",
        "managed-disabled-vs-local-enabled",
        "intrinsic-native-block-vs-policy-allow",
    }
    for example in EFFECTIVE_AUTHORITY_EXAMPLES:
        assert example["winner"]
        assert example["shadowed"]
        assert example["reason"]


def test_newer_local_allow_wins_same_specificity_timestamp(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    artifact = "codex:project:shared-artifact"
    store.replace_remote_policies(
        [
            PolicyDecision(
                harness="codex",
                scope="artifact",
                action="block",
                artifact_id=artifact,
                reason="cloud block",
                source="policy-bundle",
            )
        ],
        "2026-07-18T00:00:00Z",
        remote_write_authorized=True,
    )
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="allow",
            artifact_id=artifact,
            reason="local allow",
            source="local",
        ),
        "2026-07-18T01:00:00Z",
    )
    winner = store.resolve_policy_decision("codex", artifact, now="2026-07-18T02:00:00Z")
    assert winner is not None
    assert winner["action"] == "allow"
    assert winner["source"] == "local"


def test_managed_disable_dominates_local_enable() -> None:
    extension_id = BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions[0].extension_id
    local = ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=False,
        controls=(ExtensionControl(ControlTarget(ControlTargetKind.EXTENSION, extension_id), ControlState.ENABLED),),
    )
    cloud = ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.SIGNED_CLOUD,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=False,
        controls=(ExtensionControl(ControlTarget(ControlTargetKind.EXTENSION, extension_id), ControlState.DISABLED),),
    )
    composed = compose_control_layers((local, cloud))
    assert composed.state_for(ControlTargetKind.EXTENSION, extension_id) is ControlState.DISABLED
