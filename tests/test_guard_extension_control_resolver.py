from __future__ import annotations

import itertools
from dataclasses import FrozenInstanceError, replace
from typing import cast

import pytest

from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    CommandSafetyExtensionRegistry,
)
from codex_plugin_scanner.guard.runtime.effect_decision import EffectDecisionRequest, evaluate_effect_decision
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlResolverFailure,
    ControlState,
    ControlSurface,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
    ResolverFailureCode,
)
from codex_plugin_scanner.guard.runtime.extension_control_resolver import (
    compose_control_layers,
    resolve_extension_controls,
)


def _catalog_subjects() -> tuple[str, str]:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions[0]
    return extension.extension_id, extension.permissions[0].permission_id


def _layer(
    kind: ControlLayerKind,
    *controls: ExtensionControl,
    lockdown: bool = False,
    digest: str | None = None,
) -> ExtensionControlLayer:
    return ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=kind,
        catalog_digest=digest or BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=lockdown,
        controls=controls,
    )


def _control(kind: ControlTargetKind, target_id: str, state: ControlState) -> ExtensionControl:
    return ExtensionControl(ControlTarget(kind, target_id), state)


def test_control_contract_is_versioned_immutable_and_exactly_typed() -> None:
    extension_id, _ = _catalog_subjects()
    control = _control(ControlTargetKind.EXTENSION, extension_id, ControlState.DISABLED)
    layer = _layer(ControlLayerKind.LOCAL_ADMIN, control)

    assert layer.schema_version == "1.0.0"
    assert layer.controls == (control,)
    with pytest.raises(FrozenInstanceError):
        layer.__setattr__("global_lockdown", False)
    with pytest.raises(ValueError, match="schema version"):
        replace(layer, schema_version="2.0.0")
    with pytest.raises(ValueError, match="exact ControlState"):
        ExtensionControl(control.target, cast(ControlState, "disabled"))


def test_composition_is_permutation_independent_and_disable_dominates_enable() -> None:
    extension_id, permission_id = _catalog_subjects()
    local = _layer(
        ControlLayerKind.LOCAL_ADMIN,
        _control(ControlTargetKind.EXTENSION, extension_id, ControlState.ENABLED),
        _control(ControlTargetKind.PERMISSION, permission_id, ControlState.DISABLED),
    )
    cloud = _layer(
        ControlLayerKind.SIGNED_CLOUD,
        _control(ControlTargetKind.EXTENSION, extension_id, ControlState.DISABLED),
        _control(ControlTargetKind.PERMISSION, permission_id, ControlState.ENABLED),
    )

    compositions = {compose_control_layers(order) for order in itertools.permutations((local, cloud))}
    assert len(compositions) == 1
    composed = compositions.pop()
    assert composed.global_lockdown is False
    assert composed.state_for(ControlTargetKind.EXTENSION, extension_id) is ControlState.DISABLED
    assert composed.state_for(ControlTargetKind.PERMISSION, permission_id) is ControlState.DISABLED


def test_adding_restrictions_never_reduces_the_resolved_action() -> None:
    extension_id, permission_id = _catalog_subjects()
    targets = (
        (ControlTargetKind.EXTENSION, extension_id),
        (ControlTargetKind.PERMISSION, permission_id),
    )
    actions: dict[frozenset[int], str] = {}
    for count in range(len(targets) + 1):
        for indexes in itertools.combinations(range(len(targets)), count):
            disabled = frozenset(indexes)
            controls = tuple(
                _control(kind, target_id, ControlState.DISABLED)
                for index, (kind, target_id) in enumerate(targets)
                if index in disabled
            )
            resolution = resolve_extension_controls(
                (_layer(ControlLayerKind.LOCAL_ADMIN, *controls),),
                BUILT_IN_COMMAND_EXTENSION_REGISTRY,
                extension_ids=(extension_id,),
                permission_ids=(permission_id,),
                surface=ControlSurface.COMMAND_EVALUATION,
            )
            actions[disabled] = evaluate_effect_decision(EffectDecisionRequest(resolution.factors)).action

    assert actions[frozenset()] != "block"
    assert all(action == "block" for disabled, action in actions.items() if disabled)


def test_global_lockdown_preserves_observations_and_allows_only_typed_local_recovery() -> None:
    extension_id, permission_id = _catalog_subjects()
    layer = _layer(ControlLayerKind.LOCAL_ADMIN, lockdown=True)
    observations = ("classification:package-manager", "classification:remote-mutation")

    command = resolve_extension_controls(
        (layer,),
        BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        extension_ids=(extension_id,),
        permission_ids=(permission_id,),
        surface=ControlSurface.COMMAND_EVALUATION,
        observations=observations,
    )
    recovery = resolve_extension_controls(
        (layer,),
        BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        extension_ids=(),
        permission_ids=(),
        surface=ControlSurface.TRUSTED_LOCAL_RECOVERY,
        observations=observations,
    )

    assert command.blocked is True
    assert command.observations == observations
    assert command.factors[0].reason_code == "control.global-lockdown"
    assert recovery.blocked is False
    assert recovery.factors == ()
    assert recovery.observations == observations


def test_disabled_extension_permission_dependency_and_implied_permission_each_block() -> None:
    owner = next(
        extension for extension in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions if len(extension.permissions) >= 2
    )
    dependency = next(
        extension
        for extension in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions
        if extension.extension_id != owner.extension_id and extension.permissions
    )
    dependency_permission = owner.permissions[1]
    owner_permission = replace(
        owner.permissions[0],
        dependencies=(dependency_permission.permission_id,),
        implied_permissions=(),
    )
    owner = replace(
        owner,
        dependencies=(dependency.extension_id,),
        permissions=(owner_permission, *owner.permissions[1:]),
    )
    registry = CommandSafetyExtensionRegistry((owner, dependency))
    scenarios = (
        (
            (owner.extension_id,),
            (),
            _control(ControlTargetKind.EXTENSION, owner.extension_id, ControlState.DISABLED),
        ),
        (
            (),
            (owner_permission.permission_id,),
            _control(ControlTargetKind.PERMISSION, owner_permission.permission_id, ControlState.DISABLED),
        ),
        (
            (owner.extension_id,),
            (),
            _control(ControlTargetKind.EXTENSION, dependency.extension_id, ControlState.DISABLED),
        ),
        (
            (),
            (owner_permission.permission_id,),
            _control(
                ControlTargetKind.PERMISSION,
                dependency_permission.permission_id,
                ControlState.DISABLED,
            ),
        ),
    )

    for extension_ids, permission_ids, control in scenarios:
        layer = ExtensionControlLayer(
            schema_version=CONTROL_SCHEMA_VERSION,
            kind=ControlLayerKind.LOCAL_ADMIN,
            catalog_digest=registry.catalog_digest,
            global_lockdown=False,
            controls=(control,),
        )
        resolution = resolve_extension_controls(
            (layer,),
            registry,
            extension_ids=extension_ids,
            permission_ids=permission_ids,
            surface=ControlSurface.COMMAND_EVALUATION,
        )
        assert resolution.blocked is True
        assert evaluate_effect_decision(EffectDecisionRequest(resolution.factors)).action == "block"


def test_resolver_failures_are_typed_privacy_safe_and_fail_closed() -> None:
    extension_id, _ = _catalog_subjects()
    cases = (
        (
            (_layer(ControlLayerKind.LOCAL_ADMIN, digest="0" * 64),),
            (extension_id,),
            ResolverFailureCode.CATALOG_DIGEST_MISMATCH,
        ),
        (
            (_layer(ControlLayerKind.LOCAL_ADMIN),),
            ("command.private-unknown-input",),
            ResolverFailureCode.UNKNOWN_EXTENSION_TARGET,
        ),
    )
    for layers, extension_ids, expected_code in cases:
        resolution = resolve_extension_controls(
            layers,
            BUILT_IN_COMMAND_EXTENSION_REGISTRY,
            extension_ids=extension_ids,
            permission_ids=(),
            surface=ControlSurface.COMMAND_EVALUATION,
        )
        assert resolution.blocked is True
        assert resolution.failures[0].code is expected_code
        assert evaluate_effect_decision(EffectDecisionRequest(resolution.factors)).action == "block"
        serialized = repr(resolution.factors)
        assert "private-unknown-input" not in serialized


def test_duplicate_layers_targets_and_invalid_surface_fail_closed() -> None:
    extension_id, _ = _catalog_subjects()
    control = _control(ControlTargetKind.EXTENSION, extension_id, ControlState.DISABLED)
    duplicate_target = _layer(ControlLayerKind.LOCAL_ADMIN, control, control)
    duplicate_kind = (
        _layer(ControlLayerKind.LOCAL_ADMIN),
        _layer(ControlLayerKind.LOCAL_ADMIN),
    )

    for layers, expected in (
        ((duplicate_target,), ResolverFailureCode.DUPLICATE_TARGET_IN_LAYER),
        (duplicate_kind, ResolverFailureCode.DUPLICATE_LAYER_KIND),
    ):
        resolution = resolve_extension_controls(
            layers,
            BUILT_IN_COMMAND_EXTENSION_REGISTRY,
            extension_ids=(extension_id,),
            permission_ids=(),
            surface=ControlSurface.COMMAND_EVALUATION,
        )
        assert resolution.blocked is True
        assert resolution.failures[0].code is expected

    invalid = resolve_extension_controls(
        (),
        BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        extension_ids=(extension_id,),
        permission_ids=(),
        surface=cast(ControlSurface, "recovery/by-path"),
    )
    assert invalid.blocked is True
    assert invalid.failures[0].code is ResolverFailureCode.INVALID_CONTROL_SURFACE


def test_resolver_rejects_alias_targets_instead_of_missing_disabled_control() -> None:
    canonical = BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions[0]
    alias = "command.legacy-control-alias"
    aliased = replace(canonical, aliases=(*canonical.aliases, alias))
    registry = CommandSafetyExtensionRegistry(
        tuple(
            aliased if item.extension_id == canonical.extension_id else item
            for item in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions
        )
    )
    layer = _layer(
        ControlLayerKind.LOCAL_ADMIN,
        _control(ControlTargetKind.EXTENSION, alias, ControlState.DISABLED),
        digest=registry.catalog_digest,
    )

    resolution = resolve_extension_controls(
        (layer,),
        registry=registry,
        extension_ids=(canonical.extension_id,),
        permission_ids=(),
        observations=("classified",),
        surface=ControlSurface.COMMAND_EVALUATION,
    )

    assert resolution.blocked is True
    assert resolution.failures[0].code is ResolverFailureCode.NON_CANONICAL_TARGET
    assert evaluate_effect_decision(EffectDecisionRequest(resolution.factors)).action == "block"


def test_resolver_input_limits_fail_closed_at_boundary() -> None:
    extension_id, _ = _catalog_subjects()
    accepted = resolve_extension_controls(
        (),
        registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        extension_ids=(extension_id,),
        permission_ids=(),
        observations=tuple("observed" for _ in range(2048)),
        surface=ControlSurface.COMMAND_EVALUATION,
    )
    rejected = resolve_extension_controls(
        (),
        registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        extension_ids=(extension_id,),
        permission_ids=(),
        observations=tuple("observed" for _ in range(2049)),
        surface=ControlSurface.COMMAND_EVALUATION,
    )

    assert accepted.blocked is False
    assert rejected.blocked is True
    assert rejected.failures[0].code is ResolverFailureCode.INPUT_LIMIT_EXCEEDED


def test_authority_failure_blocks_command_evaluation_but_not_trusted_proof() -> None:
    extension_id, _ = _catalog_subjects()
    command = resolve_extension_controls(
        (),
        registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        extension_ids=(extension_id,),
        permission_ids=(),
        observations=("classified",),
        surface=ControlSurface.COMMAND_EVALUATION,
        authority_failure=ResolverFailureCode.AUTHORITY_TAMPERED,
    )
    trusted_proof = resolve_extension_controls(
        (),
        registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        extension_ids=(extension_id,),
        permission_ids=(),
        observations=("classified",),
        surface=ControlSurface.TRUSTED_LOCAL_PROOF,
        authority_failure=ResolverFailureCode.AUTHORITY_TAMPERED,
    )

    assert command.blocked is True
    assert command.failures == (ControlResolverFailure(ResolverFailureCode.AUTHORITY_TAMPERED),)
    assert trusted_proof.blocked is False
    assert trusted_proof.failures == ()
