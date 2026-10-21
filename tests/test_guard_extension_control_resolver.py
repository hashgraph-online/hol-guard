"""Extension-control composition and resolution, asked of the real native runtime.

Python holds no resolver: these tests drive the bridge against the compiled
resident, the same resolver command evaluation runs. The Rust op's own tests
(``extension_control_op_tests.rs``) pin every rule on a synthetic registry;
the observation limit and observation preservation are pinned beside the
resolver in ``guard-command``. ``test_native_extension_control.py`` pins the
bridge's request and strict reply decoding without a runtime.
"""

from __future__ import annotations

import itertools
from collections.abc import Sequence
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard import native_extension_control as bridge
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    CommandSafetyExtensionRegistry,
)
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


@pytest.fixture
def home(native_hook_force: Path, _native_context_home: Path) -> Path:
    """A guard home whose resident answers the control questions."""

    return _native_context_home


def _resolve(
    home: Path,
    layers: Sequence[ExtensionControlLayer],
    registry: CommandSafetyExtensionRegistry,
    *,
    extension_ids: tuple[str, ...] = (),
    permission_ids: tuple[str, ...] = (),
    surface: ControlSurface = ControlSurface.COMMAND_EVALUATION,
    authority_failure: ResolverFailureCode | None = None,
) -> bridge.ControlAnswer:
    return bridge.resolve_extension_controls(
        layers,
        registry,
        extension_ids=extension_ids,
        permission_ids=permission_ids,
        surface=surface,
        authority_failure=authority_failure,
        guard_home=home,
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


def test_composition_is_permutation_independent_and_disable_dominates_enable(home: Path) -> None:
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

    compositions = {
        bridge.compose_control_layers(order, guard_home=home) for order in itertools.permutations((local, cloud))
    }
    assert len(compositions) == 1
    composed = compositions.pop()
    assert composed.global_lockdown is False
    assert composed.failures == ()
    assert composed.state_for(ControlTargetKind.EXTENSION, extension_id) is ControlState.DISABLED
    assert composed.state_for(ControlTargetKind.PERMISSION, permission_id) is ControlState.DISABLED


def test_composition_reports_duplicates_instead_of_choosing_one(home: Path) -> None:
    extension_id, _ = _catalog_subjects()
    control = _control(ControlTargetKind.EXTENSION, extension_id, ControlState.DISABLED)

    duplicate_kind = bridge.compose_control_layers(
        (_layer(ControlLayerKind.LOCAL_ADMIN), _layer(ControlLayerKind.LOCAL_ADMIN)), guard_home=home
    )
    duplicate_target = bridge.compose_control_layers(
        (_layer(ControlLayerKind.LOCAL_ADMIN, control, control),), guard_home=home
    )

    assert ResolverFailureCode.DUPLICATE_LAYER_KIND in {failure.code for failure in duplicate_kind.failures}
    assert ResolverFailureCode.DUPLICATE_TARGET_IN_LAYER in {failure.code for failure in duplicate_target.failures}


def test_adding_restrictions_never_reduces_the_resolved_action(home: Path) -> None:
    extension_id, permission_id = _catalog_subjects()
    targets = (
        (ControlTargetKind.EXTENSION, extension_id),
        (ControlTargetKind.PERMISSION, permission_id),
    )
    subsets = [
        frozenset(indexes)
        for count in range(len(targets) + 1)
        for indexes in itertools.combinations(range(len(targets)), count)
    ]
    scenarios = tuple(
        bridge.ControlScenario(
            (
                _layer(
                    ControlLayerKind.LOCAL_ADMIN,
                    *(
                        _control(kind, target_id, ControlState.DISABLED)
                        for index, (kind, target_id) in enumerate(targets)
                        if index in disabled
                    ),
                ),
            ),
            (bridge.ControlItem((extension_id,), (permission_id,)),),
        )
        for disabled in subsets
    )

    answers = dict(
        zip(
            subsets,
            (
                scenario.items[0]
                for scenario in bridge.resolve_scenarios(
                    BUILT_IN_COMMAND_EXTENSION_REGISTRY, scenarios, guard_home=home
                )
            ),
            strict=True,
        )
    )

    assert answers[frozenset()].blocked is False
    assert answers[frozenset()].reason_codes == ()
    for disabled, answer in answers.items():
        if disabled:
            assert answer.blocked is True
            assert answer.reason_codes


def test_global_lockdown_blocks_commands_and_allows_only_typed_local_recovery(home: Path) -> None:
    extension_id, permission_id = _catalog_subjects()
    layer = _layer(ControlLayerKind.LOCAL_ADMIN, lockdown=True)

    command = _resolve(
        home,
        (layer,),
        BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        extension_ids=(extension_id,),
        permission_ids=(permission_id,),
    )
    recovery = _resolve(
        home,
        (layer,),
        BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        surface=ControlSurface.TRUSTED_LOCAL_RECOVERY,
    )

    assert command.blocked is True
    assert command.reason_codes == ("control.global-lockdown",)
    assert recovery.blocked is False
    assert recovery.reason_codes == ()


def test_disabled_extension_permission_dependency_and_implied_permission_each_block(home: Path) -> None:
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
            "control.disabled-extension",
        ),
        (
            (),
            (owner_permission.permission_id,),
            _control(ControlTargetKind.PERMISSION, owner_permission.permission_id, ControlState.DISABLED),
            "control.disabled-permission",
        ),
        (
            (owner.extension_id,),
            (),
            _control(ControlTargetKind.EXTENSION, dependency.extension_id, ControlState.DISABLED),
            "control.disabled-extension",
        ),
        (
            (),
            (owner_permission.permission_id,),
            _control(
                ControlTargetKind.PERMISSION,
                dependency_permission.permission_id,
                ControlState.DISABLED,
            ),
            "control.disabled-permission",
        ),
    )

    for extension_ids, permission_ids, control, expected_reason in scenarios:
        layer = ExtensionControlLayer(
            schema_version=CONTROL_SCHEMA_VERSION,
            kind=ControlLayerKind.LOCAL_ADMIN,
            catalog_digest=registry.catalog_digest,
            global_lockdown=False,
            controls=(control,),
        )
        answer = _resolve(home, (layer,), registry, extension_ids=extension_ids, permission_ids=permission_ids)
        assert answer.blocked is True
        assert answer.reason_codes[0] == expected_reason


def test_resolver_failures_are_typed_privacy_safe_and_fail_closed(home: Path) -> None:
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
        answer = _resolve(home, layers, BUILT_IN_COMMAND_EXTENSION_REGISTRY, extension_ids=extension_ids)
        assert answer.blocked is True
        assert answer.failures[0].code is expected_code
        assert answer.reason_codes
        assert "private-unknown-input" not in repr(answer)


def test_duplicate_layers_and_targets_fail_closed(home: Path) -> None:
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
        answer = _resolve(home, layers, BUILT_IN_COMMAND_EXTENSION_REGISTRY, extension_ids=(extension_id,))
        assert answer.blocked is True
        assert answer.failures[0].code is expected


def test_resolver_rejects_alias_targets_instead_of_missing_disabled_control(home: Path) -> None:
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

    answer = _resolve(home, (layer,), registry, extension_ids=(canonical.extension_id,))

    assert answer.blocked is True
    assert answer.failures[0].code is ResolverFailureCode.NON_CANONICAL_TARGET
    assert answer.reason_codes


def test_resolver_input_limits_fail_closed_at_boundary(home: Path) -> None:
    extension_id, _ = _catalog_subjects()
    accepted = _resolve(
        home,
        (),
        BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        extension_ids=tuple(extension_id for _ in range(1024)),
    )
    rejected = _resolve(
        home,
        (),
        BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        extension_ids=tuple(extension_id for _ in range(1025)),
    )

    assert accepted.blocked is False
    assert rejected.blocked is True
    assert rejected.failures[0].code is ResolverFailureCode.INPUT_LIMIT_EXCEEDED


def test_authority_failure_blocks_command_evaluation_but_not_trusted_proof(home: Path) -> None:
    extension_id, _ = _catalog_subjects()
    command = _resolve(
        home,
        (),
        BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        extension_ids=(extension_id,),
        authority_failure=ResolverFailureCode.AUTHORITY_TAMPERED,
    )
    trusted_proof = _resolve(
        home,
        (),
        BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        extension_ids=(extension_id,),
        surface=ControlSurface.TRUSTED_LOCAL_PROOF,
        authority_failure=ResolverFailureCode.AUTHORITY_TAMPERED,
    )

    assert command.blocked is True
    assert command.failures == (ControlResolverFailure(ResolverFailureCode.AUTHORITY_TAMPERED),)
    assert trusted_proof.blocked is False
    assert trusted_proof.failures == ()
