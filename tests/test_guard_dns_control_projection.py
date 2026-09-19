"""Compiler-only DNS compatibility must preserve authenticated authority identity."""

from __future__ import annotations

import itertools
from collections.abc import Iterator
from dataclasses import FrozenInstanceError

import pytest

from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY as REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlState,
    ControlSurface,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
    ResolverFailureCode,
)
from codex_plugin_scanner.guard.runtime.extension_control_projection import (
    DNS_PROVIDER_EXTENSION_IDS,
    DNS_ZONE_PERMISSION_IDS,
    compile_control_projection,
)
from codex_plugin_scanner.guard.runtime.extension_control_resolver import resolve_extension_controls


def _layer(kind: ControlLayerKind, controls: tuple[ExtensionControl, ...]) -> ExtensionControlLayer:
    return ExtensionControlLayer(CONTROL_SCHEMA_VERSION, kind, REGISTRY.catalog_digest, False, controls)


def _control(kind: ControlTargetKind, target: str, state: ControlState) -> ExtensionControl:
    return ExtensionControl(ControlTarget(kind, target), state)


@pytest.mark.parametrize(
    "kind,aggregate,providers",
    [
        (ControlTargetKind.EXTENSION, "command.dns", DNS_PROVIDER_EXTENSION_IDS),
        (ControlTargetKind.PERMISSION, "command.dns.permission.delete", DNS_ZONE_PERMISSION_IDS),
    ],
)
@pytest.mark.parametrize("layer_kind", tuple(ControlLayerKind))
@pytest.mark.parametrize(
    "legacy_state,provider_state,reverse,index", itertools.product(ControlState, ControlState, (False, True), range(3))
)
def test_projection_collision_preserves_each_provider_and_raw_layer(
    kind: ControlTargetKind,
    aggregate: str,
    providers: tuple[str, ...],
    layer_kind: ControlLayerKind,
    legacy_state: ControlState,
    provider_state: ControlState,
    reverse: bool,
    index: int,
) -> None:
    controls = (_control(kind, aggregate, legacy_state), _control(kind, providers[index], provider_state))
    if reverse:
        controls = tuple(reversed(controls))
    raw = (_layer(layer_kind, controls),)
    projection = compile_control_projection(raw)
    assert raw[0].controls is controls
    assert projection.layers[0] is not raw[0]
    assert projection.layers[0].kind is raw[0].kind
    assert projection.layers[0].catalog_digest == raw[0].catalog_digest
    assert not projection.composed.failures
    for position, target in enumerate(providers):
        expected = legacy_state
        if position == index and ControlState.DISABLED in (legacy_state, provider_state):
            expected = ControlState.DISABLED
        assert projection.composed.state_for(kind, target) is expected
    with pytest.raises(FrozenInstanceError):
        projection.__setattr__("layers", ())


@pytest.mark.parametrize("raw_count", (510, 511, 512, 513))
@pytest.mark.parametrize("provider_collisions", (False, True))
def test_resolver_keeps_existing_post_projection_bound(raw_count: int, provider_collisions: bool) -> None:
    ids = ["command.dns"]
    if provider_collisions:
        ids.extend(DNS_PROVIDER_EXTENSION_IDS)
    ids.extend(f"command.synthetic{index}" for index in range(raw_count - len(ids)))
    raw = (
        _layer(
            ControlLayerKind.LOCAL_ADMIN,
            tuple(_control(ControlTargetKind.EXTENSION, target, ControlState.DISABLED) for target in ids),
        ),
    )
    projected_count = raw_count - 1 if provider_collisions else raw_count + 2
    assert len(compile_control_projection(raw).layers[0].controls) == projected_count
    resolution = resolve_extension_controls(
        raw, REGISTRY, extension_ids=(), permission_ids=(), surface=ControlSurface.COMMAND_EVALUATION
    )
    codes = {failure.code for failure in resolution.failures}
    assert (ResolverFailureCode.INPUT_LIMIT_EXCEEDED in codes) is (projected_count > 512)
    assert resolution.failures  # Synthetic targets remain unknown when within bounds.


def test_projection_preserves_duplicate_layers_and_does_not_consume_beyond_resolver_bound() -> None:
    layer = _layer(ControlLayerKind.LOCAL_ADMIN, ())
    assert any(
        failure.code is ResolverFailureCode.DUPLICATE_LAYER_KIND
        for failure in compile_control_projection((layer, layer)).composed.failures
    )
    consumed: list[int] = []

    def layers() -> Iterator[ExtensionControlLayer]:
        for index in range(10):
            consumed.append(index)
            yield layer

    result = resolve_extension_controls(
        layers(), REGISTRY, extension_ids=(), permission_ids=(), surface=ControlSurface.COMMAND_EVALUATION
    )
    assert consumed == [0, 1, 2]
    assert any(failure.code is ResolverFailureCode.INPUT_LIMIT_EXCEEDED for failure in result.failures)
