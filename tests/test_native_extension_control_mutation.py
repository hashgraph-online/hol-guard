"""The bridge asks the resident whether a local mutation may proceed and presents only a well-formed verdict.

The decisions (bounds, canonical targets, catalog binding, immutable controls)
are pinned by the resident's own tests; this file pins the request the bridge
builds and that it accepts nothing but a bound, strictly shaped verdict.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_extension_control as bridge
from codex_plugin_scanner.guard.daemon import extension_control_api
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    ControlLayerKind,
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
)
from tests.native_extension_control_support import (
    DIGEST,
    EXTENSION,
    PERMISSION,
    bound_reply,
    make_disabled,
    make_layer,
    request_query,
    resident_answers,
)

pytestmark = pytest.mark.native_route_unpinned

ALIAS = "command.legacy-git"
OTHER_DIGEST = "b" * 64
OVERLAY_EXTENSION = "command.overlay"
OVERLAY_PERMISSION = "command.overlay.permission.run"


def _registry() -> SimpleNamespace:
    return SimpleNamespace(
        catalog_digest=DIGEST,
        extensions=(
            SimpleNamespace(extension_id=EXTENSION, aliases=(ALIAS,), required=False),
            SimpleNamespace(extension_id="command.shell", aliases=(), required=True),
        ),
        permissions=(
            SimpleNamespace(permission_id=PERMISSION, configurable=True),
            SimpleNamespace(permission_id="command.shell.permission.run", configurable=False),
        ),
    )


def _overlay() -> tuple[SimpleNamespace, ...]:
    return (
        SimpleNamespace(
            extension_id=OVERLAY_EXTENSION,
            required=True,
            permissions=(SimpleNamespace(permission_id=OVERLAY_PERMISSION, configurable=False),),
        ),
    )


def _wire(layer: Any) -> dict[str, object]:
    return bridge._layer_wire(layer)


def _verdict(refusal: str | None = None, layers: tuple[Any, ...] = ()) -> dict[str, object]:
    return {"kind": "mutation_validate", "refusal": refusal, "layers": [_wire(layer) for layer in layers]}


def _refusal(kind: str, refusal: str | None = None) -> dict[str, object]:
    return {"kind": kind, "refusal": refusal}


def _answer(payload: dict[str, object]) -> Any:
    return lambda request: bound_reply(request, payload)


def _extension_layer(target_id: str) -> Any:
    return make_layer(ControlLayerKind.LOCAL_ADMIN, make_disabled(ControlTargetKind.EXTENSION, target_id))


def test_validate_sends_the_catalog_the_overlay_and_every_layer(monkeypatch: pytest.MonkeyPatch) -> None:
    draft = _extension_layer(ALIAS)
    canonical = _extension_layer(EXTENSION)
    current = make_layer(ControlLayerKind.SIGNED_CLOUD)
    requests = resident_answers(monkeypatch, _answer(_verdict(None, (canonical,))))

    verdict = bridge.validate_mutation(
        _registry(),
        _overlay(),
        catalog_digest=DIGEST,
        requested_catalog_digest=OTHER_DIGEST,
        current_layers=(current,),
        layers=(draft,),
    )

    assert verdict == bridge.MutationVerdict(None, (canonical,))
    assert request_query(requests[0]) == {
        "kind": "mutation_validate",
        "registry": {
            "extensions": [
                {"extension_id": EXTENSION, "aliases": [ALIAS], "required": False},
                {"extension_id": "command.shell", "aliases": [], "required": True},
            ],
            "permissions": [
                {"permission_id": PERMISSION, "configurable": True},
                {"permission_id": "command.shell.permission.run", "configurable": False},
            ],
            "overlay": [
                {
                    "extension_id": OVERLAY_EXTENSION,
                    "required": True,
                    "permissions": [{"permission_id": OVERLAY_PERMISSION, "configurable": False}],
                }
            ],
        },
        "catalog_digest": DIGEST,
        "requested_catalog_digest": OTHER_DIGEST,
        "current_layers": [_wire(current)],
        "layers": [_wire(draft)],
    }


def test_validate_presents_a_refusal_without_layers(monkeypatch: pytest.MonkeyPatch) -> None:
    resident_answers(monkeypatch, _answer(_verdict("catalog_conflict")))

    verdict = bridge.validate_mutation(
        _registry(),
        (),
        catalog_digest=DIGEST,
        requested_catalog_digest=OTHER_DIGEST,
        current_layers=(),
        layers=(make_layer(),),
    )

    assert verdict == bridge.MutationVerdict("catalog_conflict", ())


def test_bounds_sends_the_layers_alone_and_presents_the_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    layers = (make_layer(), make_layer(ControlLayerKind.SIGNED_CLOUD))
    requests = resident_answers(monkeypatch, _answer(_refusal("mutation_bounds", "layer_limit_exceeded")))

    assert bridge.mutation_bounds(layers) == "layer_limit_exceeded"
    assert request_query(requests[0]) == {"kind": "mutation_bounds", "layers": [_wire(layer) for layer in layers]}

    resident_answers(monkeypatch, _answer(_refusal("mutation_bounds")))
    assert bridge.mutation_bounds(layers) is None


def test_mutability_sends_the_catalog_without_an_overlay(monkeypatch: pytest.MonkeyPatch) -> None:
    current = make_layer(ControlLayerKind.LOCAL_ADMIN)
    proposed = make_layer(ControlLayerKind.LOCAL_ADMIN, make_disabled(ControlTargetKind.PERMISSION, PERMISSION))
    requests = resident_answers(monkeypatch, _answer(_refusal("mutability_validate", "immutable_permission")))

    assert bridge.mutability_validate(_registry(), (current,), (proposed,)) == "immutable_permission"

    query = request_query(requests[0])
    assert query["kind"] == "mutability_validate"
    assert query["registry"]["overlay"] == []
    assert query["current_layers"] == [_wire(current)]
    assert query["layers"] == [_wire(proposed)]


def test_every_refusal_the_api_maps_is_one_the_bridge_accepts() -> None:
    assert frozenset(extension_control_api._MUTATION_REFUSAL_STATUS) == bridge.MUTATION_REFUSAL_CODES


def _validate(monkeypatch: pytest.MonkeyPatch, payload: dict[str, object], *, asked: int = 1) -> bridge.MutationVerdict:
    resident_answers(monkeypatch, _answer(payload))
    return bridge.validate_mutation(
        _registry(),
        (),
        catalog_digest=DIGEST,
        requested_catalog_digest=DIGEST,
        current_layers=(),
        layers=tuple(_extension_layer(EXTENSION) for _ in range(asked)),
    )


_LAYER: dict[str, Any] = _wire(_extension_layer(EXTENSION))


@pytest.mark.parametrize(
    "payload",
    [
        {"kind": "mutation_validate"},
        {"kind": "mutation_validate", "refusal": None},
        {"kind": "mutation_validate", "layers": []},
        {"kind": "mutation_validate", "refusal": None, "layers": [], "extra": 1},
        {"kind": "mutation_validate", "refusal": 7, "layers": []},
        {"kind": "mutation_validate", "refusal": "made_up", "layers": []},
        {"kind": "mutation_validate", "refusal": "", "layers": []},
        {"kind": "mutation_validate", "refusal": None, "layers": {}},
        {"kind": "mutation_validate", "refusal": "unknown_extension", "layers": [_LAYER]},
        {"kind": "mutation_validate", "refusal": None, "layers": []},
        {"kind": "mutation_validate", "refusal": None, "layers": [_LAYER, _LAYER]},
        {"kind": "mutation_validate", "refusal": None, "layers": [{**_LAYER, "extra": 1}]},
        {"kind": "mutation_validate", "refusal": None, "layers": [{**_LAYER, "kind": "other"}]},
        {"kind": "mutation_validate", "refusal": None, "layers": [{**_LAYER, "schema_version": "9.9.9"}]},
        {"kind": "mutation_validate", "refusal": None, "layers": [{**_LAYER, "catalog_digest": "short"}]},
        {"kind": "mutation_validate", "refusal": None, "layers": [{**_LAYER, "global_lockdown": 1}]},
        {
            "kind": "mutation_validate",
            "refusal": None,
            "layers": [{**_LAYER, "controls": [{"target_kind": "extension"}]}],
        },
        {
            "kind": "mutation_validate",
            "refusal": None,
            "layers": [
                {**_LAYER, "controls": [{"target_kind": "extension", "target_id": EXTENSION, "state": "maybe"}]}
            ],
        },
        {
            "kind": "mutation_validate",
            "refusal": None,
            "layers": [
                {**_LAYER, "controls": [{"target_kind": "extension", "target_id": "Not A Target", "state": "disabled"}]}
            ],
        },
        # A layer that is not the one asked about: another lockdown state, another control state,
        # another target kind, or another permission.
        {"kind": "mutation_validate", "refusal": None, "layers": [{**_LAYER, "global_lockdown": True}]},
        {
            "kind": "mutation_validate",
            "refusal": None,
            "layers": [{**_LAYER, "controls": [{**_LAYER["controls"][0], "state": "enabled"}]}],
        },
        {
            "kind": "mutation_validate",
            "refusal": None,
            "layers": [{**_LAYER, "controls": [{**_LAYER["controls"][0], "target_kind": "permission"}]}],
        },
        {"kind": "mutation_validate", "refusal": None, "layers": [{**_LAYER, "controls": []}]},
        {"kind": "mutation_validate", "refusal": None, "layers": [{**_LAYER, "catalog_digest": OTHER_DIGEST}]},
    ],
)
def test_a_malformed_validate_verdict_raises(monkeypatch: pytest.MonkeyPatch, payload: dict[str, object]) -> None:
    with pytest.raises(bridge.NativeExtensionControlError) as caught:
        _validate(monkeypatch, payload)
    assert caught.value.code == "native_extension_control_payload_invalid"


def test_a_validate_verdict_may_only_rename_extension_targets(monkeypatch: pytest.MonkeyPatch) -> None:
    asked = make_layer(ControlLayerKind.LOCAL_ADMIN, make_disabled(ControlTargetKind.PERMISSION, PERMISSION))
    other = make_layer(
        ControlLayerKind.LOCAL_ADMIN,
        ExtensionControl(
            ControlTarget(ControlTargetKind.PERMISSION, "command.git.permission.other"), ControlState.DISABLED
        ),
    )
    resident_answers(monkeypatch, _answer(_verdict(None, (other,))))

    with pytest.raises(bridge.NativeExtensionControlError) as caught:
        bridge.validate_mutation(
            _registry(),
            (),
            catalog_digest=DIGEST,
            requested_catalog_digest=DIGEST,
            current_layers=(),
            layers=(asked,),
        )
    assert caught.value.code == "native_extension_control_payload_invalid"


def _ask_bounds(layers: tuple[Any, ...]) -> str | None:
    return bridge.mutation_bounds(layers)


def _ask_mutability(layers: tuple[Any, ...]) -> str | None:
    return bridge.mutability_validate(_registry(), (), layers)


@pytest.mark.parametrize(("kind", "ask"), [("mutation_bounds", _ask_bounds), ("mutability_validate", _ask_mutability)])
@pytest.mark.parametrize(
    "fields",
    [
        {},
        {"refusal": 7},
        {"refusal": "made_up"},
        {"refusal": ""},
        {"refusal": None, "layers": []},
        {"refusal": None, "extra": 1},
    ],
)
def test_a_malformed_refusal_verdict_raises(
    monkeypatch: pytest.MonkeyPatch, kind: str, ask: Any, fields: dict[str, object]
) -> None:
    resident_answers(monkeypatch, _answer({"kind": kind, **fields}))

    with pytest.raises(bridge.NativeExtensionControlError) as caught:
        ask((make_layer(),))
    assert caught.value.code == "native_extension_control_payload_invalid"


@pytest.mark.parametrize(
    ("answered", "ask"),
    [
        ("mutation_validate", _ask_bounds),
        ("mutability_validate", _ask_bounds),
        ("mutation_bounds", _ask_mutability),
        ("mutation_validate", _ask_mutability),
    ],
)
def test_a_verdict_of_another_query_is_no_verdict(monkeypatch: pytest.MonkeyPatch, answered: str, ask: Any) -> None:
    resident_answers(monkeypatch, _answer({"kind": answered, "refusal": None, "layers": []}))

    with pytest.raises(bridge.NativeExtensionControlError) as caught:
        ask((make_layer(),))
    assert caught.value.code == "native_extension_control_unavailable"


def test_a_validate_verdict_of_another_query_is_no_verdict(monkeypatch: pytest.MonkeyPatch) -> None:
    resident_answers(monkeypatch, _answer(_refusal("mutation_bounds")))

    with pytest.raises(bridge.NativeExtensionControlError) as caught:
        bridge.validate_mutation(
            _registry(),
            (),
            catalog_digest=DIGEST,
            requested_catalog_digest=DIGEST,
            current_layers=(),
            layers=(make_layer(),),
        )
    assert caught.value.code == "native_extension_control_unavailable"


def test_a_mutation_no_request_can_carry_is_refused_before_asking(monkeypatch: pytest.MonkeyPatch) -> None:
    requests = resident_answers(monkeypatch, lambda request: pytest.fail("resident must not be asked"))
    padding = ExtensionControl(
        ControlTarget(ControlTargetKind.EXTENSION, "command." + "a" * 600), ControlState.DISABLED
    )
    layer = make_layer(ControlLayerKind.LOCAL_ADMIN, *([padding] * (bridge._MAX_BATCH_BYTES // 600 + 1)))

    with pytest.raises(bridge.NativeExtensionControlError) as bounds:
        bridge.mutation_bounds((layer,))
    with pytest.raises(bridge.NativeExtensionControlError) as validating:
        bridge.validate_mutation(
            _registry(),
            (),
            catalog_digest=DIGEST,
            requested_catalog_digest=DIGEST,
            current_layers=(),
            layers=(layer,),
        )
    with pytest.raises(bridge.NativeExtensionControlError) as mutability:
        bridge.mutability_validate(_registry(), (), (layer,))

    assert bounds.value.code == validating.value.code == mutability.value.code == "native_extension_control_too_large"
    assert requests == []


def test_no_runtime_is_no_verdict(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import native_resident_decision as shared

    resident_answers(monkeypatch, lambda request: pytest.fail("resident must not be asked"))
    monkeypatch.setattr(shared, "ensure_resident_prerequisite", lambda _home: False)

    with pytest.raises(bridge.NativeExtensionControlError) as caught:
        bridge.mutation_bounds((make_layer(),))
    assert caught.value.code == "native_extension_control_unavailable"
