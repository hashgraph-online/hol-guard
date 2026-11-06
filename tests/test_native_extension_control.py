"""The Python bridge builds the extension-control request and splits a large question.

The composition and resolution rules are pinned by the Rust op's own tests and
by ``test_guard_extension_control_resolver.py`` against the real runtime. These
tests pin the request the bridge builds, how it splits a question across
requests, and how it presents a bound ``ok`` reply. Decoding and refusal of a
bad reply is pinned in ``test_native_extension_control_answers.py``.
"""

from __future__ import annotations

from typing import Any, cast

import pytest

from codex_plugin_scanner.guard import native_extension_control as bridge
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    ComposedExtensionControls,
    ControlLayerKind,
    ControlResolverFailure,
    ControlSurface,
    ControlTargetKind,
    ResolverFailureCode,
)
from codex_plugin_scanner.guard.runtime.extension_trust import trust_class_for
from tests.native_extension_control_support import (
    DIGEST,
    EXTENSION,
    PERMISSION,
    bound_reply,
    echo_answers,
    item_answer,
    make_disabled,
    make_layer,
    make_registry,
    request_query,
    resident_answers,
    resolve_payload,
)

pytestmark = pytest.mark.native_route_unpinned


def test_compose_sends_every_layer_field_and_presents_the_composition(monkeypatch: pytest.MonkeyPatch) -> None:
    body = {
        "kind": "compose",
        "composed": {
            "global_lockdown": True,
            "controls": [{"target_kind": "extension", "target_id": EXTENSION, "state": "disabled"}],
            "failures": [{"code": "duplicate-layer-kind", "layer_kind": "local-admin"}],
        },
    }
    requests = resident_answers(monkeypatch, lambda request: bound_reply(request, body))
    layers = (
        make_layer(ControlLayerKind.LOCAL_ADMIN, make_disabled(ControlTargetKind.EXTENSION, EXTENSION)),
        make_layer(ControlLayerKind.SIGNED_CLOUD, lockdown=True),
    )

    composed = bridge.compose_control_layers(layers)

    assert composed == ComposedExtensionControls(
        True,
        (make_disabled(ControlTargetKind.EXTENSION, EXTENSION),),
        (ControlResolverFailure(ResolverFailureCode.DUPLICATE_LAYER_KIND, ControlLayerKind.LOCAL_ADMIN),),
    )
    assert len(requests) == 1
    assert requests[0]["schema"] == "guard-extension-control-request.v1"
    assert requests[0]["query"] == {
        "kind": "compose",
        "layers": [
            {
                "schema_version": "1.0.0",
                "kind": "local-admin",
                "catalog_digest": DIGEST,
                "global_lockdown": False,
                "controls": [{"target_kind": "extension", "target_id": EXTENSION, "state": "disabled"}],
            },
            {
                "schema_version": "1.0.0",
                "kind": "signed-cloud",
                "catalog_digest": DIGEST,
                "global_lockdown": True,
                "controls": [],
            },
        ],
    }


def test_compose_of_no_layers_still_asks_the_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    body = {"kind": "compose", "composed": {"global_lockdown": False, "controls": [], "failures": []}}
    requests = resident_answers(monkeypatch, lambda request: bound_reply(request, body))

    assert bridge.compose_control_layers(()) == ComposedExtensionControls(False, (), ())
    assert requests[0]["query"] == {"kind": "compose", "layers": []}


def test_resolve_sends_the_registry_projection_and_every_item_field(monkeypatch: pytest.MonkeyPatch) -> None:
    requests = resident_answers(monkeypatch, echo_answers)
    scenario = bridge.ControlScenario(
        (make_layer(),),
        (
            bridge.ControlItem((EXTENSION,), (PERMISSION,)),
            bridge.ControlItem(active_extension_id=EXTENSION),
        ),
        ControlSurface.TRUSTED_LOCAL_RECOVERY,
        ResolverFailureCode.AUTHORITY_TAMPERED,
    )

    [answered] = bridge.resolve_scenarios(make_registry(), (scenario,))
    assert [item.active for item in answered.items] == [None, True]

    query = request_query(requests[0])
    assert query["kind"] == "resolve"
    assert query["registry"] == {
        "catalog_digest": DIGEST,
        "extensions": [
            {
                "extension_id": EXTENSION,
                "aliases": ["command.legacy-git"],
                "dependencies": ["command.shell"],
                "required": False,
                "trust_class": None,
            },
            {"extension_id": "command.shell", "aliases": [], "dependencies": [], "required": True, "trust_class": None},
        ],
        "permissions": [
            {
                "permission_id": PERMISSION,
                "extension_id": EXTENSION,
                "dependencies": ["command.shell.permission.run"],
                "implied_permissions": ["command.git.permission.fetch"],
            }
        ],
    }
    [wire] = query["scenarios"]
    assert wire["surface"] == "trusted-local-recovery"
    assert wire["authority_failure"] == "authority-tampered"
    assert wire["items"] == [
        {"extension_ids": [EXTENSION], "permission_ids": [PERMISSION], "active_extension_id": None},
        {"extension_ids": [], "permission_ids": [], "active_extension_id": EXTENSION},
    ]


def test_resolve_sends_the_curated_trust_class_only_when_asked(monkeypatch: pytest.MonkeyPatch) -> None:
    requests = resident_answers(
        monkeypatch, lambda request: bound_reply(request, resolve_payload([item_answer(active=True)]))
    )
    scenario = bridge.ControlScenario((make_layer(),), (bridge.ControlItem(active_extension_id=EXTENSION),))

    answer = bridge.resolve_scenarios(make_registry(), (scenario,), trust_classes=True)[0].items[0]

    assert answer.active is True
    query = request_query(requests[0])
    classes = [extension["trust_class"] for extension in query["registry"]["extensions"]]
    assert classes == [trust_class_for(EXTENSION), trust_class_for("command.shell")]
    [wire] = query["scenarios"]
    assert wire["authority_failure"] is None
    assert wire["surface"] == "command-evaluation"


def test_resolve_presents_blocking_reasons_failures_and_enabled_permissions(monkeypatch: pytest.MonkeyPatch) -> None:
    answer = item_answer(
        blocked=True,
        factor_reason_codes=["control.disabled-extension"],
        failures=[
            {"code": "catalog-digest-mismatch", "layer_kind": "signed-cloud"},
            {"code": "unknown-extension-target", "layer_kind": None},
        ],
        explicitly_enabled_permission_ids=[PERMISSION],
    )
    resident_answers(monkeypatch, lambda request: bound_reply(request, resolve_payload([answer], lockdown=True)))

    result = bridge.resolve_scenarios(
        make_registry(), (bridge.ControlScenario((make_layer(),), (bridge.ControlItem((EXTENSION,)),)),)
    )

    assert result == (
        bridge.ScenarioAnswer(
            True,
            (
                bridge.ControlAnswer(
                    True,
                    ("control.disabled-extension",),
                    (
                        ControlResolverFailure(
                            ResolverFailureCode.CATALOG_DIGEST_MISMATCH, ControlLayerKind.SIGNED_CLOUD
                        ),
                        ControlResolverFailure(ResolverFailureCode.UNKNOWN_EXTENSION_TARGET, None),
                    ),
                    (PERMISSION,),
                    None,
                ),
            ),
        ),
    )


def test_resolve_keeps_only_the_layers_the_resolver_admits_plus_one(monkeypatch: pytest.MonkeyPatch) -> None:
    requests = resident_answers(monkeypatch, echo_answers)
    layers = tuple(make_layer(ControlLayerKind.LOCAL_ADMIN) for _ in range(bridge.MAX_CONTROL_LAYERS + 4))

    bridge.resolve_scenarios(make_registry(), (bridge.ControlScenario(layers, (bridge.ControlItem((EXTENSION,)),)),))

    query = request_query(requests[0])
    assert len(query["scenarios"][0]["layers"]) == bridge.MAX_CONTROL_LAYERS + 1


def test_resolve_of_no_scenarios_asks_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    requests = resident_answers(monkeypatch, lambda request: pytest.fail("resident must not be asked"))

    assert bridge.resolve_scenarios(make_registry(), ()) == ()
    assert requests == []


def test_a_scenario_without_items_is_still_asked_and_answered(monkeypatch: pytest.MonkeyPatch) -> None:
    requests = resident_answers(monkeypatch, echo_answers)

    result = bridge.resolve_scenarios(make_registry(), (bridge.ControlScenario((make_layer(),), ()),))

    assert result == (bridge.ScenarioAnswer(False, ()),)
    assert len(requests) == 1


def test_items_beyond_one_requests_bound_are_split_and_reassembled_in_order(monkeypatch: pytest.MonkeyPatch) -> None:
    requests = resident_answers(monkeypatch, echo_answers)
    count = bridge._MAX_ITEMS_PER_REQUEST * 2 + 1
    scenario = bridge.ControlScenario(
        (make_layer(),), tuple(bridge.ControlItem((f"command.item{index}",)) for index in range(count))
    )

    [answered] = bridge.resolve_scenarios(make_registry(), (scenario,))

    assert [len(request_query(request)["scenarios"][0]["items"]) for request in requests] == [
        bridge._MAX_ITEMS_PER_REQUEST,
        bridge._MAX_ITEMS_PER_REQUEST,
        1,
    ]
    assert [item.reason_codes for item in answered.items] == [(f"command.item{index}",) for index in range(count)]


def test_scenarios_beyond_one_requests_bound_are_split_and_answered_in_order(monkeypatch: pytest.MonkeyPatch) -> None:
    requests = resident_answers(monkeypatch, echo_answers)
    count = bridge._MAX_SCENARIOS_PER_REQUEST + 3
    scenarios = tuple(
        bridge.ControlScenario((make_layer(),), (bridge.ControlItem((f"command.scenario{index}",)),))
        for index in range(count)
    )

    answered = bridge.resolve_scenarios(make_registry(), scenarios)

    assert [len(request_query(request)["scenarios"]) for request in requests] == [
        bridge._MAX_SCENARIOS_PER_REQUEST,
        3,
    ]
    assert [scenario.items[0].reason_codes for scenario in answered] == [
        (f"command.scenario{index}",) for index in range(count)
    ]


def _padded_scenario(index: int, size: int) -> bridge.ControlScenario:
    """One scenario whose single item carries ``size`` bytes of extension id."""

    return bridge.ControlScenario((make_layer(),), (bridge.ControlItem((f"command.s{index}." + "x" * size,)),))


def _blank_answers(request: dict[str, object]) -> dict[str, object]:
    return bound_reply(
        request,
        resolve_payload(
            *[[item_answer() for _ in scenario["items"]] for scenario in request_query(request)["scenarios"]]
        ),
    )


def test_scenarios_beyond_one_requests_byte_bound_are_split_and_answered_in_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests = resident_answers(monkeypatch, _blank_answers)
    scenarios = tuple(_padded_scenario(index, 1_500_000) for index in range(3))

    answered = bridge.resolve_scenarios(make_registry(), scenarios)

    assert len(answered) == 3
    assert [len(request_query(request)["scenarios"]) for request in requests] == [2, 1]
    assert all(bridge._wire_bytes(request_query(request)) <= bridge._MAX_BATCH_BYTES for request in requests)


def test_a_piece_no_request_can_carry_refuses_the_question_before_asking(monkeypatch: pytest.MonkeyPatch) -> None:
    requests = resident_answers(monkeypatch, _blank_answers)
    scenarios = (_padded_scenario(0, 1_000), _padded_scenario(1, bridge._MAX_BATCH_BYTES))

    with pytest.raises(bridge.NativeExtensionControlError) as caught:
        bridge.resolve_scenarios(make_registry(), scenarios)

    assert caught.value.code == "native_extension_control_too_large"
    assert requests == []


def test_every_piece_of_one_scenario_must_agree_on_the_lockdown(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[bool] = []

    def reply(request: dict[str, object]) -> dict[str, object]:
        reply = echo_answers(request)
        seen.append(len(seen) == 1)
        for scenario in cast(dict[str, Any], reply["payload"])["scenarios"]:
            scenario["global_lockdown"] = seen[-1]
        return reply

    resident_answers(monkeypatch, reply)
    scenario = bridge.ControlScenario(
        (make_layer(),), tuple(bridge.ControlItem((EXTENSION,)) for _ in range(bridge._MAX_ITEMS_PER_REQUEST + 1))
    )

    with pytest.raises(bridge.NativeExtensionControlError) as caught:
        bridge.resolve_scenarios(make_registry(), (scenario,))
    assert caught.value.code == "native_extension_control_payload_invalid"
