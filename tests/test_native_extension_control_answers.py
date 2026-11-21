"""The Python bridge presents only a bound, well-formed ``ok`` reply and raises on anything else.

There is no Python answer to fall back to: a malformed, unbound, rejected or
missing reply fails the whole question so callers fail closed. The request
the bridge builds is pinned in ``test_native_extension_control.py``.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_extension_control as bridge
from codex_plugin_scanner.guard import native_resident_decision as shared
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    ControlSurface,
)
from tests.native_extension_control_support import (
    COMPOSED,
    EXTENSION,
    PERMISSION,
    UNBOUND_DIGEST,
    bound_reply,
    echo_answers,
    item_answer,
    make_layer,
    make_registry,
    resident_answers,
    resolve_extension_controls,
    resolve_payload,
)

pytestmark = pytest.mark.native_route_unpinned


def test_resolve_extension_controls_answers_one_item(monkeypatch: pytest.MonkeyPatch) -> None:
    resident_answers(
        monkeypatch,
        lambda request: bound_reply(request, resolve_payload([item_answer(blocked=True)])),
    )

    answer = resolve_extension_controls(
        (make_layer(),),
        make_registry(),
        extension_ids=(EXTENSION,),
        permission_ids=(),
        surface=ControlSurface.COMMAND_EVALUATION,
    )

    assert answer.blocked is True
    assert answer.active is None


@pytest.mark.parametrize(
    "payload",
    [
        {"kind": "compose"},
        {"kind": "compose", "composed": []},
        {"kind": "compose", "composed": {**COMPOSED, "extra": 1}},
        {"kind": "compose", "composed": {"global_lockdown": False, "controls": []}},
        {"kind": "compose", "composed": {**COMPOSED, "global_lockdown": 1}},
        {"kind": "compose", "composed": {**COMPOSED, "controls": "none"}},
        {"kind": "compose", "composed": {**COMPOSED, "controls": [{"target_kind": "extension"}]}},
        {
            "kind": "compose",
            "composed": {
                **COMPOSED,
                "controls": [{"target_kind": "extension", "target_id": EXTENSION, "state": "maybe"}],
            },
        },
        {
            "kind": "compose",
            "composed": {
                **COMPOSED,
                "controls": [{"target_kind": "extension", "target_id": "Not A Target", "state": "enabled"}],
            },
        },
        {"kind": "compose", "composed": {**COMPOSED, "failures": [{"code": "made-up", "layer_kind": None}]}},
        {
            "kind": "compose",
            "composed": {**COMPOSED, "failures": [{"code": "duplicate-layer-kind", "layer_kind": "other"}]},
        },
        {"kind": "compose", "composed": {**COMPOSED, "failures": [{"code": "duplicate-layer-kind"}]}},
        {"kind": "compose", "composed": {**COMPOSED, "failures": {}}},
    ],
)
def test_a_malformed_composition_raises(monkeypatch: pytest.MonkeyPatch, payload: dict[str, object]) -> None:
    resident_answers(monkeypatch, lambda request: bound_reply(request, payload))

    with pytest.raises(bridge.NativeExtensionControlError) as caught:
        bridge.compose_control_layers((make_layer(),))
    assert caught.value.code == "native_extension_control_payload_invalid"


@pytest.mark.parametrize(
    "payload",
    [
        resolve_payload(),
        resolve_payload([item_answer()], [item_answer()]),
        resolve_payload([]),
        resolve_payload([item_answer(), item_answer()]),
        {"kind": "resolve", "scenarios": [{"global_lockdown": False}]},
        {"kind": "resolve", "scenarios": [{"global_lockdown": 0, "results": [item_answer()]}]},
        {"kind": "resolve", "scenarios": [{"global_lockdown": False, "results": [item_answer()], "extra": 1}]},
        {"kind": "resolve", "scenarios": "none"},
        {"kind": "resolve", "scenarios": [None]},
        resolve_payload([{**item_answer(), "extra": 1}]),
        resolve_payload([{key: value for key, value in item_answer().items() if key != "failures"}]),
        resolve_payload([item_answer(blocked="yes")]),
        resolve_payload([item_answer(blocked=1)]),
        resolve_payload([item_answer(factor_reason_codes="control.x")]),
        resolve_payload([item_answer(factor_reason_codes=[1])]),
        resolve_payload([item_answer(explicitly_enabled_permission_ids=[None])]),
        resolve_payload([item_answer(failures=[{"code": "made-up", "layer_kind": None}])]),
        resolve_payload([item_answer(active=True)]),
        resolve_payload([item_answer(active="yes")]),
        {"kind": "compose", "composed": COMPOSED},
    ],
)
def test_a_malformed_resolution_raises(monkeypatch: pytest.MonkeyPatch, payload: dict[str, object]) -> None:
    resident_answers(monkeypatch, lambda request: bound_reply(request, payload))
    scenario = bridge.ControlScenario((make_layer(),), (bridge.ControlItem((EXTENSION,)),))

    with pytest.raises(bridge.NativeExtensionControlError):
        bridge.resolve_scenarios(make_registry(), (scenario,))


def test_an_item_that_asked_for_activity_must_be_answered_with_a_verdict(monkeypatch: pytest.MonkeyPatch) -> None:
    resident_answers(monkeypatch, lambda request: bound_reply(request, resolve_payload([item_answer(active=None)])))
    scenario = bridge.ControlScenario((make_layer(),), (bridge.ControlItem(active_extension_id=EXTENSION),))

    with pytest.raises(bridge.NativeExtensionControlError) as caught:
        bridge.resolve_scenarios(make_registry(), (scenario,), trust_classes=True)
    assert caught.value.code == "native_extension_control_payload_invalid"


@pytest.mark.parametrize("active", [True, False])
def test_the_activity_verdict_is_presented_exactly(monkeypatch: pytest.MonkeyPatch, active: bool) -> None:
    resident_answers(monkeypatch, lambda request: bound_reply(request, resolve_payload([item_answer(active=active)])))
    scenario = bridge.ControlScenario((make_layer(),), (bridge.ControlItem(active_extension_id=EXTENSION),))

    answer = bridge.resolve_scenarios(make_registry(), (scenario,), trust_classes=True)[0].items[0]

    assert answer.active is active


@pytest.mark.parametrize(
    "mutate",
    [
        lambda request: None,
        lambda request: [],
        lambda request: bound_reply(request, resolve_payload([item_answer()]), request_id="someone-else"),
        lambda request: bound_reply(request, resolve_payload([item_answer()]), request_sha256=UNBOUND_DIGEST),
        lambda request: bound_reply(
            request, resolve_payload([item_answer()]), schema="guard-extension-control-result.v0"
        ),
        lambda request: bound_reply(request, resolve_payload([item_answer()]), status="denied"),
        lambda request: bound_reply(request, resolve_payload([item_answer()]), code="other"),
        lambda request: bound_reply(request, resolve_payload([item_answer()]), payload=None),
        lambda request: bound_reply(request, {**resolve_payload([item_answer()]), "kind": "compose"}),
        lambda request: bound_reply(request, resolve_payload([item_answer()]), status="error", code="not-a-code"),
    ],
)
def test_an_unbound_reply_raises(
    monkeypatch: pytest.MonkeyPatch, mutate: Callable[[dict[str, object]], object]
) -> None:
    resident_answers(monkeypatch, mutate)
    scenario = bridge.ControlScenario((make_layer(),), (bridge.ControlItem((EXTENSION,)),))

    with pytest.raises(bridge.NativeExtensionControlError) as caught:
        bridge.resolve_scenarios(make_registry(), (scenario,))
    assert caught.value.code == "native_extension_control_unavailable"


def test_a_rejected_request_raises_with_the_runtimes_code(monkeypatch: pytest.MonkeyPatch) -> None:
    resident_answers(
        monkeypatch,
        lambda request: bound_reply(
            request, {}, status="error", code="native_extension_control_registry_invalid", payload=None
        ),
    )
    scenario = bridge.ControlScenario((make_layer(),), (bridge.ControlItem((EXTENSION,)),))

    with pytest.raises(bridge.NativeExtensionControlError) as caught:
        bridge.resolve_scenarios(make_registry(), (scenario,))
    assert caught.value.code == "native_extension_control_registry_invalid"
    with pytest.raises(bridge.NativeExtensionControlError) as composed:
        bridge.compose_control_layers((make_layer(),))
    assert composed.value.code == "native_extension_control_registry_invalid"


def test_no_runtime_is_no_answer_and_never_a_default_verdict(monkeypatch: pytest.MonkeyPatch) -> None:
    resident_answers(monkeypatch, lambda request: pytest.fail("resident must not be asked"))
    monkeypatch.setattr(shared, "ensure_resident_prerequisite", lambda _home: False)
    scenario = bridge.ControlScenario((make_layer(),), (bridge.ControlItem((EXTENSION,)),))

    with pytest.raises(bridge.NativeExtensionControlError) as resolving:
        bridge.resolve_scenarios(make_registry(), (scenario,))
    with pytest.raises(bridge.NativeExtensionControlError) as composing:
        bridge.compose_control_layers((make_layer(),))
    assert resolving.value.code == composing.value.code == "native_extension_control_unavailable"


def test_a_failed_later_request_fails_the_whole_question(monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[int] = []

    def reply(request: dict[str, object]) -> object:
        asked.append(len(asked))
        return echo_answers(request) if len(asked) == 1 else None

    resident_answers(monkeypatch, reply)
    scenario = bridge.ControlScenario(
        (make_layer(),), tuple(bridge.ControlItem((EXTENSION,)) for _ in range(bridge._MAX_ITEMS_PER_REQUEST + 1))
    )

    with pytest.raises(bridge.NativeExtensionControlError):
        bridge.resolve_scenarios(make_registry(), (scenario,))
    assert len(asked) == 2


def _projection_registry() -> Any:
    registry = make_registry()
    permission = registry.permissions[0]
    registry.permissions = (type(permission)(**vars(permission), configurable=False, fixed_reason="Always reviewed."),)
    return registry


def _row(**overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "effective_state": "allowed",
        "local_state": "inherited",
        "managed_state": "inherited",
        "reason_codes": [],
    }
    row.update(overrides)
    return row


_DISABLED = _row(effective_state="blocked", local_state="disabled", reason_codes=["control.disabled-permission"])


def _rows_payload(rows: list[dict[str, object]]) -> dict[str, object]:
    return {"kind": "project", "rows": rows}


def test_a_projection_is_answered_by_state_and_joined_with_the_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[dict[str, object]] = []

    def answer(request: dict[str, object]) -> dict[str, object]:
        asked.append(request)
        return bound_reply(request, _rows_payload([_row(), _row(reason_codes=["b", "a"]), _DISABLED]))

    resident_answers(monkeypatch, answer)

    extensions, permissions = bridge.project_extension_controls(_projection_registry(), (make_layer(),), None)

    query = asked[0]["query"]
    assert isinstance(query, dict)
    assert query["kind"] == "project"
    assert query["start"] == 0
    assert query["authority_failure"] is None
    assert "permission_facts" not in query
    assert extensions == [
        {"extension_id": EXTENSION, **_row(), "required": False},
        {"extension_id": "command.shell", **_row(reason_codes=["b", "a"]), "required": True},
    ]
    # Ids, the owner and the catalog facts are the registry's own.
    assert permissions == [
        {
            "permission_id": PERMISSION,
            "extension_id": EXTENSION,
            **_DISABLED,
            "configurable": False,
            "fixed_reason": "Always reviewed.",
        }
    ]


def test_a_large_projection_is_asked_a_page_at_a_time(monkeypatch: pytest.MonkeyPatch) -> None:
    registry = _projection_registry()
    permission = registry.permissions[0]
    registry.permissions = tuple(
        type(permission)(**{**vars(permission), "permission_id": f"{PERMISSION}-{index}"}) for index in range(2047)
    )
    starts: list[object] = []

    def answer(request: dict[str, object]) -> dict[str, object]:
        query = request["query"]
        assert isinstance(query, dict)
        start = query["start"]
        assert isinstance(start, int)
        starts.append(start)
        return bound_reply(request, _rows_payload([_DISABLED] * min(2048, 2049 - start)))

    resident_answers(monkeypatch, answer)

    extensions, permissions = bridge.project_extension_controls(registry, (make_layer(),), None)

    assert starts == [0, 2048]
    assert len(extensions) == 2
    assert [entry["permission_id"] for entry in permissions] == [f"{PERMISSION}-{index}" for index in range(2047)]


@pytest.mark.parametrize(
    "payload",
    [
        _rows_payload([_row(), _row()]),
        _rows_payload([_row(), _row(), _row(), _row()]),
        _rows_payload([_row(), _row(), _row(effective_state="maybe")]),
        _rows_payload([_row(), _row(), _row(local_state="on")]),
        _rows_payload([_row(), _row(), _row(reason_codes=[1])]),
        _rows_payload([_row(), _row(), {**_row(), "permission_id": PERMISSION}]),
        {"kind": "project"},
    ],
)
def test_a_malformed_projection_raises(monkeypatch: pytest.MonkeyPatch, payload: dict[str, object]) -> None:
    resident_answers(monkeypatch, lambda request: bound_reply(request, payload))

    with pytest.raises(bridge.NativeExtensionControlError):
        bridge.project_extension_controls(_projection_registry(), (make_layer(),), None)
