"""The bridge asks the resident for what the daemon binds around a prepared Extension control commit.

The values (the request digest, the candidate nonce, the audit projection of the
changed targets) are pinned by the resident's own tests; this file pins the
request the bridge builds, that it sends nothing it does not own the meaning of,
and that it accepts nothing but a bound, strictly shaped answer of the kind it
asked for.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_extension_control as bridge
from codex_plugin_scanner.guard.daemon import extension_control_semantic_preview as preview
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_contract import ControlLayerKind, ControlTargetKind
from tests.native_extension_control_support import (
    DIGEST,
    PERMISSION,
    bound_reply,
    make_disabled,
    make_layer,
    request_query,
    resident_answers,
)

pytestmark = pytest.mark.native_route_unpinned

REQUEST_FIELDS = ("previous_revision", "catalog_digest", "layers", "actor_id", "idempotency_key", "nonce")
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64
DIGEST_E = "e" * 64


def _request() -> dict[str, object]:
    return {
        "previous_revision": 3,
        "catalog_digest": DIGEST,
        "layers": [{"kind": "local-admin", "controls": []}],
        "actor_id": "actor-1",
        "idempotency_key": "key-1",
        "nonce": "nonce-1",
    }


def _answer(payload: dict[str, object]) -> Any:
    return lambda request: bound_reply(request, payload)


def _nonce(**overrides: object) -> str:
    arguments: dict[str, Any] = {
        "nonce": "nonce-1",
        "activation_digest": DIGEST_B,
        "lifecycle_before": DIGEST_C,
        "lifecycle_after": DIGEST_D,
        "security_digest": DIGEST_E,
    }
    arguments.update(overrides)
    return bridge.candidate_nonce(**arguments)


# --- request_digest ---------------------------------------------------------


def test_the_request_digest_asks_for_the_six_fields_that_make_a_request_and_nothing_else(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests = resident_answers(monkeypatch, _answer({"kind": "request_digest", "digest": DIGEST_A}))
    payload = {
        **_request(),
        "proof_id": "proof-1",
        "session_nonce": "session-1",
        "approval_password": "not-sent",
        "approval_totp_code": "123456",
    }

    assert bridge.request_digest(payload) == DIGEST_A

    query = request_query(requests[0])
    assert query == {"kind": "request_digest", **{field: _request()[field] for field in REQUEST_FIELDS}}
    assert "not-sent" not in json.dumps(requests[0])
    assert "proof-1" not in json.dumps(requests[0])


def test_request_wire_snapshot_copies_nested_fields_and_excludes_credentials() -> None:
    layers = [{"controls": [], "global_lockdown": False}]
    payload = {**_request(), "layers": layers, "approval_password": "not-retained"}
    snapshot = bridge.request_json(payload)
    assert "not-retained" not in snapshot
    assert snapshot == bridge.request_json(dict(reversed(list(payload.items()))))
    layers[0]["global_lockdown"] = True
    assert snapshot != bridge.request_json(payload)


def test_a_field_the_request_left_out_is_sent_as_null(monkeypatch: pytest.MonkeyPatch) -> None:
    requests = resident_answers(monkeypatch, _answer({"kind": "request_digest", "digest": DIGEST_A}))

    assert bridge.request_digest({}) == DIGEST_A

    assert request_query(requests[0]) == {"kind": "request_digest", **dict.fromkeys(REQUEST_FIELDS)}


@pytest.mark.parametrize(
    "payload",
    [
        {"kind": "request_digest"},
        {"kind": "request_digest", "digest": 7},
        {"kind": "request_digest", "digest": ""},
        {"kind": "request_digest", "digest": "a" * 63},
        {"kind": "request_digest", "digest": "a" * 65},
        {"kind": "request_digest", "digest": "A" * 64},
        {"kind": "request_digest", "digest": "g" * 64},
        {"kind": "request_digest", "digest": DIGEST_A, "extra": 1},
    ],
)
def test_a_malformed_request_digest_raises(monkeypatch: pytest.MonkeyPatch, payload: dict[str, object]) -> None:
    resident_answers(monkeypatch, _answer(payload))

    with pytest.raises(bridge.NativeExtensionControlError) as caught:
        bridge.request_digest(_request())
    assert caught.value.code == "native_extension_control_payload_invalid"


@pytest.mark.parametrize("answered", ["candidate_nonce", "preview_event_targets", "mutation_bounds", "compose"])
def test_the_answer_of_another_query_is_no_request_digest(monkeypatch: pytest.MonkeyPatch, answered: str) -> None:
    resident_answers(monkeypatch, _answer({"kind": answered, "digest": DIGEST_A}))

    with pytest.raises(bridge.NativeExtensionControlError) as caught:
        bridge.request_digest(_request())
    assert caught.value.code == "native_extension_control_unavailable"


@pytest.mark.parametrize("number", [float("nan"), float("inf"), float("-inf")])
def test_a_request_with_a_non_finite_number_is_never_asked_about(
    monkeypatch: pytest.MonkeyPatch, number: float
) -> None:
    requests = resident_answers(monkeypatch, _answer({"kind": "request_digest", "digest": DIGEST_A}))

    with pytest.raises(bridge.NativeExtensionControlError) as caught:
        bridge.request_digest({**_request(), "previous_revision": number})
    assert caught.value.code == "native_extension_control_invalid_digest_input"
    assert requests == []


def test_a_request_too_big_for_one_ask_is_never_asked_about(monkeypatch: pytest.MonkeyPatch) -> None:
    requests = resident_answers(monkeypatch, _answer({"kind": "request_digest", "digest": DIGEST_A}))
    oversized = {**_request(), "layers": "x" * (bridge._MAX_BATCH_BYTES + 1)}

    with pytest.raises(bridge.NativeExtensionControlError) as caught:
        bridge.request_digest(oversized)
    assert caught.value.code == "native_extension_control_too_large"
    assert requests == []


# --- candidate_nonce --------------------------------------------------------


def test_the_candidate_nonce_asks_with_the_five_bound_inputs_in_order(monkeypatch: pytest.MonkeyPatch) -> None:
    requests = resident_answers(monkeypatch, _answer({"kind": "candidate_nonce", "nonce": DIGEST_A}))

    assert _nonce() == DIGEST_A

    assert request_query(requests[0]) == {
        "kind": "candidate_nonce",
        "nonce": "nonce-1",
        "activation_digest": DIGEST_B,
        "lifecycle_before": DIGEST_C,
        "lifecycle_after": DIGEST_D,
        "security_digest": DIGEST_E,
    }


def test_no_security_record_is_sent_as_null_not_as_an_empty_string(monkeypatch: pytest.MonkeyPatch) -> None:
    requests = resident_answers(monkeypatch, _answer({"kind": "candidate_nonce", "nonce": DIGEST_A}))

    _nonce(security_digest=None)

    assert request_query(requests[0])["security_digest"] is None


@pytest.mark.parametrize(
    "payload",
    [
        {"kind": "candidate_nonce"},
        {"kind": "candidate_nonce", "nonce": None},
        {"kind": "candidate_nonce", "nonce": "nonce-1"},
        {"kind": "candidate_nonce", "nonce": "A" * 64},
        {"kind": "candidate_nonce", "nonce": DIGEST_A, "extra": 1},
        {"kind": "candidate_nonce", "digest": DIGEST_A},
    ],
)
def test_a_malformed_candidate_nonce_raises(monkeypatch: pytest.MonkeyPatch, payload: dict[str, object]) -> None:
    resident_answers(monkeypatch, _answer(payload))

    with pytest.raises(bridge.NativeExtensionControlError) as caught:
        _nonce()
    assert caught.value.code == "native_extension_control_payload_invalid"


@pytest.mark.parametrize("answered", ["request_digest", "preview_event_targets", "mutation_digest"])
def test_the_answer_of_another_query_is_no_candidate_nonce(monkeypatch: pytest.MonkeyPatch, answered: str) -> None:
    resident_answers(monkeypatch, _answer({"kind": answered, "nonce": DIGEST_A, "digest": DIGEST_A}))

    with pytest.raises(bridge.NativeExtensionControlError) as caught:
        _nonce()
    assert caught.value.code == "native_extension_control_unavailable"


# --- preview_event_targets --------------------------------------------------


def _target(**overrides: object) -> dict[str, object]:
    target: dict[str, object] = {
        "kind": "permission",
        "target_ref": DIGEST_A,
        "before_explicit": "inherited",
        "after_explicit": "disabled",
        "before_effective": "allowed",
        "after_effective": "blocked",
        "affected_rule_ids": ["git.push"],
    }
    target.update(overrides)
    return target


def _targets(monkeypatch: pytest.MonkeyPatch, answer: dict[str, object]) -> list[dict[str, object]]:
    resident_answers(monkeypatch, _answer(answer))
    return preview.build_extension_control_event_targets(
        BUILT_IN_COMMAND_EXTENSION_REGISTRY, (make_layer(),), (make_layer(),)
    )


def test_event_targets_ask_with_the_catalog_and_both_sides_of_the_replacement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests = resident_answers(monkeypatch, _answer({"kind": "preview_event_targets", "targets": [_target()]}))
    current = make_layer(ControlLayerKind.LOCAL_ADMIN)
    proposed = make_layer(ControlLayerKind.LOCAL_ADMIN, make_disabled(ControlTargetKind.PERMISSION, PERMISSION))

    targets = preview.build_extension_control_event_targets(
        BUILT_IN_COMMAND_EXTENSION_REGISTRY, (current,), (proposed,)
    )

    assert targets == [_target()]
    query = request_query(requests[0])
    assert query["kind"] == "preview_event_targets"
    assert query["registry"] == bridge._preview_registry_wire(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    assert query["current_layers"] == [bridge._layer_wire(current)]
    assert query["proposed_layers"] == [bridge._layer_wire(proposed)]


def test_event_targets_keep_the_order_the_resident_named_them_in(monkeypatch: pytest.MonkeyPatch) -> None:
    refs = [DIGEST_C, DIGEST_A, DIGEST_B]

    targets = _targets(
        monkeypatch,
        {"kind": "preview_event_targets", "targets": [_target(target_ref=ref) for ref in refs]},
    )

    assert [target["target_ref"] for target in targets] == refs


def test_no_changed_target_is_an_empty_list(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _targets(monkeypatch, {"kind": "preview_event_targets", "targets": []}) == []


@pytest.mark.parametrize(
    "bad",
    [
        _target(kind="role"),
        _target(target_ref="short"),
        _target(target_ref="A" * 64),
        _target(target_ref=7),
        _target(before_explicit="maybe"),
        _target(after_explicit=None),
        _target(before_effective="maybe"),
        _target(after_effective=None),
        _target(affected_rule_ids="git.push"),
        _target(affected_rule_ids=[7]),
        _target(affected_rule_ids=["rule"] * 1025),
        {**_target(), "target_id": PERMISSION},
        {key: value for key, value in _target().items() if key != "target_ref"},
        "target",
    ],
)
def test_a_malformed_event_target_raises(monkeypatch: pytest.MonkeyPatch, bad: object) -> None:
    with pytest.raises(bridge.NativeExtensionControlError) as caught:
        _targets(monkeypatch, {"kind": "preview_event_targets", "targets": [bad]})
    assert caught.value.code == "native_extension_control_payload_invalid"


def test_more_event_targets_than_one_event_holds_are_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    within = [_target(target_ref=f"{index:064x}") for index in range(512)]
    assert len(_targets(monkeypatch, {"kind": "preview_event_targets", "targets": within})) == 512

    with pytest.raises(bridge.NativeExtensionControlError) as caught:
        _targets(monkeypatch, {"kind": "preview_event_targets", "targets": [*within, _target()]})
    assert caught.value.code == "native_extension_control_payload_invalid"


@pytest.mark.parametrize(
    "payload",
    [
        {"kind": "preview_event_targets"},
        {"kind": "preview_event_targets", "targets": {}},
        {"kind": "preview_event_targets", "targets": [], "extra": 1},
        {"kind": "preview_event_targets", "preview": {}},
    ],
)
def test_a_malformed_event_target_reply_raises(monkeypatch: pytest.MonkeyPatch, payload: dict[str, object]) -> None:
    with pytest.raises(bridge.NativeExtensionControlError) as caught:
        _targets(monkeypatch, payload)
    assert caught.value.code == "native_extension_control_payload_invalid"


@pytest.mark.parametrize("answered", ["preview", "request_digest", "candidate_nonce"])
def test_the_answer_of_another_query_is_no_event_target_list(monkeypatch: pytest.MonkeyPatch, answered: str) -> None:
    with pytest.raises(bridge.NativeExtensionControlError) as caught:
        _targets(monkeypatch, {"kind": answered, "targets": [], "preview": {}})
    assert caught.value.code == "native_extension_control_unavailable"
