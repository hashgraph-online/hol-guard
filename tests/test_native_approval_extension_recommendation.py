"""The Python recommendation client builds the resident query and presents only a bound, valid answer.

Whether a queued hint still applies, and which permissions and risk classes call
for a caution, is decided by the resident (``approval_extension_recommendation``)
and pinned by the Rust op's own tests. These tests pin the request the client
builds and the refusal of every reply that is not a bound, strictly shaped
answer: there is no Python decision to fall back to.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from codex_plugin_scanner.guard import native_daemon_route as route
from codex_plugin_scanner.guard import native_resident_decision as shared
from codex_plugin_scanner.guard.daemon import approval_extension_recommendation as client
from codex_plugin_scanner.guard.runtime.extension_allow_hint import EXTENSION_ALLOW_HINT_SCHEMA
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth
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
from tests.native_extension_control_support import UNBOUND_DIGEST, bound_reply

pytestmark = pytest.mark.native_route_unpinned

DIGEST = "a" * 64
GIT_ADD = "command.git.permission.add"
RESULT_SCHEMA = "guard-approval-extension-recommendation-result.v1"
HINT: dict[str, object] = {
    "schema": EXTENSION_ALLOW_HINT_SCHEMA,
    "permission_ids": [GIT_ADD],
    "rule_ids": ["command.git.add"],
    "extension_ids": ["command.git"],
    "relied_permission_ids": [],
    "catalog_digest": DIGEST,
}
PERMISSION: dict[str, object] = {
    "permission_id": GIT_ADD,
    "label": "Git add",
    "description": "Stage files",
    "example_command": None,
    "extension_id": "command.git",
    "extension_name": "Git",
    "rule_id": "command.git.add",
    "risk_tier": "low",
    "caution": False,
    "caution_reason": None,
    "caution_detail": None,
    "cli_command": f"hol-guard command controls set {GIT_ADD} --state allow",
}
RECOMMENDATION: dict[str, object] = {
    "schema": client.RECOMMENDATION_SCHEMA,
    "status": "available",
    "permissions": [PERMISSION],
    "caution": False,
    "revision": 7,
    "catalog_digest": DIGEST,
}
REGISTRY = cast(Any, SimpleNamespace(catalog_digest=DIGEST))


def _snapshot(health: AuthorityHealth = AuthorityHealth.PROTECTED) -> ExtensionControlRuntimeSnapshot:
    layer = ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=DIGEST,
        global_lockdown=False,
        controls=(ExtensionControl(ControlTarget(ControlTargetKind.PERMISSION, GIT_ADD), ControlState.DISABLED),),
    )
    return ExtensionControlRuntimeSnapshot(
        health=health, revision=7, catalog_digest=DIGEST, effective_digest="e" * 64, layers=(layer,)
    )


def _approval(hint: object = HINT, *, status: str = "pending") -> dict[str, object]:
    return {"request_id": "req-1", "status": status, "extension_allow_hint": hint}


class _Resident:
    """A scripted resident: every ask is recorded and answered by ``reply``."""

    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        self.transport_kwargs: list[dict[str, Any]] = []


def _resident(monkeypatch: pytest.MonkeyPatch, reply: Callable[[dict[str, Any]], object]) -> _Resident:
    resident = _Resident()
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=object(),
        capabilities=SimpleNamespace(
            features={"resident-protocol-v2", client.APPROVAL_EXTENSION_RECOMMENDATION_FEATURE}
        ),
    )

    def transport(*, request: dict[str, Any], **kwargs: object) -> object:
        resident.requests.append(request)
        resident.transport_kwargs.append(dict(kwargs))
        return reply(request)

    monkeypatch.setattr(shared, "native_runtime_status", lambda: status)
    monkeypatch.setattr(shared, "_resolve_digest_home", lambda _home: Path("/tmp/approval-recommendation-home"))
    monkeypatch.setattr(shared, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(shared, "record_resident", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(route, "_resident_request", transport)
    return resident


def _recommends(recommendation: object) -> Callable[[dict[str, Any]], object]:
    return lambda request: bound_reply(
        request, {"kind": "recommend", "recommendation": recommendation}, schema=RESULT_SCHEMA
    )


def _cautions(risk_classes: object) -> Callable[[dict[str, Any]], object]:
    return lambda request: bound_reply(
        request, {"kind": "caution_risk_classes", "risk_classes": risk_classes}, schema=RESULT_SCHEMA
    )


def _build() -> dict[str, object] | None:
    return client.build_approval_extension_recommendation(_approval(), registry=REGISTRY, snapshot=_snapshot())


def test_the_client_sends_the_hint_and_the_control_view_and_returns_the_recommendation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    resident = _resident(monkeypatch, _recommends(dict(RECOMMENDATION)))

    recommendation = client.build_approval_extension_recommendation(
        _approval(), registry=REGISTRY, snapshot=_snapshot(), guard_home=tmp_path
    )

    assert recommendation == RECOMMENDATION
    [request] = resident.requests
    assert request["schema"] == "guard-approval-extension-recommendation-request.v1"
    query = cast(dict[str, Any], request["query"])
    assert set(query) == {"kind", "hint", "registry_catalog_digest", "snapshot"}
    assert query["kind"] == "recommend"
    assert query["hint"] == HINT
    assert query["registry_catalog_digest"] == DIGEST
    assert query["snapshot"] == {
        "health": "protected",
        "revision": 7,
        "catalog_digest": DIGEST,
        "layers": [
            {
                "schema_version": CONTROL_SCHEMA_VERSION,
                "kind": "local-admin",
                "catalog_digest": DIGEST,
                "global_lockdown": False,
                "controls": [{"target_kind": "permission", "target_id": GIT_ADD, "state": "disabled"}],
            }
        ],
    }
    kwargs = resident.transport_kwargs[0]
    assert kwargs["operation"] == "approval_extension_recommendation"
    assert kwargs["required_feature"] == client.APPROVAL_EXTENSION_RECOMMENDATION_FEATURE
    assert kwargs["response_schema"] == RESULT_SCHEMA
    # The resident refuses a canonical request over 4 MiB; the envelope fits around it.
    assert kwargs["max_request_bytes"] == 4 * 1024 * 1024 + 64 * 1024


def test_a_null_recommendation_is_no_recommendation(monkeypatch: pytest.MonkeyPatch) -> None:
    resident = _resident(monkeypatch, _recommends(None))

    assert _build() is None
    assert len(resident.requests) == 1


@pytest.mark.parametrize(
    "approval",
    [
        _approval(status="approved"),
        _approval(None),
        _approval({**HINT, "schema": "guard.extension-allow-hint.v2"}),
        _approval({**HINT, "permission_ids": []}),
        _approval("hint"),
    ],
)
def test_nothing_is_asked_without_a_pending_valid_hint(
    monkeypatch: pytest.MonkeyPatch, approval: dict[str, Any]
) -> None:
    resident = _resident(monkeypatch, _recommends(dict(RECOMMENDATION)))

    assert client.build_approval_extension_recommendation(approval, registry=REGISTRY, snapshot=_snapshot()) is None
    assert resident.requests == []


@pytest.mark.parametrize("health", list(AuthorityHealth))
def test_every_authority_health_is_sent_as_its_value(monkeypatch: pytest.MonkeyPatch, health: AuthorityHealth) -> None:
    resident = _resident(monkeypatch, _recommends(None))

    client.build_approval_extension_recommendation(_approval(), registry=REGISTRY, snapshot=_snapshot(health))

    assert resident.requests[0]["query"]["snapshot"]["health"] == health.value


def test_a_resident_unavailable_status_is_kept(monkeypatch: pytest.MonkeyPatch) -> None:
    _resident(monkeypatch, _recommends({**RECOMMENDATION, "status": "authority_unavailable"}))

    recommendation = _build()

    assert recommendation is not None and recommendation["status"] == "authority_unavailable"


@pytest.mark.parametrize(
    "recommendation",
    [
        {**RECOMMENDATION, "surprise": True},
        {key: value for key, value in RECOMMENDATION.items() if key != "revision"},
        {**RECOMMENDATION, "schema": "guard.approval-extension-recommendation.v2"},
        {**RECOMMENDATION, "status": "maybe"},
        {**RECOMMENDATION, "permissions": []},
        {**RECOMMENDATION, "permissions": [PERMISSION] * 13},
        {**RECOMMENDATION, "permissions": [{**PERMISSION, "surprise": True}]},
        {**RECOMMENDATION, "permissions": [{**PERMISSION, "caution": 1}]},
        {**RECOMMENDATION, "permissions": [{**PERMISSION, "label": 7}]},
        {**RECOMMENDATION, "permissions": ["command.git.permission.add"]},
        {**RECOMMENDATION, "caution": "no"},
        {**RECOMMENDATION, "revision": True},
        ["recommendation"],
        "recommendation",
    ],
)
def test_a_malformed_recommendation_is_refused(monkeypatch: pytest.MonkeyPatch, recommendation: object) -> None:
    _resident(monkeypatch, _recommends(recommendation))

    with pytest.raises(client.NativeApprovalExtensionRecommendationError) as refused:
        _build()

    assert refused.value.code == "native_approval_extension_recommendation_payload_invalid"


UNBOUND_REPLIES: list[Callable[[dict[str, Any]], object]] = [
    lambda request: bound_reply(
        request, {"kind": "recommend", "recommendation": None}, schema=RESULT_SCHEMA, status="error"
    ),
    lambda request: bound_reply(
        request, {"kind": "recommend", "recommendation": None}, schema=RESULT_SCHEMA, request_sha256=UNBOUND_DIGEST
    ),
    lambda request: bound_reply(
        request, {"kind": "recommend", "recommendation": None}, schema=RESULT_SCHEMA, request_id="another-request"
    ),
    lambda request: bound_reply(request, {"kind": "recommend", "recommendation": None}, schema="guard-other-result.v1"),
    lambda request: bound_reply(
        request, {"kind": "caution_risk_classes", "recommendation": None}, schema=RESULT_SCHEMA
    ),
    lambda request: bound_reply(request, {"kind": "recommend"}, schema=RESULT_SCHEMA),
    lambda request: bound_reply(
        request, {"kind": "recommend", "recommendation": None, "extra": 1}, schema=RESULT_SCHEMA
    ),
    lambda request: bound_reply(
        request, {"kind": "recommend", "recommendation": dict(RECOMMENDATION)}, schema=RESULT_SCHEMA, code="x"
    ),
    lambda _request: None,
    lambda _request: "not a reply",
]


@pytest.mark.parametrize("reply", UNBOUND_REPLIES)
def test_an_unbound_or_refused_reply_is_an_error_and_never_a_recommendation(
    monkeypatch: pytest.MonkeyPatch, reply: Callable[[dict[str, Any]], object]
) -> None:
    _resident(monkeypatch, reply)

    with pytest.raises(client.NativeApprovalExtensionRecommendationError):
        _build()
    # The read-path shim swallows it: the approval still lists, without advice.
    enriched = client.with_approval_extension_recommendation(
        _approval(), registry=REGISTRY, snapshot=_snapshot(), include=True
    )
    assert "extension_recommendation" not in enriched and "extension_allow_hint" not in enriched


def test_the_resident_names_why_it_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    code = "native_approval_extension_recommendation_catalog_mismatch"
    _resident(
        monkeypatch,
        lambda request: bound_reply(
            request, {"kind": "recommend", "recommendation": None}, schema=RESULT_SCHEMA, status="error", code=code
        ),
    )

    with pytest.raises(client.NativeApprovalExtensionRecommendationError) as refused:
        _build()

    assert refused.value.code == code


def test_a_refused_read_leaves_a_log_trail_with_the_code_and_no_detail(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    code = "native_approval_extension_recommendation_catalog_mismatch"
    _resident(
        monkeypatch,
        lambda request: bound_reply(
            request, {"kind": "recommend", "recommendation": None}, schema=RESULT_SCHEMA, status="error", code=code
        ),
    )

    with caplog.at_level("WARNING", logger=client.__name__):
        enriched = client.with_approval_extension_recommendation(
            _approval(), registry=REGISTRY, snapshot=_snapshot(), include=True
        )

    assert "extension_recommendation" not in enriched
    assert [(record.levelname, record.getMessage()) for record in caplog.records] == [
        ("WARNING", f"Extension recommendation unavailable ({code})")
    ]
    assert all(record.exc_info is None for record in caplog.records)


def test_an_unavailable_resident_is_an_error_and_never_recomputed(monkeypatch: pytest.MonkeyPatch) -> None:
    resident = _resident(monkeypatch, _recommends(dict(RECOMMENDATION)))
    monkeypatch.setattr(shared, "ensure_resident_prerequisite", lambda _home: False)

    with pytest.raises(client.NativeApprovalExtensionRecommendationError):
        _build()
    assert resident.requests == []


def test_enrichment_strips_the_hint_and_respects_include(monkeypatch: pytest.MonkeyPatch) -> None:
    resident = _resident(monkeypatch, _recommends(dict(RECOMMENDATION)))
    approval = _approval()

    enriched = client.with_approval_extension_recommendation(
        approval, registry=REGISTRY, snapshot=_snapshot(), include=True
    )
    hidden = client.with_approval_extension_recommendation(
        approval, registry=REGISTRY, snapshot=_snapshot(), include=False
    )
    unseeded = client.with_approval_extension_recommendation(approval, registry=None, snapshot=None, include=True)

    assert "extension_allow_hint" not in enriched
    assert enriched["extension_recommendation"] == RECOMMENDATION
    assert "extension_allow_hint" not in hidden and "extension_recommendation" not in hidden
    assert "extension_allow_hint" not in unseeded and "extension_recommendation" not in unseeded
    assert len(resident.requests) == 1


def test_caution_classes_are_asked_once_sorted_and_without_repeats(monkeypatch: pytest.MonkeyPatch) -> None:
    resident = _resident(monkeypatch, _cautions(["destructive", "policy_bypass"]))

    answered = client.native_caution_risk_classes(["policy_bypass", "network", "destructive", "network"])

    assert answered == frozenset({"destructive", "policy_bypass"})
    [request] = resident.requests
    assert request["schema"] == "guard-approval-extension-recommendation-request.v1"
    assert request["query"] == {
        "kind": "caution_risk_classes",
        "risk_classes": ["destructive", "network", "policy_bypass"],
    }
    assert resident.transport_kwargs[0]["operation"] == "approval_extension_recommendation"


def test_no_risk_classes_asks_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    resident = _resident(monkeypatch, _cautions(["destructive"]))

    assert client.native_caution_risk_classes([]) == frozenset()
    assert resident.requests == []


@pytest.mark.parametrize(
    "answer",
    [["not-asked"], ["destructive", 7], "destructive", None, [["destructive"]]],
)
def test_a_caution_answer_outside_the_question_is_refused(monkeypatch: pytest.MonkeyPatch, answer: object) -> None:
    _resident(monkeypatch, _cautions(answer))

    with pytest.raises(client.NativeApprovalExtensionRecommendationError) as refused:
        client.native_caution_risk_classes(["destructive", "network"])

    assert refused.value.code == "native_approval_extension_recommendation_payload_invalid"


@pytest.mark.parametrize("reply", UNBOUND_REPLIES)
def test_an_unbound_caution_reply_is_an_error_never_no_caution(
    monkeypatch: pytest.MonkeyPatch, reply: Callable[[dict[str, Any]], object]
) -> None:
    _resident(monkeypatch, reply)

    with pytest.raises(client.NativeApprovalExtensionRecommendationError):
        client.native_caution_risk_classes(["destructive"])
