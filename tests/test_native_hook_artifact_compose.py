"""Hook artifact decision composition is answered by the native runtime.

The language-neutral vectors are shared with the Rust crate, so a divergence
here means the resident changed behaviour.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_hook_artifact_compose as compose

_VECTORS = json.loads(
    (
        Path(__file__).parent.parent
        / "rust"
        / "crates"
        / "guard-runtime"
        / "tests"
        / "fixtures"
        / "hook_artifact_compose_vectors.json"
    ).read_text(encoding="utf-8")
)


def _fields(vector: dict[str, object]) -> tuple[str, dict[str, object]]:
    query = dict(vector["query"])  # type: ignore[arg-type]
    return str(query.pop("kind")), query


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_resident_answers_match_shared_vectors(native_approval_reuse_runtime: Path) -> None:
    mismatches = []
    for vector in _VECTORS:
        kind, fields = _fields(vector)
        if kind not in compose._FIELDS:
            # The resident still answers kinds no Python caller sends; the
            # Rust crate replays those vectors itself.
            continue
        answer = compose.native_hook_compose(kind, fields, guard_home=native_approval_reuse_runtime)
        if answer != vector["expected"]:
            mismatches.append(vector["name"])
    assert mismatches == []


_TRUSTED_OVERRIDE_FIELDS = dict.fromkeys(compose._FIELDS["trusted_override"])


def _resident_returning(monkeypatch: pytest.MonkeyPatch, reply) -> None:
    monkeypatch.setattr(compose, "_resolve_digest_home", lambda _home: Path("/tmp/hook-compose-home"))
    monkeypatch.setattr(compose, "ensure_resident_prerequisite", lambda _home: True)

    def fake(*, request, **_kwargs):
        return reply(request)

    monkeypatch.setattr(compose, "_resident_request", fake)


_CONFIG_FIELDS: dict[str, object] = {"policy_config": None, "artifact": None}
_CONFIG_ANSWER = {"action": "allow", "auto_stop_events": []}


def _good(request: dict[str, object], **overrides: object) -> dict[str, object]:
    reply: dict[str, object] = {
        "schema": "guard-hook-artifact-compose-result.v1",
        "request_id": request["request_id"],
        "request_sha256": "sha256:" + compose._canonical_request_sha256(request),
        "status": "ok",
        "code": "ok",
        "payload": dict(_CONFIG_ANSWER),
    }
    reply.update(overrides)
    return reply


def test_bound_answer_is_returned(monkeypatch: pytest.MonkeyPatch) -> None:
    _resident_returning(monkeypatch, lambda request: _good(request))
    assert compose.native_hook_compose("config_action", _CONFIG_FIELDS, guard_home=None) == _CONFIG_ANSWER


def test_bound_validation_refusal_is_value_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _resident_returning(
        monkeypatch,
        lambda request: _good(
            request,
            status="error",
            code="native_hook_artifact_compose_validation_refused",
            payload={"error_type": "ValueError", "message": "signal list required"},
        ),
    )
    with pytest.raises(compose.NativeHookComposeValidationError, match="signal list required"):
        compose.native_hook_compose("config_action", _CONFIG_FIELDS, guard_home=None)


@pytest.mark.parametrize(
    "overrides",
    [
        {"request_sha256": "sha256:" + "0" * 64},
        {"request_id": "someone-else"},
        {"schema": "wrong"},
        {"status": "error", "code": "native_hook_artifact_compose_schema_mismatch", "payload": None},
        {"status": "error", "code": "arbitrary text", "payload": None},
        {"status": "ok", "code": "other"},
        {"payload": None},
        {"payload": []},
    ],
)
def test_unbound_or_malformed_answers_raise(monkeypatch: pytest.MonkeyPatch, overrides: dict[str, object]) -> None:
    _resident_returning(monkeypatch, lambda request: _good(request, **overrides))
    with pytest.raises(compose.NativeHookComposeError):
        compose.native_hook_compose("config_action", _CONFIG_FIELDS, guard_home=None)


@pytest.mark.parametrize(
    "payload",
    [
        {"action": "allow"},
        {**_CONFIG_ANSWER, "extra": 1},
        {**_CONFIG_ANSWER, "action": "bogus"},
        {**_CONFIG_ANSWER, "action": None},
        {**_CONFIG_ANSWER, "auto_stop_events": 1},
    ],
)
def test_incomplete_or_mistyped_payloads_raise(monkeypatch: pytest.MonkeyPatch, payload: dict[str, object]) -> None:
    _resident_returning(monkeypatch, lambda request: _good(request, payload=payload))
    with pytest.raises(compose.NativeHookComposeError) as error:
        compose.native_hook_compose("config_action", _CONFIG_FIELDS, guard_home=None)
    assert error.value.code == "native_hook_artifact_compose_payload_invalid"


def test_boolean_fields_reject_integers(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {"claim_required": 1, "evidence": None, "reason_code": None}
    _resident_returning(monkeypatch, lambda request: _good(request, payload=payload))
    with pytest.raises(compose.NativeHookComposeError):
        compose.native_hook_compose("trusted_override", _TRUSTED_OVERRIDE_FIELDS, guard_home=None)


def test_error_codes_are_sanitised(monkeypatch: pytest.MonkeyPatch) -> None:
    _resident_returning(
        monkeypatch,
        lambda request: _good(request, status="error", code="native_hook_artifact_compose_schema_mismatch"),
    )
    with pytest.raises(compose.NativeHookComposeError) as known:
        compose.native_hook_compose("config_action", _CONFIG_FIELDS, guard_home=None)
    assert known.value.code == "native_hook_artifact_compose_schema_mismatch"
    _resident_returning(monkeypatch, lambda request: _good(request, status="error", code="free text"))
    with pytest.raises(compose.NativeHookComposeError) as unknown:
        compose.native_hook_compose("config_action", _CONFIG_FIELDS, guard_home=None)
    assert unknown.value.code == "native_hook_artifact_compose_unavailable"


def test_unavailable_resident_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _resident_returning(monkeypatch, lambda _request: None)
    with pytest.raises(compose.NativeHookComposeError):
        compose.native_hook_compose("config_action", _CONFIG_FIELDS, guard_home=None)


def test_missing_prerequisite_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _resident_returning(monkeypatch, lambda request: _good(request))
    monkeypatch.setattr(compose, "ensure_resident_prerequisite", lambda _home: False)
    with pytest.raises(compose.NativeHookComposeError):
        compose.native_hook_compose("config_action", _CONFIG_FIELDS, guard_home=None)


@pytest.mark.parametrize(
    ("kind", "fields"),
    [
        ("unknown_kind", {}),
        ("config_action", {"policy_config": None}),
        ("config_action", {**_CONFIG_FIELDS, "extra": 1}),
        ("trusted_override", {"policy_action": "allow"}),
        ("package_firewall_access", {}),
        # Kinds the resident answers but no Python caller sends are refused.
        ("policy_stack", {"event_name": "PreToolUse"}),
        ("tool_grant_apply", {}),
    ],
)
def test_request_key_set_is_exact(monkeypatch: pytest.MonkeyPatch, kind: str, fields: dict[str, object]) -> None:
    _resident_returning(monkeypatch, lambda request: _good(request))
    with pytest.raises(compose.NativeHookComposeError) as error:
        compose.native_hook_compose(kind, fields, guard_home=None)
    assert error.value.code == "native_hook_artifact_compose_request_invalid"


def _feature_recorder(
    monkeypatch: pytest.MonkeyPatch,
    payload: dict[str, object] | None = None,
) -> list[str | None]:
    """Record the feature each query requires of the resident.

    A kind that answers with its own payload passes one, so the recorded reply
    is the answer that kind's result schema accepts.
    """

    required: list[str | None] = []
    monkeypatch.setattr(compose, "_resolve_digest_home", lambda _home: Path("/tmp/hook-compose-home"))
    monkeypatch.setattr(compose, "ensure_resident_prerequisite", lambda _home: True)

    def fake(*, request, required_feature=None, **_kwargs):
        required.append(required_feature)
        if payload is None:
            return _good(request)
        return _good(request, payload=payload)

    monkeypatch.setattr(compose, "_resident_request", fake)
    return required


def test_a_kind_added_after_the_op_requires_its_own_feature(monkeypatch: pytest.MonkeyPatch) -> None:
    required = _feature_recorder(monkeypatch)
    with pytest.raises(compose.NativeHookComposeError):
        compose.native_hook_compose(
            "package_reuse_settle",
            dict.fromkeys(compose._FIELDS["package_reuse_settle"]),
            guard_home=None,
        )
    assert required == [compose.HOOK_ARTIFACT_COMPOSE_PACKAGE_REUSE_FEATURE]


def test_the_kinds_the_op_shipped_with_require_the_op_feature(monkeypatch: pytest.MonkeyPatch) -> None:
    required = _feature_recorder(monkeypatch)
    compose.native_hook_compose("config_action", _CONFIG_FIELDS, guard_home=None)
    assert required == [compose.HOOK_ARTIFACT_COMPOSE_FEATURE]


def test_the_signal_composition_kind_requires_its_own_feature(monkeypatch: pytest.MonkeyPatch) -> None:
    required = _feature_recorder(
        monkeypatch,
        payload={
            "action": "block",
            "reason": "bypass signal 'det' forces block",
            "downgraded": False,
            "upgraded": True,
            "normalization_reason_code": None,
            "original_action": None,
        },
    )
    composed = compose.native_hook_compose(
        "signal_composition",
        {"signals": [], "base_action": "allow"},
        guard_home=None,
    )
    assert composed["action"] == "block"
    assert required == [compose.HOOK_ARTIFACT_COMPOSE_SIGNAL_COMPOSITION_FEATURE]


def test_the_policy_lookup_selection_requires_its_own_feature(monkeypatch: pytest.MonkeyPatch) -> None:
    required = _feature_recorder(monkeypatch)
    with pytest.raises(compose.NativeHookComposeError):
        compose.native_hook_compose("policy_lookup_select", {"lookups": []}, guard_home=None)
    assert required == [compose.HOOK_ARTIFACT_COMPOSE_POLICY_LOOKUP_FEATURE]


@pytest.mark.parametrize("revision", [True, "7", 7.0, None])
def test_integer_answers_reject_anything_but_an_integer(
    monkeypatch: pytest.MonkeyPatch,
    revision: object,
) -> None:
    payload = {
        "authority_revision": revision,
        "decision": None,
        "ignored_local_integrity": None,
        "trust_status": {},
    }
    _resident_returning(monkeypatch, lambda request: _good(request, payload=payload))
    with pytest.raises(compose.NativeHookComposeError):
        compose.native_hook_compose("policy_lookup_select", {"lookups": []}, guard_home=None)


def test_the_live_allow_precheck_is_bounded_where_its_envelopes_are(monkeypatch: pytest.MonkeyPatch) -> None:
    """The precheck carries two action envelopes, so the default cap is too small.

    An envelope the hook adapter accepted must not be refused on the way to the
    resident: that would deny an action the user had already approved.
    """

    seen: dict[str, object] = {}
    monkeypatch.setattr(compose, "_resolve_digest_home", lambda _home: Path("/tmp/hook-compose-home"))
    monkeypatch.setattr(compose, "ensure_resident_prerequisite", lambda _home: True)

    def fake(*, request, **kwargs: object) -> dict[str, object]:
        seen.update(kwargs)
        return _good(
            request,
            payload={
                "review_required": False,
                "claimed_saved_allow_hash": None,
                "claimed_approval_request_id": None,
            },
        )

    monkeypatch.setattr(compose, "_resident_request", fake)

    answer = compose.native_hook_compose(
        "codex_live_allow_precheck",
        dict.fromkeys(compose._FIELDS["codex_live_allow_precheck"]),
        guard_home=None,
    )

    assert answer["review_required"] is False
    assert seen["max_request_bytes"] == 4 * 1024 * 1024
