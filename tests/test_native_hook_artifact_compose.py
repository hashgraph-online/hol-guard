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


_TOOL_GRANT_ANSWER = {
    "approval_context_policy_action": "allow",
    "current_policy_action": "allow",
    "policy_action": "allow",
}


def _good(request: dict[str, object], **overrides: object) -> dict[str, object]:
    reply: dict[str, object] = {
        "schema": "guard-hook-artifact-compose-result.v1",
        "request_id": request["request_id"],
        "request_sha256": "sha256:" + compose._canonical_request_sha256(request),
        "status": "ok",
        "code": "ok",
        "payload": dict(_TOOL_GRANT_ANSWER),
    }
    reply.update(overrides)
    return reply


def test_bound_answer_is_returned(monkeypatch: pytest.MonkeyPatch) -> None:
    _resident_returning(monkeypatch, lambda request: _good(request))
    assert compose.native_hook_compose("tool_grant_apply", {}, guard_home=None) == _TOOL_GRANT_ANSWER


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
        compose.native_hook_compose("tool_grant_apply", {}, guard_home=None)


@pytest.mark.parametrize(
    "payload",
    [
        {"current_policy_action": "allow"},
        {**_TOOL_GRANT_ANSWER, "extra": 1},
        {**_TOOL_GRANT_ANSWER, "policy_action": "bogus"},
        {**_TOOL_GRANT_ANSWER, "policy_action": None},
        {**_TOOL_GRANT_ANSWER, "current_policy_action": 1},
    ],
)
def test_incomplete_or_mistyped_payloads_raise(monkeypatch: pytest.MonkeyPatch, payload: dict[str, object]) -> None:
    _resident_returning(monkeypatch, lambda request: _good(request, payload=payload))
    with pytest.raises(compose.NativeHookComposeError) as error:
        compose.native_hook_compose("tool_grant_apply", {}, guard_home=None)
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
        compose.native_hook_compose("tool_grant_apply", {}, guard_home=None)
    assert known.value.code == "native_hook_artifact_compose_schema_mismatch"
    _resident_returning(monkeypatch, lambda request: _good(request, status="error", code="free text"))
    with pytest.raises(compose.NativeHookComposeError) as unknown:
        compose.native_hook_compose("tool_grant_apply", {}, guard_home=None)
    assert unknown.value.code == "native_hook_artifact_compose_unavailable"


def test_unavailable_resident_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _resident_returning(monkeypatch, lambda _request: None)
    with pytest.raises(compose.NativeHookComposeError):
        compose.native_hook_compose("tool_grant_apply", {}, guard_home=None)


def test_missing_prerequisite_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _resident_returning(monkeypatch, lambda request: _good(request))
    monkeypatch.setattr(compose, "ensure_resident_prerequisite", lambda _home: False)
    with pytest.raises(compose.NativeHookComposeError):
        compose.native_hook_compose("tool_grant_apply", {}, guard_home=None)


@pytest.mark.parametrize(
    ("kind", "fields"),
    [
        ("unknown_kind", {}),
        ("tool_grant_apply", {"extra": 1}),
        ("grant_settle", {"current_action": "allow"}),
    ],
)
def test_request_key_set_is_exact(monkeypatch: pytest.MonkeyPatch, kind: str, fields: dict[str, object]) -> None:
    _resident_returning(monkeypatch, lambda request: _good(request))
    with pytest.raises(compose.NativeHookComposeError) as error:
        compose.native_hook_compose(kind, fields, guard_home=None)
    assert error.value.code == "native_hook_artifact_compose_request_invalid"
