"""Consumer artifact decision composition is answered by the native runtime.

The language-neutral vectors are shared with the Rust crate and were recorded
from the retired Python composition, so a divergence here means the resident
changed behaviour.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard import native_consumer_artifact_compose as compose
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.consumer import service as consumer_service
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.store import GuardStore

_VECTORS = json.loads(
    (
        Path(__file__).parent.parent
        / "rust"
        / "crates"
        / "guard-runtime"
        / "tests"
        / "fixtures"
        / "consumer_artifact_compose_vectors.json"
    ).read_text(encoding="utf-8")
)


def _fields(vector: dict[str, object]) -> tuple[str, dict[str, object]]:
    query = dict(cast(Mapping[str, object], vector["query"]))
    return str(query.pop("kind")), query


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_resident_answers_match_shared_vectors(native_approval_reuse_runtime: Path) -> None:
    mismatches = []
    for vector in _VECTORS:
        kind, fields = _fields(vector)
        answer = compose.native_consumer_compose(kind, fields, guard_home=native_approval_reuse_runtime)
        if answer != vector["expected"]:
            mismatches.append(vector["name"])
    assert mismatches == []


_CURRENT_FIELDS = _fields(next(vector for vector in _VECTORS if vector["query"]["kind"] == "current_action"))[1]
_CURRENT_ANSWER = {"current_action": "warn", "scanner_action": "allow", "verdict": {"action": "allow"}}


def _resident_returning(monkeypatch: pytest.MonkeyPatch, reply) -> list[object]:
    """Stub the transport; the returned list records health verdicts and transport kwargs."""

    seen: list[object] = []
    monkeypatch.setattr(compose, "_resolve_digest_home", lambda _home: Path("/tmp/consumer-compose-home"))
    monkeypatch.setattr(compose, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(compose, "_record_health", lambda _home, *, healthy: seen.append(healthy))

    def fake(*, request, **kwargs):
        seen.append(kwargs)
        return reply(request)

    monkeypatch.setattr(compose, "_resident_request", fake)
    return seen


def _good(request: dict[str, object], **overrides: object) -> dict[str, object]:
    reply: dict[str, object] = {
        "schema": "guard-consumer-artifact-compose-result.v1",
        "request_id": request["request_id"],
        "request_sha256": "sha256:" + compose._canonical_request_sha256(request),
        "status": "ok",
        "code": "ok",
        "payload": dict(_CURRENT_ANSWER),
    }
    reply.update(overrides)
    return reply


def _compose_current() -> dict[str, object]:
    return compose.native_consumer_compose("current_action", _CURRENT_FIELDS, guard_home=None)


def test_bound_answer_is_returned(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _resident_returning(monkeypatch, lambda request: _good(request))
    assert _compose_current() == _CURRENT_ANSWER
    transport, healthy = seen
    assert isinstance(transport, dict)
    assert transport["record_success"] is False
    assert transport["max_request_bytes"] == 4 * 1024 * 1024
    assert healthy is True


def test_bound_validation_refusal_preserves_message_and_resident_health(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _resident_returning(
        monkeypatch,
        lambda request: _good(
            request,
            status="error",
            code="native_consumer_artifact_compose_validation_refused",
            payload={"error_type": "ValueError", "message": "configured action cannot be weakened"},
        ),
    )
    for _ in range(3):
        with pytest.raises(compose.NativeConsumerComposeValidationError, match="cannot be weakened"):
            _compose_current()
    assert [item for item in seen if isinstance(item, bool)] == [True, True, True]


@pytest.mark.parametrize(
    "overrides",
    [
        {"request_sha256": "sha256:" + "0" * 64},
        {"payload": {"current_action": "warn"}},
    ],
)
def test_unbound_or_malformed_answers_count_as_resident_failures(
    monkeypatch: pytest.MonkeyPatch, overrides: dict[str, object]
) -> None:
    seen = _resident_returning(monkeypatch, lambda request: _good(request, **overrides))
    with pytest.raises(compose.NativeConsumerComposeError):
        _compose_current()
    assert seen[-1] is False


@pytest.mark.parametrize(
    "overrides",
    [
        {"request_sha256": "sha256:" + "0" * 64},
        {"request_id": "someone-else"},
        {"schema": "wrong"},
        {"status": "error", "code": "native_consumer_artifact_compose_schema_mismatch", "payload": None},
        {"status": "ok", "code": "other"},
        {"payload": None},
        {"payload": []},
    ],
)
def test_unbound_or_malformed_answers_raise(monkeypatch: pytest.MonkeyPatch, overrides: dict[str, object]) -> None:
    _resident_returning(monkeypatch, lambda request: _good(request, **overrides))
    with pytest.raises(compose.NativeConsumerComposeError):
        _compose_current()


@pytest.mark.parametrize(
    "payload",
    [
        {"current_action": "warn"},
        {**_CURRENT_ANSWER, "extra": 1},
        {**_CURRENT_ANSWER, "current_action": "bogus"},
        {**_CURRENT_ANSWER, "current_action": None},
        {**_CURRENT_ANSWER, "scanner_action": "sandbox_required"},
        {**_CURRENT_ANSWER, "verdict": []},
    ],
)
def test_incomplete_or_mistyped_payloads_raise(monkeypatch: pytest.MonkeyPatch, payload: dict[str, object]) -> None:
    _resident_returning(monkeypatch, lambda request: _good(request, payload=payload))
    with pytest.raises(compose.NativeConsumerComposeError) as error:
        _compose_current()
    assert error.value.code == "native_consumer_artifact_compose_payload_invalid"


def test_boolean_fields_reject_integers(monkeypatch: pytest.MonkeyPatch) -> None:
    runtime_vector = next(vector for vector in _VECTORS if vector["query"]["kind"] == "runtime_decision")
    kind, fields = _fields(runtime_vector)
    payload = {**runtime_vector["expected"], "authority_finalized": 1}
    _resident_returning(monkeypatch, lambda request: _good(request, payload=payload))
    with pytest.raises(compose.NativeConsumerComposeError):
        compose.native_consumer_compose(kind, fields, guard_home=None)


def test_error_codes_are_sanitised(monkeypatch: pytest.MonkeyPatch) -> None:
    _resident_returning(
        monkeypatch,
        lambda request: _good(request, status="error", code="native_consumer_artifact_compose_schema_mismatch"),
    )
    with pytest.raises(compose.NativeConsumerComposeError) as known:
        _compose_current()
    assert known.value.code == "native_consumer_artifact_compose_schema_mismatch"
    _resident_returning(monkeypatch, lambda request: _good(request, status="error", code="free text"))
    with pytest.raises(compose.NativeConsumerComposeError) as unknown:
        _compose_current()
    assert unknown.value.code == "native_consumer_artifact_compose_unavailable"


def test_unavailable_resident_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _resident_returning(monkeypatch, lambda _request: None)
    with pytest.raises(compose.NativeConsumerComposeError):
        _compose_current()


def test_missing_prerequisite_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _resident_returning(monkeypatch, lambda request: _good(request))
    monkeypatch.setattr(compose, "ensure_resident_prerequisite", lambda _home: False)
    with pytest.raises(compose.NativeConsumerComposeError):
        _compose_current()


@pytest.mark.parametrize(
    ("kind", "fields"),
    [
        ("unknown_kind", {}),
        ("current_action", {**_CURRENT_FIELDS, "extra": 1}),
        ("runtime_decision", {"current_action": "allow"}),
    ],
)
def test_request_key_set_is_exact(monkeypatch: pytest.MonkeyPatch, kind: str, fields: dict[str, object]) -> None:
    _resident_returning(monkeypatch, lambda request: _good(request))
    with pytest.raises(compose.NativeConsumerComposeError) as error:
        compose.native_consumer_compose(kind, fields, guard_home=None)
    assert error.value.code == "native_consumer_artifact_compose_request_invalid"


@pytest.mark.usefixtures("native_prompt_runtime")
@pytest.mark.parametrize("failing", [("current_action", "runtime_authoritative"), ("runtime_authoritative",)])
def test_resident_failure_blocks_each_artifact_without_aborting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failing: tuple[str, ...],
) -> None:
    from codex_plugin_scanner.guard import native_decisions

    def no_second_authority_request(*args: object, **kwargs: object) -> object:
        pytest.fail("an unavailable resident must not receive a second decision request")

    monkeypatch.setattr(native_decisions, "_request", no_second_authority_request)
    answer = compose.native_consumer_compose

    def unavailable(kind: str, fields: Mapping[str, object], *, guard_home: Path | None) -> dict[str, object]:
        if kind in failing:
            raise compose.NativeConsumerComposeError("native_consumer_artifact_compose_unavailable")
        return answer(kind, fields, guard_home=guard_home)

    monkeypatch.setattr(consumer_service, "native_consumer_compose", unavailable)
    artifact = GuardArtifact(
        artifact_id="codex:project:compose-unavailable",
        name="compose-unavailable",
        harness="codex",
        artifact_type="mcp_server",
        source_scope="project",
        config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
        command=sys.executable,
        args=("-c", "pass"),
        transport="stdio",
    )
    detection = HarnessDetection(
        harness="codex",
        installed=True,
        command_available=True,
        config_paths=(artifact.config_path,),
        artifacts=(artifact,),
    )
    config = GuardConfig(guard_home=tmp_path / "guard-home", workspace=tmp_path / "workspace", default_action="allow")

    output = consumer_service.evaluate_detection(
        detection,
        GuardStore(tmp_path / "guard-home"),
        config,
        default_action="allow",
        persist=False,
    )

    assert output["blocked"] is True
    item = output["artifacts"][0]
    assert item["policy_action"] == "block"
    assert item["approval_reuse_reason_code"] == "consumer_artifact_compose_unavailable"
    assert item["policy_composition"]["native_compose_error"] == "native_consumer_artifact_compose_unavailable"
    assert item["trusted_request_override"]["applied"] is False
    assert "approval_claim" not in item
    assert item["evaluation_error"]["code"] == "native_consumer_artifact_compose_unavailable"
    for field in ("decision_v2", "action_envelope", "authoritative_decision", "enforcement", "launch_permitted"):
        assert field not in item
