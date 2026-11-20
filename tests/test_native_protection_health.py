"""The protection-health adapter only reads a complete, request-bound reply."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_execution, native_protection_health
from codex_plugin_scanner.guard.native_context import _canonical_request_sha256
from codex_plugin_scanner.guard.runtime.protection_health import ProtectionCheckStatus, ProtectionSignal

_PAYLOAD: dict[str, Any] = {
    "schema_version": "guard.protection-health.v1",
    "state": "protected",
    "label": "Protected",
    "detail": "All required protection checks have current proof.",
    "evidence_gap": False,
    "checks": [{"check_id": "daemon", "status": "pass", "reason_code": "daemon_healthy"}],
    "reason_codes": ["daemon_healthy"],
    "apps": [],
}


def _app(**overrides: Any) -> dict[str, Any]:
    """One harness row of the report, as the resident publishes it."""

    row: dict[str, Any] = {
        "harness": "codex",
        "state": "protected",
        "label": "Protected",
        "detail": "All required protection checks have current proof.",
        "evidence_gap": False,
        "checks": [{"check_id": "daemon", "status": "pass", "reason_code": "daemon_healthy"}],
        "reason_codes": ["daemon_healthy"],
    }
    row.update(overrides)
    return row


def _facts() -> dict[str, Any]:
    return {
        "now": "2026-07-19T15:00:00+00:00",
        "managed_installs": [{"harness": "codex", "active": True}],
        "hook_verification": {"codex": True},
        "daemon": None,
        "remembered_rules": "enforced",
        "runtime_protection": "protected",
        "decision_stream": {"active_error_count": 0, "activity_count": 1},
    }


def _install(monkeypatch: pytest.MonkeyPatch, mutate) -> tuple[list[tuple[str, object]], list[dict[str, Any]]]:
    recorded: list[tuple[str, object]] = []
    sent: list[dict[str, Any]] = []

    def fake(*, request, response_schema, record_success, status, **_kwargs) -> dict[str, Any]:
        assert record_success is False
        assert status.identity.sha256 == "0" * 64
        assert _kwargs["operation"] == "protection_health_facts"
        assert _kwargs["required_feature"] == "protection-health-facts-v1"
        sent.append(request)
        result: dict[str, Any] = {
            "schema": response_schema,
            "request_id": request["request_id"],
            # The resident answers with the prefixed token.
            "request_sha256": "sha256:" + _canonical_request_sha256(request),
            "status": "ok",
            "code": "ok",
            "payload": dict(_PAYLOAD),
        }
        mutate(result)
        return result

    monkeypatch.setattr(native_protection_health, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(native_execution, "_resident_request", fake)
    monkeypatch.setattr(
        native_protection_health,
        "native_runtime_status",
        lambda: SimpleNamespace(identity=SimpleNamespace(sha256="0" * 64)),
    )
    monkeypatch.setattr(
        native_protection_health,
        "native_record_resident_success",
        lambda *_args: recorded.append(("success", None)),
    )
    monkeypatch.setattr(
        native_protection_health,
        "native_record_resident_failure",
        lambda *_args, reason: recorded.append(("failure", reason)),
    )
    return recorded, sent


def _call(tmp_path):
    return native_protection_health.protection_health_report(_facts(), guard_home=tmp_path)


def test_a_bound_reply_returns_the_report_and_records_success(monkeypatch, tmp_path) -> None:
    recorded, _sent = _install(monkeypatch, lambda result: None)
    assert _call(tmp_path) == _PAYLOAD
    assert recorded == [("success", None)]


def test_a_harness_row_the_resident_published_is_returned_whole(monkeypatch, tmp_path) -> None:
    app = _app()
    recorded, _sent = _install(monkeypatch, lambda result: result["payload"].update(apps=[app]))
    assert _call(tmp_path)["apps"] == [app]
    assert recorded == [("success", None)]


def test_the_request_carries_the_facts_under_the_facts_schema(monkeypatch, tmp_path) -> None:
    _recorded, sent = _install(monkeypatch, lambda result: None)
    _call(tmp_path)
    request = dict(sent[0])
    assert request.pop("schema") == "guard-protection-health-facts-request.v1"
    assert isinstance(request.pop("request_id"), str)
    assert request == _facts()


def test_the_facts_cannot_replace_the_schema_or_request_id(monkeypatch, tmp_path) -> None:
    _recorded, sent = _install(monkeypatch, lambda result: None)
    native_protection_health.protection_health_report(
        {**_facts(), "schema": "other", "request_id": "chosen"}, guard_home=tmp_path
    )
    assert sent[0]["schema"] == "guard-protection-health-facts-request.v1"
    assert sent[0]["request_id"] != "chosen"


def test_a_free_form_reason_is_refused_before_it_can_be_sent() -> None:
    with pytest.raises(ValueError, match="stable identifier"):
        ProtectionSignal(ProtectionCheckStatus.FAIL, "Not A Reason Code")


@pytest.mark.parametrize(
    "mutate",
    [
        lambda result: result.update(request_sha256="sha256:" + "0" * 64),
        # The bare hex of the right request is still the wrong token.
        lambda result: result.update(request_sha256=result["request_sha256"].removeprefix("sha256:")),
        lambda result: result.update(request_id="other"),
        lambda result: result.update(code="other"),
        lambda result: result.update(payload="nope"),
        lambda result: result["payload"].pop("state"),
        lambda result: result["payload"].update(extra={}),
        # A payload that keeps every key can still be no report at all. None of
        # these may be rendered as a headline the resident never published.
        lambda result: result["payload"].update(state="compromised"),
        lambda result: result["payload"].update(state=1),
        lambda result: result["payload"].update(state=[]),
        lambda result: result["payload"].update(checks=[{"check_id": "daemon", "status": {}, "reason_code": "x"}]),
        lambda result: result["payload"].update(schema_version=1),
        lambda result: result["payload"].update(label=None),
        lambda result: result["payload"].update(detail=[]),
        lambda result: result["payload"].update(evidence_gap="false"),
        lambda result: result["payload"].update(checks={}),
        lambda result: result["payload"].update(checks=[{"check_id": "daemon", "status": "ok", "reason_code": "x"}]),
        lambda result: result["payload"].update(checks=[{"check_id": "daemon", "status": "pass"}]),
        lambda result: result["payload"].update(reason_codes=["daemon_healthy", 7]),
        lambda result: result["payload"].update(apps=[{"harness": "codex"}]),
        lambda result: result["payload"].update(apps=[_app(state="compromised")]),
        lambda result: result["payload"].update(apps=[_app(checks=[{"check_id": "daemon"}])]),
    ],
)
def test_an_unusable_reply_raises_the_adapter_error_and_records_a_failure(monkeypatch, tmp_path, mutate) -> None:
    recorded, _sent = _install(monkeypatch, mutate)
    with pytest.raises(native_protection_health.NativeProtectionHealthError):
        _call(tmp_path)
    assert recorded == [("failure", "native_protection_health_report_result")]


def test_a_missing_resident_reply_leaves_recording_to_the_transport(monkeypatch, tmp_path) -> None:
    recorded, _sent = _install(monkeypatch, lambda result: None)
    monkeypatch.setattr(native_execution, "_resident_request", lambda **_kwargs: None)
    with pytest.raises(native_protection_health.NativeProtectionHealthError, match="unavailable"):
        _call(tmp_path)
    assert recorded == []


def test_an_absent_runtime_never_reads_as_a_protected_machine(monkeypatch, tmp_path) -> None:
    recorded, _sent = _install(monkeypatch, lambda result: None)
    monkeypatch.setattr(native_protection_health, "ensure_resident_prerequisite", lambda _home: False)
    with pytest.raises(native_protection_health.NativeProtectionHealthError, match="unavailable"):
        _call(tmp_path)
    assert recorded == []
