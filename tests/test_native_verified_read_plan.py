"""The verified-read plan client tells a grammar refusal from a broken resident."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_verified_read_plan as client


def _install(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, reply: dict[str, Any]) -> list[str]:
    records: list[str] = []
    identity = SimpleNamespace(sha256="a" * 64)
    monkeypatch.setattr(client, "_resolve_digest_home", lambda _home: tmp_path)
    monkeypatch.setattr(client, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(client, "native_runtime_status", lambda: SimpleNamespace(identity=identity))
    monkeypatch.setattr(client, "native_record_resident_success", lambda *_a, **_k: records.append("success"))
    monkeypatch.setattr(client, "native_record_resident_failure", lambda *_a, **_k: records.append("failure"))

    def resident(**kwargs: Any) -> dict[str, Any]:
        request = kwargs["request"]
        return {
            "schema": "guard-verified-read-plan-result.v1",
            "request_id": request["request_id"],
            "request_sha256": client._canonical_request_sha256(request),
            **reply,
        }

    monkeypatch.setattr(client.native_execution, "_resident_request", resident)
    return records


def test_a_refusal_keeps_its_rule_and_counts_as_a_healthy_answer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    records = _install(
        monkeypatch,
        tmp_path,
        {
            "status": "error",
            "code": "native_verified_read_plan_refused",
            "detail": "line count exceeds the bound",
            "plan": None,
        },
    )

    with pytest.raises(client.NativeVerifiedReadPlanRefusedError) as raised:
        client.verified_read_plan(("head", "-2000", "main.py"))

    assert str(raised.value) == "native_verified_read_plan_refused"
    assert raised.value.detail == "line count exceeds the bound"
    assert records == ["success"]


@pytest.mark.parametrize(
    "reply",
    [
        {"status": "error", "code": "native_verified_read_plan_refused", "detail": None, "plan": None},
        {"status": "error", "code": "native_verified_read_plan_refused", "detail": "x" * 257, "plan": None},
        {"status": "error", "code": "native_verified_read_plan_failed", "detail": None, "plan": None},
        {"status": "ok", "code": "native_verified_read_plan_refused", "detail": "rule", "plan": None},
    ],
)
def test_other_error_replies_are_unusable_and_count_against_health(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reply: dict[str, Any]
):
    records = _install(monkeypatch, tmp_path, reply)

    with pytest.raises(client.NativeVerifiedReadPlanError) as raised:
        client.verified_read_plan(("head", "-5", "main.py"))

    assert not isinstance(raised.value, client.NativeVerifiedReadPlanRefusedError)
    assert str(raised.value) == "native_verified_read_plan_invalid_result"
    assert records == ["failure"]
