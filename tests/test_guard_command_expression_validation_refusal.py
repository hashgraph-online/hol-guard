"""An authoring refusal, a refused request and an absent runtime stay distinct."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_command_expression_validation as transport
from codex_plugin_scanner.guard.native_context import _canonical_request_sha256

EXPRESSIONS = [
    {
        "combinator": "all",
        "conditions": [{"field": "command", "operator": "regex", "value": "[unclosed"}],
    }
]


def _home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(transport, "_resolve_digest_home", lambda home: tmp_path)
    monkeypatch.setattr(transport, "ensure_resident_prerequisite", lambda home: True)


def _reply(monkeypatch: pytest.MonkeyPatch, *, bound: bool, status: str, code: str, payload: object = None) -> None:
    def answer(**kwargs: Any) -> dict[str, object]:
        request = kwargs["request"]
        digest = "sha256:" + _canonical_request_sha256(request)
        return {
            "schema": transport._RESULT_SCHEMA,
            "request_id": request["request_id"] if bound else "someone-elses-request",
            "request_sha256": digest,
            "status": status,
            "code": code,
            "payload": payload,
        }

    monkeypatch.setattr(transport, "_resident_request", answer)
    monkeypatch.setattr(transport, "_payload", lambda response, request, home: response.get("payload"))


def _validate() -> tuple[int, str] | None:
    return transport.native_command_expression_validation(EXPRESSIONS)


def _unavailable() -> transport.CommandExpressionValidationUnavailableError:
    with pytest.raises(transport.CommandExpressionValidationUnavailableError) as raised:
        _validate()
    return raised.value


def test_the_runtime_names_the_row_whose_pattern_it_will_not_compile(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _home(monkeypatch, tmp_path)
    _reply(
        monkeypatch,
        bound=True,
        status="ok",
        code="ok",
        payload={"invalid": {"index": 0, "code": "invalid_command_regex"}},
    )

    assert _validate() == (0, "invalid_command_regex")


def test_every_pattern_compiling_is_reported_as_nothing_to_report(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _home(monkeypatch, tmp_path)
    _reply(monkeypatch, bound=True, status="ok", code="ok", payload={"invalid": None})

    assert _validate() is None


def test_a_refused_request_is_reported_as_the_refusal_it_is(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _home(monkeypatch, tmp_path)
    _reply(
        monkeypatch,
        bound=True,
        status="error",
        code="native_command_expression_validation_schema_mismatch",
    )
    error = _unavailable()

    assert error.code == "native_command_expression_validation_schema_mismatch"
    assert error.refused


def test_a_reply_for_another_request_is_an_unavailable_runtime(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _home(monkeypatch, tmp_path)
    _reply(
        monkeypatch,
        bound=False,
        status="error",
        code="native_command_expression_validation_too_large",
    )
    error = _unavailable()

    assert error.code == transport.UNAVAILABLE
    assert not error.refused


def test_a_payload_outside_the_contract_is_an_unavailable_runtime(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _home(monkeypatch, tmp_path)
    _reply(monkeypatch, bound=True, status="ok", code="ok", payload={"invalid": {"index": -1, "code": "x"}})
    error = _unavailable()

    assert error.code == transport.UNAVAILABLE


def test_more_expressions_than_the_contract_carries_never_reach_the_runtime(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _home(monkeypatch, tmp_path)

    def refuse(**kwargs: Any) -> dict[str, object]:
        raise AssertionError("the request must not be sent")

    monkeypatch.setattr(transport, "_resident_request", refuse)

    with pytest.raises(transport.CommandExpressionValidationUnavailableError) as raised:
        transport.native_command_expression_validation(EXPRESSIONS * (transport._MAX_EXPRESSIONS + 1))

    assert raised.value.code == transport.TOO_LARGE
