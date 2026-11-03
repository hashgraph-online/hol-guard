"""The binding requirement of a package evaluation comes from the resident."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_mcp_proxy_decision as decision


class _Evaluation:
    def __init__(self, **fields: Any) -> None:
        for name, value in fields.items():
            setattr(self, name, value)


def _answer(monkeypatch: pytest.MonkeyPatch, payload: object) -> list[dict[str, Any]]:
    queries: list[dict[str, Any]] = []

    def decide(query: dict[str, Any], **kwargs: Any) -> Any:
        queries.append({**query, **kwargs})
        if isinstance(payload, Exception):
            raise payload
        return payload

    monkeypatch.setattr(decision, "native_mcp_proxy_decide", decide)
    return queries


def test_the_resident_answers_and_the_query_carries_only_the_fields_it_reads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    queries = _answer(monkeypatch, {"required": True})
    evaluation = _Evaluation(
        external_archive_source_hashes=("a" * 64,),
        reasons=({"code": "external_tarball_source"},),
        packages=(),
        decision="block",
        user_copy=object(),
    )

    assert decision.native_external_archive_binding_required(evaluation, guard_home=Path("/tmp/g")) is True
    assert queries[0]["check"] == "external_archive_binding_required"
    assert queries[0]["required_feature"] == decision.MCP_PROXY_ARCHIVE_BINDING_REQUIRED_FEATURE
    assert queries[0]["evaluation"] == {
        "external_archive_source_hashes": ["a" * 64],
        "reasons": [{"code": "external_tarball_source"}],
        "packages": [],
    }


def test_a_field_that_is_not_a_sequence_carries_no_entries(monkeypatch: pytest.MonkeyPatch) -> None:
    queries = _answer(monkeypatch, {"required": False})
    evaluation = _Evaluation(reasons="external_tarball_source")

    assert decision.native_external_archive_binding_required(evaluation, guard_home=Path("/tmp/g")) is False
    assert queries[0]["evaluation"] == {
        "external_archive_source_hashes": [],
        "reasons": [],
        "packages": [],
    }


@pytest.mark.parametrize(
    "payload",
    [
        decision.NativeMcpProxyDecisionError("native_mcp_proxy_decision_unavailable"),
        {},
        {"required": "yes"},
        {"required": None},
    ],
)
def test_no_authoritative_answer_demands_the_binding(monkeypatch: pytest.MonkeyPatch, payload: object) -> None:
    # Demanding a binding the caller cannot produce blocks the install, so an
    # unreachable or malformed answer has to read as a requirement.
    _ = _answer(monkeypatch, payload)

    assert decision.native_external_archive_binding_required(object(), guard_home=Path("/tmp/g")) is True
