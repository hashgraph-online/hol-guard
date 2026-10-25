"""The AIBOM summaries adapter only reads a complete, request-bound reply."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import aibom_reporting, native_aibom_summaries, native_execution
from codex_plugin_scanner.guard.native_context import _canonical_request_sha256

_PAYLOAD = {
    "layer_summary": {"skills": 1, "generatedAt": "2026-10-22T00:00:00Z"},
    "trust": {"eligible": 1, "covered": 1},
    "drift": {"total": 0},
}


def _snapshot(metadata: dict[str, object] | None = None) -> SimpleNamespace:
    item = SimpleNamespace(
        item_kind="skill",
        risk_level="low",
        drift_state="unchanged",
        metadata={} if metadata is None else metadata,
    )
    return SimpleNamespace(
        items=(item,),
        findings=({"id": "f1"}, {"id": "f2"}),
        sources=({"path": "a"},),
        drift=(SimpleNamespace(state="new"),),
    )


def _install(monkeypatch: pytest.MonkeyPatch, mutate) -> tuple[list[tuple[str, object]], list[dict[str, Any]]]:
    recorded: list[tuple[str, object]] = []
    sent: list[dict[str, Any]] = []

    def fake(*, request, response_schema, record_success, status, **_kwargs) -> dict[str, Any]:
        assert record_success is False
        assert status.identity.sha256 == "0" * 64
        sent.append(request)
        result: dict[str, Any] = {
            "schema": response_schema,
            "request_id": request["request_id"],
            # The resident answers with the prefixed token.
            "request_sha256": "sha256:" + _canonical_request_sha256(request),
            "status": "ok",
            "code": "ok",
            "payload": {key: dict(value) for key, value in _PAYLOAD.items()},
        }
        mutate(result)
        return result

    monkeypatch.setattr(native_aibom_summaries, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(native_execution, "_resident_request", fake)
    monkeypatch.setattr(
        native_aibom_summaries,
        "native_runtime_status",
        lambda: SimpleNamespace(identity=SimpleNamespace(sha256="0" * 64)),
    )
    monkeypatch.setattr(
        native_aibom_summaries,
        "native_record_resident_success",
        lambda *_args: recorded.append(("success", None)),
    )
    monkeypatch.setattr(
        native_aibom_summaries,
        "native_record_resident_failure",
        lambda *_args, reason: recorded.append(("failure", reason)),
    )
    return recorded, sent


def _call(tmp_path, snapshots=None):
    return native_aibom_summaries.report_summaries(
        (_snapshot(),) if snapshots is None else snapshots,
        generated_at="2026-10-22T00:00:00Z",
        guard_home=tmp_path,
    )


def test_a_bound_reply_returns_the_three_summaries_and_records_success(monkeypatch, tmp_path) -> None:
    recorded, _sent = _install(monkeypatch, lambda result: None)
    layer_summary, trust, drift = _call(tmp_path)
    assert layer_summary == _PAYLOAD["layer_summary"]
    assert trust == _PAYLOAD["trust"]
    assert drift == _PAYLOAD["drift"]
    assert recorded == [("success", None)]


def test_the_request_carries_counts_and_every_metadata_key(monkeypatch, tmp_path) -> None:
    _recorded, sent = _install(monkeypatch, lambda result: None)
    _call(tmp_path, (_snapshot({"sourceLinks": [{"url": "one"}]}),))
    row = sent[0]["snapshots"][0]
    assert row["finding_count"] == 2
    assert row["source_count"] == 1
    assert row["drift_states"] == ["new"]
    item = row["items"][0]
    # Every key travels on every item: one the request omits digests
    # differently on each side and the reply never binds to it.
    assert item["source_links"] == [None]
    assert item["trust_resolution"] is None
    assert item["source_of_truth"] is None


def test_metadata_the_grammar_cannot_read_travels_as_null(monkeypatch, tmp_path) -> None:
    _recorded, sent = _install(monkeypatch, lambda result: None)
    _call(tmp_path, (_snapshot({"trustResolution": "not-an-object", "sourceOfTruth": 7}),))
    item = sent[0]["snapshots"][0]["items"][0]
    assert item["trust_resolution"] is None
    assert item["source_of_truth"] is None


def test_large_metadata_travels_as_the_shape_the_grammar_reads(monkeypatch, tmp_path) -> None:
    _recorded, sent = _install(monkeypatch, lambda result: None)
    detail = {"evidence": ["x" * 4096] * 2048}
    metadata = {
        "trustResolution": {"trustScore": 64, **detail},
        "sourceLinks": [detail, detail, detail],
        "sourceOfTruth": detail,
    }
    _call(tmp_path, (_snapshot(metadata),))
    item = sent[0]["snapshots"][0]["items"][0]
    assert item["trust_resolution"] == {"trustScore": 64}
    assert item["source_links"] == [None, None, None]
    assert item["source_of_truth"] == {}


def test_a_trust_resolution_without_a_numeric_score_travels_as_an_empty_object(monkeypatch, tmp_path) -> None:
    _recorded, sent = _install(monkeypatch, lambda result: None)
    _call(tmp_path, (_snapshot({"trustResolution": {"trustScore": "high", "notes": "n"}}),))
    assert sent[0]["snapshots"][0]["items"][0]["trust_resolution"] == {}


@pytest.mark.parametrize(
    "mutate",
    [
        lambda result: result.update(request_sha256="sha256:" + "0" * 64),
        # The bare hex of the right request is still the wrong token.
        lambda result: result.update(request_sha256=result["request_sha256"].removeprefix("sha256:")),
        lambda result: result.update(request_id="other"),
        lambda result: result.update(code="other"),
        lambda result: result.update(payload="nope"),
        lambda result: result["payload"].pop("trust"),
        lambda result: result["payload"].update(extra={}),
        lambda result: result["payload"].update(drift=[]),
    ],
)
def test_an_unusable_reply_raises_the_adapter_error_and_records_a_failure(monkeypatch, tmp_path, mutate) -> None:
    recorded, _sent = _install(monkeypatch, mutate)
    with pytest.raises(native_aibom_summaries.NativeAibomSummariesError):
        _call(tmp_path)
    assert recorded == [("failure", "native_aibom_report_summaries_result")]


def test_a_missing_resident_reply_leaves_recording_to_the_transport(monkeypatch, tmp_path) -> None:
    recorded, _sent = _install(monkeypatch, lambda result: None)
    monkeypatch.setattr(native_execution, "_resident_request", lambda **_kwargs: None)
    with pytest.raises(native_aibom_summaries.NativeAibomSummariesError, match="unavailable"):
        _call(tmp_path)
    assert recorded == []


def test_the_reporting_seams_fail_closed_when_the_resident_is_gone(monkeypatch) -> None:
    def unavailable(*_args, **_kwargs):
        raise native_aibom_summaries.NativeAibomSummariesError("native_aibom_report_summaries_unavailable")

    monkeypatch.setattr(native_aibom_summaries, "report_summaries", unavailable)
    for call in (
        lambda: aibom_reporting.summarize_aibom_layers((), generated_at="now"),
        lambda: aibom_reporting.summarize_aibom_trust(()),
        lambda: aibom_reporting.summarize_aibom_drift(()),
    ):
        with pytest.raises(native_aibom_summaries.NativeAibomSummariesError):
            call()
