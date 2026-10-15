"""Consumer artifact projection is answered by the native runtime.

The language-neutral vectors are shared with the Rust crate and were recorded
from the retired Python projection (capability delta, diff, history,
provenance, receipt strings, incident copy and result rows), so a divergence
here means the resident changed behaviour.
"""

from __future__ import annotations

import gzip
import json
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard import native_consumer_artifact_project as project
from codex_plugin_scanner.guard.consumer import projection
from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.store import GuardStore

_VECTORS = json.loads(
    gzip.decompress(
        (
            Path(__file__).parent.parent
            / "rust"
            / "crates"
            / "guard-runtime"
            / "tests"
            / "fixtures"
            / "consumer_artifact_project_vectors.json.gz"
        ).read_bytes()
    )
)


def _fields(vector: dict[str, object]) -> tuple[str, dict[str, object]]:
    query = dict(cast(Mapping[str, object], vector["query"]))
    return str(query.pop("kind")), query


def _first(kind: str) -> dict[str, object]:
    return next(vector for vector in _VECTORS if vector["query"]["kind"] == kind)


def test_resident_answers_match_shared_vectors(native_approval_reuse_runtime: Path) -> None:
    mismatches = []
    for vector in _VECTORS:
        kind, fields = _fields(vector)
        answer = project.native_consumer_project(kind, fields, guard_home=native_approval_reuse_runtime)
        if answer != vector["expected"]:
            mismatches.append(vector["name"])
    assert mismatches == []


def test_vectors_cover_every_query_kind() -> None:
    assert {vector["query"]["kind"] for vector in _VECTORS} == set(project._FIELDS)


def _artifact_from_wire(wire: Mapping[str, object], source_metadata: dict[str, object] | None = None) -> GuardArtifact:
    return GuardArtifact(
        artifact_id=str(wire["artifact_id"]),
        name=str(wire["name"]),
        harness=str(wire["harness"]),
        artifact_type=str(wire["artifact_type"]),
        source_scope=str(wire["source_scope"]),
        config_path=str(wire["config_path"]),
        command=cast("str | None", wire["command"]),
        args=tuple(cast("list[str]", wire["args"])),
        url=cast("str | None", wire["url"]),
        transport=cast("str | None", wire["transport"]),
        publisher=cast("str | None", wire["publisher"]),
        metadata=dict(source_metadata if source_metadata is not None else cast("dict[str, object]", wire["metadata"])),
    )


def test_wire_artifact_matches_the_recorded_vector_artifacts() -> None:
    checked = 0
    for vector in _VECTORS:
        wire = vector["query"].get("artifact")
        if not isinstance(wire, dict):
            continue
        source = vector.get("source_metadata")
        artifact = _artifact_from_wire(wire, cast("dict[str, object] | None", source))
        assert projection.wire_artifact(artifact) == wire, vector["name"]
        checked += 1
    assert checked > 100


def test_structured_summary_vectors_keep_launch_and_incident_copy_on_string_summaries() -> None:
    structured = [vector for vector in _VECTORS if vector["name"].startswith("structured-")]
    assert len(structured) >= 90
    for vector in structured:
        metadata = vector["query"]["artifact"]["metadata"]
        source = vector["source_metadata"]
        for key in ("request_summary", "prompt_summary", "runtime_request_summary"):
            if key in source and not isinstance(source[key], str):
                assert key not in metadata, vector["name"]
                assert key in metadata["capability_text_summaries"], vector["name"]


def test_wire_artifact_sends_structured_summaries_only_as_capability_text() -> None:
    wire = next(v["query"]["artifact"] for v in _VECTORS if isinstance(v["query"].get("artifact"), dict))
    artifact = _artifact_from_wire(wire)
    artifact.metadata.update({"request_summary": {"a": 1}, "prompt_summary": [], "runtime_request_summary": "ok"})
    metadata = projection.wire_artifact(artifact)["metadata"]
    assert isinstance(metadata, dict)
    assert "request_summary" not in metadata
    assert "prompt_summary" not in metadata
    assert metadata["runtime_request_summary"] == "ok"
    assert metadata["capability_text_summaries"] == {"request_summary": "{'a': 1}", "prompt_summary": ""}


class _Store:
    guard_home = None


def test_history_reads_the_store_into_the_recorded_wire_shape(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    artifact_id = "codex:project:tool"
    store.add_event("changed_artifact_caught", {"artifact_id": artifact_id}, "2026-07-18T00:00:00Z")
    store.add_event("changed_artifact_caught", {"artifact_id": "other"}, "2026-07-18T00:00:01Z")
    store.add_event("install_time_block", {"artifact_id": artifact_id}, "2026-07-18T00:00:02Z")
    history = projection._history(store, "codex", artifact_id, None)
    assert history["inventory_item"] is None
    assert history["decision_counts"] == {}
    assert sorted(cast("list[str]", history["event_names"])) == ["changed_artifact_caught", "install_time_block"]
    assert history["advisories"] == []
    assert set(history) == set(cast("dict[str, object]", _first("artifact_evidence")["query"])["history"])


def test_bare_diff_sends_the_empty_history(monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[dict[str, object]] = []

    def capture(kind: str, fields: Mapping[str, object], *, guard_home: Path | None) -> dict[str, object]:
        sent.append({"kind": kind, **fields})
        return {}

    monkeypatch.setattr(projection, "native_consumer_project", capture)
    artifact = GuardArtifact(
        artifact_id="a", name="a", harness="codex", artifact_type="skill", source_scope="project", config_path="/p"
    )
    projection.artifact_evidence(None, artifact, payload={}, content_hash="h", previous=None, with_history=False)
    assert sent[0]["history"] == {"inventory_item": None, "decision_counts": {}, "event_names": [], "advisories": []}
    assert sent[0]["previous_capabilities"] is None


_EVIDENCE_FIELDS = _fields(_first("artifact_evidence"))[1]
_EVIDENCE_ANSWER = _first("artifact_evidence")["expected"]


def _resident_returning(monkeypatch: pytest.MonkeyPatch, reply) -> list[object]:
    """Stub the transport; the returned list records health verdicts and transport kwargs."""

    seen: list[object] = []
    monkeypatch.setattr(project, "_resolve_digest_home", lambda _home: Path("/tmp/consumer-project-home"))
    monkeypatch.setattr(project, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(project, "_record_health", lambda _home, *, healthy: seen.append(healthy))

    def fake(*, request, **kwargs):
        seen.append(kwargs)
        return reply(request)

    monkeypatch.setattr(project, "_resident_request", fake)
    return seen


def _good(request: dict[str, object], **overrides: object) -> dict[str, object]:
    reply: dict[str, object] = {
        "schema": "guard-consumer-artifact-project-result.v1",
        "request_id": request["request_id"],
        "request_sha256": "sha256:" + project._canonical_request_sha256(request),
        "status": "ok",
        "code": "ok",
        "payload": dict(cast("dict[str, object]", _EVIDENCE_ANSWER)),
    }
    reply.update(overrides)
    return reply


def _evidence() -> dict[str, object]:
    return project.native_consumer_project("artifact_evidence", _EVIDENCE_FIELDS, guard_home=None)


def test_bound_answer_is_returned(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _resident_returning(monkeypatch, lambda request: _good(request))
    assert _evidence() == _EVIDENCE_ANSWER
    transport, healthy = seen
    assert isinstance(transport, dict)
    assert transport["record_success"] is False
    assert transport["max_request_bytes"] == 4 * 1024 * 1024
    assert healthy is True


@pytest.mark.parametrize(
    "overrides",
    [
        {"request_sha256": "sha256:" + "0" * 64},
        {"payload": {"changed": True}},
    ],
)
def test_unbound_or_malformed_answers_count_as_resident_failures(
    monkeypatch: pytest.MonkeyPatch, overrides: dict[str, object]
) -> None:
    seen = _resident_returning(monkeypatch, lambda request: _good(request, **overrides))
    with pytest.raises(project.NativeConsumerProjectError):
        _evidence()
    assert seen[-1] is False


@pytest.mark.parametrize(
    "overrides",
    [
        {"request_sha256": "sha256:" + "0" * 64},
        {"request_id": "someone-else"},
        {"schema": "wrong"},
        {"status": "error", "code": "native_consumer_artifact_project_schema_mismatch", "payload": None},
        {"status": "ok", "code": "other"},
        {"payload": None},
        {"payload": []},
    ],
)
def test_unbound_or_malformed_replies_raise(monkeypatch: pytest.MonkeyPatch, overrides: dict[str, object]) -> None:
    _resident_returning(monkeypatch, lambda request: _good(request, **overrides))
    with pytest.raises(project.NativeConsumerProjectError):
        _evidence()


@pytest.mark.parametrize(
    "mutate",
    [
        lambda payload: payload.pop("scoring"),
        lambda payload: payload.update(extra=1),
        lambda payload: payload.update(changed=1),
        lambda payload: payload.update(current_hash=None),
        lambda payload: payload.update(changed_fields="x"),
    ],
)
def test_incomplete_or_mistyped_payloads_raise(monkeypatch: pytest.MonkeyPatch, mutate) -> None:
    payload = json.loads(json.dumps(_EVIDENCE_ANSWER))
    mutate(payload)
    _resident_returning(monkeypatch, lambda request: _good(request, payload=payload))
    with pytest.raises(project.NativeConsumerProjectError) as error:
        _evidence()
    assert error.value.code == "native_consumer_artifact_project_payload_invalid"


def test_removed_result_must_be_marked_removed(monkeypatch: pytest.MonkeyPatch) -> None:
    kind, fields = _fields(_first("removed_result"))
    payload = json.loads(json.dumps(_first("removed_result")["expected"]))
    payload["result"]["removed"] = False
    _resident_returning(monkeypatch, lambda request: _good(request, payload=payload))
    with pytest.raises(project.NativeConsumerProjectError):
        project.native_consumer_project(kind, fields, guard_home=None)


def test_error_codes_are_sanitised(monkeypatch: pytest.MonkeyPatch) -> None:
    _resident_returning(
        monkeypatch,
        lambda request: _good(request, status="error", code="native_consumer_artifact_project_schema_mismatch"),
    )
    with pytest.raises(project.NativeConsumerProjectError) as known:
        _evidence()
    assert known.value.code == "native_consumer_artifact_project_schema_mismatch"
    _resident_returning(monkeypatch, lambda request: _good(request, status="error", code="free text"))
    with pytest.raises(project.NativeConsumerProjectError) as unknown:
        _evidence()
    assert unknown.value.code == "native_consumer_artifact_project_unavailable"


def test_unavailable_resident_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _resident_returning(monkeypatch, lambda _request: None)
    with pytest.raises(project.NativeConsumerProjectError):
        _evidence()


def test_missing_prerequisite_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _resident_returning(monkeypatch, lambda request: _good(request))
    monkeypatch.setattr(project, "ensure_resident_prerequisite", lambda _home: False)
    with pytest.raises(project.NativeConsumerProjectError):
        _evidence()


@pytest.mark.parametrize(
    ("kind", "fields"),
    [
        ("unknown_kind", {}),
        ("artifact_evidence", {**_EVIDENCE_FIELDS, "extra": 1}),
        ("incident_context", {"harness": "codex"}),
    ],
)
def test_request_key_set_is_exact(monkeypatch: pytest.MonkeyPatch, kind: str, fields: dict[str, object]) -> None:
    _resident_returning(monkeypatch, lambda request: _good(request))
    with pytest.raises(project.NativeConsumerProjectError) as error:
        project.native_consumer_project(kind, fields, guard_home=None)
    assert error.value.code == "native_consumer_artifact_project_request_invalid"
