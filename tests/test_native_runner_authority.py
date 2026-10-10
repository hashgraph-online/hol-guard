"""Transport contract and recorded parity for the native runner-authority owner.

The vectors in ``fixtures/runner_authority/vectors.json`` were recorded from the
retired Python ``guard run`` authority helpers before they were deleted; the same
file is replayed by the Rust unit tests, so a divergence here means the resident
changed behaviour.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_runner_authority as module
from codex_plugin_scanner.guard.native_runner_authority import NativeRunnerAuthorityError, native_runner_authority
from codex_plugin_scanner.guard.runtime import runner as guard_runner
from codex_plugin_scanner.guard.runtime import runner_native_authority as authority
from codex_plugin_scanner.guard.store import GuardStore

_VECTORS = Path(__file__).parent / "fixtures" / "runner_authority" / "vectors.json"


def _vectors() -> list[dict[str, Any]]:
    document = json.loads(_VECTORS.read_text(encoding="utf-8"))
    assert document["version"] == 1
    return document["vectors"]


def _replay(vector: dict[str, Any]) -> None:
    """Replay through the typed adapters so the slim projections are held to the recorded Python."""

    kind, args, expected = vector["kind"], vector["args"], vector["expected"]
    base = vector.get("merge_base") or {}
    if kind == "apply_detector_result":
        # A vector may record no artifacts at all; then the merge base omits the key.
        assert base.get("artifacts") == args["artifacts"] and base["blocked"] == args["blocked"]
        assert authority.with_recorded_detector_result(base, args["detector"]) == expected
    elif kind == "preclaim_failure":
        assert base.get("artifacts") == args["artifacts"]
        evaluation, evidence = authority.with_preclaim_failure(
            base, affected_artifact_ids=set(args["affected_artifact_ids"]), reason_code=args["reason_code"]
        )
        assert (evaluation, evidence) == (expected["evaluation"], expected["receipt_evidence"])
    elif kind == "claim_context_failure":
        assert base.get("artifacts") == args["artifacts"]
        evaluation, evidence = authority.with_claim_context_failure(
            base, claimed_artifact_ids=set(args["claimed_artifact_ids"])
        )
        assert (evaluation, evidence) == (expected["evaluation"], expected["receipt_evidence"])
    elif kind == "authority_gate":
        error = authority.authority_error(args["evaluation"], require_launch_permitted=args["require_launch_permitted"])
        assert {"authority_error": error} == expected
    elif kind == "request_overrides" and args["mode"] == "interactive":
        overrides, labels = authority.interactive_request_overrides({"artifacts": args["artifacts"]})
        assert {"overrides": overrides, "labels": labels} == expected
    elif kind == "authority_signature_pair":
        a, b = (native_runner_authority("authority_signature", args[side])["signature"] for side in ("a", "b"))
        assert (a is None, b is None) == (expected["a_null"], expected["b_null"])
        assert (a is not None and a == b) == expected["equal"]
    else:
        assert native_runner_authority(kind, args) == expected


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_recorded_python_vectors_match_the_resident(tmp_path: Path) -> None:
    vectors = _vectors()
    assert len(vectors) > 200
    mismatches = []
    for vector in vectors:
        try:
            _replay(vector)
        except AssertionError:
            mismatches.append(f"{vector['kind']} / {vector['name']}")
    assert mismatches == []


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_unknown_kind_and_malformed_args_fail_closed() -> None:
    with pytest.raises(NativeRunnerAuthorityError, match="unknown_kind"):
        native_runner_authority("not_a_kind", {})
    with pytest.raises(NativeRunnerAuthorityError, match="invalid"):
        native_runner_authority("detector_composition", {})
    with pytest.raises(NativeRunnerAuthorityError, match="invalid"):
        native_runner_authority("preclaim_failure", {"artifacts": [], "affected_artifact_ids": [], "reason_code": "x"})


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_adapters_present_resident_answers() -> None:
    evaluation = {
        "blocked": False,
        "artifacts": [],
        "runtime_detector_composition": {"action": "review", "reason": "why", "downgraded": False, "upgraded": False},
        "runtime_detector_signals_v2": [],
        "runtime_detector_telemetry": [{"detector_id": "d", "elapsed_ms": 9, "categories": ["b", "a", "a"]}],
    }
    result = authority.detector_authority(evaluation)
    assert result.action == "review"
    assert result.nonterminal_evidence is not None
    assert result.nonterminal_evidence["reason_code"] == "runtime_detector_review"
    assert result.context is not None
    assert result.context["telemetry"] == [{"detector_id": "d", "categories": ["a", "b"]}]
    assert authority.claim_partition([]) == ({}, {}, {})
    assert authority.exact_request_overrides({}) == {}


def _force_available(monkeypatch: pytest.MonkeyPatch, *, keep_health: bool = False) -> None:
    class Features:
        features = frozenset({module._FEATURE, module._RESIDENT_PROTOCOL_FEATURE})

    class Identity:
        path = "/bin/true"
        sha256 = "0" * 64

    class Status:
        mode = "force"
        available = True
        compatible = True
        identity = Identity()
        capabilities = Features()

    monkeypatch.setattr(module, "_native_runtime_status_memo", lambda: Status())
    monkeypatch.setattr(module, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(module, "native_resident_client_ready", lambda *_a, **_k: True)
    if not keep_health:
        monkeypatch.setattr(module, "native_record_resident_failure", lambda *a, **k: None)


def _call(tmp_path: Path) -> dict[str, Any]:
    return native_runner_authority("detector_composition", {"signals": []}, tmp_path)


def test_unavailable_native_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    class Status:
        mode = "off"
        available = False
        compatible = False
        identity = None
        capabilities = None

    monkeypatch.setattr(module, "_native_runtime_status_memo", lambda: Status())
    with pytest.raises(NativeRunnerAuthorityError, match="unavailable"):
        _call(tmp_path)


def test_missing_feature_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    class Features:
        features = frozenset({module._RESIDENT_PROTOCOL_FEATURE})

    class Identity:
        path = "/bin/true"
        sha256 = "0" * 64

    class Status:
        mode = "force"
        available = True
        compatible = True
        identity = Identity()
        capabilities = Features()

    monkeypatch.setattr(module, "_native_runtime_status_memo", lambda: Status())
    with pytest.raises(NativeRunnerAuthorityError, match="unavailable"):
        _call(tmp_path)


def test_mismatched_binding_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _force_available(monkeypatch)
    monkeypatch.setattr(
        module,
        "native_resident_client_request",
        lambda **_: (
            b'{"schema":"guard-runner-authority-result.v1","request_id":"x","request_sha256":"y",'
            b'"status":"ok","code":"ok","payload":{"blocks":false}}'
        ),
    )
    with pytest.raises(NativeRunnerAuthorityError):
        _call(tmp_path)


def test_malformed_or_absent_reply_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _force_available(monkeypatch)
    for reply in (None, b"not json", b"[]", b"{}", b'{"status":"error"}'):
        monkeypatch.setattr(module, "native_resident_client_request", lambda reply=reply, **_: reply)
        with pytest.raises(NativeRunnerAuthorityError):
            _call(tmp_path)


def test_bound_refusals_never_open_the_availability_circuit(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A resident that answers a bad request is healthy; only outages count toward the circuit."""

    from codex_plugin_scanner.guard.native_runtime_resilience import native_runtime_health_snapshot

    _force_available(monkeypatch, keep_health=True)

    def refuse(*, payload: bytes, **_: object) -> bytes:
        request = json.loads(payload)["request"]
        return json.dumps(
            {
                "schema": module._RESULT_SCHEMA,
                "request_id": request["request_id"],
                "request_sha256": module._canonical_request_sha256(request),
                "status": "error",
                "code": "native_runner_authority_invalid",
            }
        ).encode()

    monkeypatch.setattr(module, "native_resident_client_request", refuse)
    for _ in range(5):
        with pytest.raises(NativeRunnerAuthorityError, match="invalid"):
            _call(tmp_path)
    assert not native_runtime_health_snapshot("0" * 64, tmp_path).circuit_open


def test_oversized_request_is_refused_before_the_resident(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _force_available(monkeypatch)

    def never(**_kwargs: object) -> bytes:
        raise AssertionError("resident must not be asked")

    monkeypatch.setattr(module, "native_resident_client_request", never)
    with pytest.raises(NativeRunnerAuthorityError, match="too_large"):
        native_runner_authority("detector_composition", {"signals": ["x" * (5 * 1024 * 1024)]}, tmp_path)


def test_adapter_rejects_an_answer_of_the_wrong_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(authority, "native_runner_authority", lambda *_a, **_k: {"authority_error": 5})
    with pytest.raises(NativeRunnerAuthorityError, match="result_invalid"):
        authority.authority_error({}, require_launch_permitted=False)


def _bulk_artifacts(count: int, *, padding: int, key: str) -> tuple[list[dict[str, Any]], set[str]]:
    vector = next(item for item in _vectors() if item["kind"] == "preclaim_failure")
    template = vector["merge_base"]["artifacts"][0]
    artifacts = []
    for index in range(count):
        artifact = json.loads(json.dumps(template))
        artifact["artifact_id"] = f"codex:project:bulk-{index}"
        artifact[key] = "x" * padding
        artifacts.append(artifact)
    return artifacts, {item["artifact_id"] for item in artifacts}


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_large_evaluation_fits_without_raising_the_caps() -> None:
    # 8 MiB of artifact payload the owner never reads: only the authority
    # projection crosses the transport, so no cap is hit and nothing is dropped.
    artifacts, ids = _bulk_artifacts(40, padding=200 * 1024, key="description")
    evaluation = {"artifacts": artifacts, "blocked": False}
    result, evidence = authority.with_preclaim_failure(
        evaluation, affected_artifact_ids=ids, reason_code="approval_reuse_claim_failed"
    )
    assert evidence["reason_code"] == "approval_reuse_claim_failed"
    assert result["blocked"] is True
    assert [item["artifact_id"] for item in result["artifacts"]] == [item["artifact_id"] for item in artifacts]
    assert all(item["description"] == "x" * (200 * 1024) for item in result["artifacts"])
    assert all(item["approval_reuse_status"] == "rejected" for item in result["artifacts"])
    assert authority.authority_error(result, require_launch_permitted=False) == authority.authority_error(
        {**result, "artifacts": [{**item, "description": None} for item in result["artifacts"]]},
        require_launch_permitted=False,
    )


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_chunked_patches_land_on_the_right_artifact(monkeypatch: pytest.MonkeyPatch) -> None:
    # Authority-relevant padding (scanner_evidence) forces several chunks.
    artifacts, ids = _bulk_artifacts(24, padding=0, key="unused")
    for index, artifact in enumerate(artifacts):
        artifact["scanner_evidence"] = [{"source": "pad", "reason_code": f"r{index}", "pad": "y" * (100 * 1024)}]
    calls: list[str] = []
    real = authority.native_runner_authority
    monkeypatch.setattr(authority, "native_runner_authority", lambda kind, args: calls.append(kind) or real(kind, args))
    result, _ = authority.with_preclaim_failure(
        {"artifacts": artifacts, "blocked": False},
        affected_artifact_ids=ids - {"codex:project:bulk-3"},
        reason_code="approval_reuse_claim_failed",
    )
    assert len(calls) > 1
    for index, artifact in enumerate(artifacts):
        alone, _ = authority.with_preclaim_failure(
            {"artifacts": [artifact], "blocked": False},
            affected_artifact_ids=ids - {"codex:project:bulk-3"},
            reason_code="approval_reuse_claim_failed",
        )
        assert result["artifacts"][index] == alone["artifacts"][0]
    assert "approval_reuse_status" not in result["artifacts"][3]


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_overflow_fails_closed_and_never_permits() -> None:
    artifacts, ids = _bulk_artifacts(1, padding=0, key="unused")
    artifacts[0]["scanner_evidence"] = [{"source": "pad", "reason_code": "r", "pad": "z" * (5 * 1024 * 1024)}]
    evaluation = {"artifacts": artifacts, "blocked": False}
    with pytest.raises(NativeRunnerAuthorityError):
        authority.authority_error(evaluation, require_launch_permitted=True)
    with pytest.raises(NativeRunnerAuthorityError):
        authority.with_preclaim_failure(
            evaluation, affected_artifact_ids=ids, reason_code="approval_reuse_claim_failed"
        )


def test_patch_merge_rejects_out_of_range_or_non_mapping_targets() -> None:
    for patches in ([{"index": 5, "set": {}}], [{"index": 0, "set": []}], [{"index": "0", "set": {}}]):
        with pytest.raises(NativeRunnerAuthorityError, match="result_invalid"):
            authority._with_set({"artifacts": [{"artifact_id": "a"}]}, {"artifact_patches": patches})
    with pytest.raises(NativeRunnerAuthorityError, match="result_invalid"):
        authority._with_set({"artifacts": ["not-a-mapping"]}, {"artifact_patches": [{"index": 0, "set": {}}]})


_EVIDENCE = {"source": "approval_reuse", "status": "rejected", "reason_code": "x", "reason": "r"}


def _seed_receipts(store: GuardStore, rows: list[tuple[str, str]]) -> None:
    with store._connect() as connection:
        connection.executemany(
            """
            insert into runtime_receipts (
              receipt_id, harness, artifact_id, artifact_hash, policy_decision,
              changed_capabilities_json, provenance_summary, scanner_evidence_json, timestamp
            ) values (?, 'codex', ?, 'h', 'allow', '[]', 'p', ?, '2026-01-01T00:00:00Z')
            """,
            [(f"r{index}", artifact_id, evidence) for index, (artifact_id, evidence) in enumerate(rows)],
        )


def _append(store: GuardStore) -> None:
    guard_runner._append_authority_evidence_to_receipts(
        store,
        after_rowid=0,
        evaluation={"artifacts": [{"artifact_id": "wanted"}]},
        evidence=_EVIDENCE,
        approval_source="approval-gate",
        source_actions=frozenset({"allow"}),
    )


def test_receipt_projection_skips_unrelated_rows(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_receipts(store, [("other", "[]")] * 1200 + [("wanted", "[]")] * 2 + [("other", "[]")] * 600)
    sent: list[list[str]] = []

    def record(rows: list[Any], **_kwargs: Any) -> list[dict[str, Any]]:
        sent.append([row["artifact_id"] for row in rows])
        return []

    monkeypatch.setattr(guard_runner._authority, "receipt_evidence_updates", record)
    _append(store)
    assert sent == [["wanted", "wanted"]]


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_receipt_projection_batches_under_the_envelope_cap(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    padded = json.dumps([{"source": "pad", "reason_code": "p", "pad": "q" * (150 * 1024)}])
    # 40 related rows (6 MiB) among unrelated ones: one request could not carry them.
    _seed_receipts(store, [("other", padded), ("wanted", padded)] * 40)
    _append(store)
    with store._connect() as connection:
        rows = connection.execute("select artifact_id, scanner_evidence_json from runtime_receipts").fetchall()
    assert len(rows) == 80
    for row in rows:
        evidence = json.loads(row["scanner_evidence_json"])
        assert (evidence[-1] == _EVIDENCE) == (row["artifact_id"] == "wanted")
