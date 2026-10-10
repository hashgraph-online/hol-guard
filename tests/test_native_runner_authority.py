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
from codex_plugin_scanner.guard.runtime import runner_native_authority as authority

_VECTORS = Path(__file__).parent / "fixtures" / "runner_authority" / "vectors.json"


def _vectors() -> list[dict[str, Any]]:
    document = json.loads(_VECTORS.read_text(encoding="utf-8"))
    assert document["version"] == 1
    return document["vectors"]


def _replay(vector: dict[str, Any]) -> None:
    kind, args, expected = vector["kind"], vector["args"], vector["expected"]
    base = vector.get("merge_base") or {}
    if kind == "apply_detector_result":
        assert {**base, **native_runner_authority(kind, args)["set"]} == expected
    elif kind in {"preclaim_failure", "claim_context_failure"}:
        result = native_runner_authority(kind, args)
        assert {**base, **result["set"]} == expected["evaluation"]
        assert result["receipt_evidence"] == expected["receipt_evidence"]
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


def _force_available(monkeypatch: pytest.MonkeyPatch) -> None:
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
