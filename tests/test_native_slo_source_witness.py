"""A delivered allow cannot stand in for actual complete source review."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from scripts.native_slo_source_witness import source_review_witness

_DIGEST = "a" * 64
_REQUEST = {"guard_source_ref": {"output_sha256": _DIGEST}}


def _edge(**changes):
    return {
        "authority": "rust",
        "result": {
            "decision": "allow",
            "model_output_action": "allow_original",
            "reason_code": "native_policy_warning",
            "reviewed_output_sha256": _DIGEST,
            **changes,
        },
    }


def test_complete_source_scan_is_witnessed_before_restoring_method() -> None:
    def original(**kwargs):
        return _edge()
    worker = SimpleNamespace(_review_raw_hook_native=original)
    with source_review_witness(worker, _REQUEST):
        worker._review_raw_hook_native()
    assert worker._review_raw_hook_native is original


@pytest.mark.parametrize(
    "result",
    [
        _edge(reason_code="no_output_to_review", reviewed_output_sha256=None),
        _edge(reviewed_output_sha256="b" * 64),
        _edge(decision="deny"),
        _edge(model_output_action="not_applicable"),
        {"authority": "python", "result": _edge()["result"]},
        None,
    ],
)
def test_allowed_no_output_wrong_digest_or_non_native_edge_never_qualifies(result) -> None:
    def original(**kwargs):
        return result
    worker = SimpleNamespace(_review_raw_hook_native=original)
    with (
        pytest.raises(RuntimeError, match="one complete native content review"),
        source_review_witness(worker, _REQUEST),
    ):
        worker._review_raw_hook_native()
    assert worker._review_raw_hook_native is original


@pytest.mark.parametrize("count", [0, 2, 3])
def test_missing_or_multiple_native_decisions_cannot_qualify(count) -> None:
    worker = SimpleNamespace(_review_raw_hook_native=lambda **kwargs: _edge())
    with (
        pytest.raises(RuntimeError, match="one complete native content review"),
        source_review_witness(worker, _REQUEST),
    ):
        for _ in range(count):
            worker._review_raw_hook_native()


def test_non_source_work_does_not_change_native_method() -> None:
    worker = object()
    with source_review_witness(worker, {"tool_response": []}):
        pass


def test_transport_exception_is_preserved_and_wrapper_retired() -> None:
    def original(**kwargs):
        return _edge()
    worker = SimpleNamespace(_review_raw_hook_native=original)
    with pytest.raises(OSError, match="transport"), source_review_witness(worker, _REQUEST):
        raise OSError("transport")
    assert worker._review_raw_hook_native is original
