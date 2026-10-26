"""The audit projection bridge only transports and fails closed on any bad native reply."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_package_audit_projection as bridge

_STORE = SimpleNamespace(guard_home=Path("/tmp/guard-home-audit"), path=Path("/tmp/guard-home-audit/guard.db"))
_RECEIPT = {
    "policy_decision": "warn",
    "capabilities_summary": "x",
    "artifact_name": "ws",
    "scanner_evidence": {},
}


def _patch(monkeypatch: pytest.MonkeyPatch, reply: dict[str, object]) -> list[dict[str, object]]:
    seen: list[dict[str, object]] = []

    def transport(request: dict[str, object], *_args: object, **kwargs: object) -> dict[str, object]:
        seen.append({"request": request, **kwargs})
        return reply

    monkeypatch.setattr(bridge, "_transport", transport)
    return seen


def test_receipt_sends_query_and_returns_native_payload(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    seen = _patch(monkeypatch, dict(_RECEIPT))
    out = bridge.native_audit_receipt_metadata({"a": 1}, workspace_dir=tmp_path, store=_STORE)
    assert out == _RECEIPT
    query = seen[0]["request"]["query"]  # type: ignore[index]
    assert query["query"] == "receipt"
    assert query["workspace_dir"] == str(tmp_path)
    assert query["store_path"] == str(_STORE.path)
    assert seen[0]["operation"] == "package_audit_projection"


def test_receipt_without_store_or_workspace_omits_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _patch(monkeypatch, dict(_RECEIPT))
    bridge.native_audit_receipt_metadata({}, workspace_dir=None, store=None)
    query = seen[0]["request"]["query"]  # type: ignore[index]
    assert set(query) == {"query", "result"}


@pytest.mark.parametrize(
    "reply",
    [
        {},
        {**_RECEIPT, "policy_decision": "maybe"},
        {**_RECEIPT, "extra": 1},
        {**_RECEIPT, "capabilities_summary": 3},
        {**_RECEIPT, "artifact_name": None},
        {**_RECEIPT, "scanner_evidence": []},
        {**_RECEIPT, "policy_decision": ["warn"]},
    ],
)
def test_receipt_rejects_malformed_reply(monkeypatch: pytest.MonkeyPatch, reply: dict[str, object]) -> None:
    _patch(monkeypatch, reply)
    with pytest.raises(bridge.NativePackageAuditProjectionError):
        bridge.native_audit_receipt_metadata({}, workspace_dir=None, store=None)


def test_aliases_maps_by_index_and_rejects_out_of_range(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, {"aliases": [{"index": 1, "aliases": ["CVE-1"]}]})
    assert bridge.native_advisory_aliases([{}, {}], store=_STORE) == {1: ["CVE-1"]}
    for bad in (
        {"aliases": [{"index": 2, "aliases": []}]},
        {"aliases": [{"index": True, "aliases": []}]},
        {"aliases": [{"index": 0, "aliases": [1]}]},
        {"aliases": "x"},
        {"aliases": [], "extra": 1},
    ):
        _patch(monkeypatch, bad)
        with pytest.raises(bridge.NativePackageAuditProjectionError):
            bridge.native_advisory_aliases([{}, {}], store=_STORE)


def test_ci_gate_and_empty_outcome_validate_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    gate = {"matched": True, "matched_packages": [], "threshold": "high"}
    _patch(monkeypatch, gate)
    assert bridge.native_ci_gate_result({}, threshold="high", store=_STORE) == gate
    _patch(monkeypatch, {**gate, "matched": "yes"})
    with pytest.raises(bridge.NativePackageAuditProjectionError):
        bridge.native_ci_gate_result({}, threshold="high", store=_STORE)
    _patch(monkeypatch, {"audit_outcome": "empty", "message": "m"})
    assert bridge.native_empty_audit_outcome(manifest_paths=[], lockfile_paths=[], posture={}, store=_STORE) == (
        "empty",
        "m",
    )
    _patch(monkeypatch, {"audit_outcome": 1, "message": "m"})
    with pytest.raises(bridge.NativePackageAuditProjectionError):
        bridge.native_empty_audit_outcome(manifest_paths=[], lockfile_paths=[], posture={}, store=_STORE)


@pytest.mark.parametrize(
    "reply",
    [
        {"matched": True, "matched_packages": "a", "threshold": "high"},
        {"matched": True, "matched_packages": [1], "threshold": "high"},
        {"matched": True, "matched_packages": [""], "threshold": "high"},
        {"matched": True, "matched_packages": [], "threshold": 5},
    ],
)
def test_ci_gate_rejects_bad_field_types(monkeypatch: pytest.MonkeyPatch, reply: dict[str, object]) -> None:
    _patch(monkeypatch, reply)
    with pytest.raises(bridge.NativePackageAuditProjectionError):
        bridge.native_ci_gate_result({}, threshold="high", store=_STORE)


def test_requests_use_five_mib_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _patch(monkeypatch, dict(_RECEIPT))
    bridge.native_audit_receipt_metadata({}, workspace_dir=None, store=None)
    assert seen[0]["max_request_bytes"] == 5 * 1024 * 1024
