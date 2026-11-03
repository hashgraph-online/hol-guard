"""The audit projection bridge only transports and fails closed on any bad native reply."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_package_audit_projection as bridge
from codex_plugin_scanner.guard import native_workspace_inventory as inventory

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


def test_a_large_package_list_is_sent_in_bounded_batches(monkeypatch: pytest.MonkeyPatch) -> None:
    # One request for every package of a large workspace outgrew the request
    # limit; each batch stays within its bound and indices map back in order.
    packages = [{"name": f"package-{index:05d}", "pad": "x" * 400} for index in range(6000)]
    batches: list[list[object]] = []

    def transport(request: dict[str, object], *_args: object, **_kwargs: object) -> dict[str, object]:
        batch = request["query"]["packages"]  # type: ignore[index]
        batches.append(batch)
        return {"aliases": [{"index": len(batch) - 1, "aliases": [f"CVE-{len(batches)}"]}]}

    monkeypatch.setattr(bridge, "_transport", transport)
    aliases = bridge.native_advisory_aliases(packages, store=_STORE)
    assert len(batches) >= 3
    assert [package for batch in batches for package in batch] == packages
    assert all(len(json.dumps(batch, separators=(",", ":"))) <= bridge._ALIAS_BATCH_BYTES for batch in batches)
    ends = [sum(len(batch) for batch in batches[: number + 1]) - 1 for number in range(len(batches))]
    assert aliases == {end: [f"CVE-{number + 1}"] for number, end in enumerate(ends)}


def test_an_audit_deadline_stops_alias_batches_before_the_next_request(monkeypatch: pytest.MonkeyPatch) -> None:
    packages = [{"name": f"package-{index:05d}", "pad": "x" * 400} for index in range(6000)]
    clock = [0.0]
    batches: list[object] = []

    def transport(request: dict[str, object], *_args: object, **_kwargs: object) -> dict[str, object]:
        batches.append(request)
        clock[0] += 4.0
        return {"aliases": []}

    monkeypatch.setattr(bridge, "_transport", transport)
    monkeypatch.setattr(inventory.time, "monotonic", lambda: clock[0])

    with inventory.audit_deadline(3), pytest.raises(inventory.AuditDeadlineError):
        bridge.native_advisory_aliases(packages, store=_STORE)

    assert len(batches) == 1


def test_an_empty_package_list_still_asks_once(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _patch(monkeypatch, {"aliases": []})
    assert bridge.native_advisory_aliases([], store=_STORE) == {}
    assert len(seen) == 1


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


_FINDING = {
    "finding_id": "a" * 32,
    "source_kind": "supply_chain",
    "detector": "supply_chain_local_v1",
    "severity": "high",
    "decision": "block",
    "ecosystem": "npm",
    "package_name": "@babel/traverse",
    "package_version": "7.0.0",
    "fix_version": None,
    "rule_ids": ["advisory_match"],
    "advisory_ids": ["GHSA-1"],
    "validation_state": "confirmed",
    "lifecycle_state": "open",
}
_WORKSPACE = {"findings": [_FINDING], "listed": [["npm", "@babel/traverse", "7.0.0"]], "unresolved": 1, "unchecked": 0}


def test_workspace_findings_send_only_what_the_projection_reads(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _patch(monkeypatch, dict(_WORKSPACE))
    payload = {"audit_status": "complete", "evaluation": {"packages": []}, "manifest_paths": ["/work/package.json"]}
    supply = bridge.native_workspace_package_findings("w" * 64, payload, store=_STORE)
    assert supply == bridge.SupplyChainProjection(
        findings=[_FINDING], listed=frozenset({("npm", "@babel/traverse", "7.0.0")}), unresolved=1, unchecked=0
    )
    query = seen[0]["request"]["query"]  # type: ignore[index]
    assert query == {
        "query": "workspace_findings",
        "worktree_key": "w" * 64,
        "payload": {"audit_status": "complete", "evaluation": {"packages": []}},
    }


def test_workspace_findings_drop_evaluation_fields_the_projection_does_not_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = _patch(monkeypatch, dict(_WORKSPACE))
    package = {
        "decision": "block",
        "ecosystem": "npm",
        "name": "a",
        "reasons": [{"code": "malicious_package", "severity": "high", "message": "m" * 4096}, "text"],
        "metadata": {"tarball": "x" * 4096},
    }
    evaluation = {"bundle_version": "v1", "packages": [package, 7], "trace": ["t"] * 100}
    bridge.native_workspace_package_findings("w", {"evaluation": evaluation}, store=_STORE)
    query = seen[0]["request"]["query"]  # type: ignore[index]
    assert query["payload"] == {
        "evaluation": {
            "bundle_version": "v1",
            "packages": [
                {
                    "decision": "block",
                    "ecosystem": "npm",
                    "name": "a",
                    "reasons": [{"code": "malicious_package", "severity": "high"}, "text"],
                },
                7,
            ],
        }
    }


def test_a_short_package_list_stays_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, {**_WORKSPACE, "listed": None})
    assert bridge.native_workspace_package_findings("w", {}, store=None).listed is None


@pytest.mark.parametrize(
    "reply",
    [
        {**_WORKSPACE, "extra": 1},
        {**_WORKSPACE, "unresolved": True},
        {**_WORKSPACE, "unchecked": -1},
        {**_WORKSPACE, "listed": [["npm", "a"]]},
        {**_WORKSPACE, "listed": [["npm", "a", None]]},
        {**_WORKSPACE, "findings": [{**_FINDING, "severity": "severe"}]},
        {**_WORKSPACE, "findings": [{**_FINDING, "decision": "allow"}]},
        {**_WORKSPACE, "findings": [{**_FINDING, "source_kind": "secret"}]},
        {**_WORKSPACE, "findings": [{**_FINDING, "package_name": ""}]},
        {**_WORKSPACE, "findings": [{**_FINDING, "advisory_ids": [3]}]},
        {**_WORKSPACE, "findings": [{**_FINDING, "path": "/work/package.json"}]},
    ],
)
def test_invalid_workspace_findings_fail_closed(monkeypatch: pytest.MonkeyPatch, reply: dict[str, object]) -> None:
    _patch(monkeypatch, reply)
    with pytest.raises(bridge.NativePackageAuditProjectionError):
        bridge.native_workspace_package_findings("w", {}, store=_STORE)


def test_package_identities_stay_aligned_with_their_inputs(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _patch(monkeypatch, {"finding_ids": ["b" * 32], "settled": [True, False]})
    ids, settled = bridge.native_package_identities(
        [_FINDING],
        [{"source_kind": "supply_chain"}, "x"],
        frozenset({("npm", "b", ""), ("npm", "a", "")}),
        store=_STORE,
    )
    assert (ids, settled) == (["b" * 32], [True, False])
    query = seen[0]["request"]["query"]  # type: ignore[index]
    assert query["listed"] == [["npm", "a", ""], ["npm", "b", ""]]


@pytest.mark.parametrize(
    "reply",
    [
        {"finding_ids": [], "settled": [False]},
        {"finding_ids": ["b"], "settled": []},
        {"finding_ids": ["b"], "settled": [1]},
        {"finding_ids": ["b"], "settled": [False], "extra": 1},
        {"finding_ids": [None], "settled": [False]},
        {"finding_ids": [7], "settled": [False]},
        {"finding_ids": [""], "settled": [False]},
    ],
)
def test_misaligned_package_identities_fail_closed(monkeypatch: pytest.MonkeyPatch, reply: dict[str, object]) -> None:
    _patch(monkeypatch, reply)
    with pytest.raises(bridge.NativePackageAuditProjectionError):
        bridge.native_package_identities([_FINDING], [{}], None, store=_STORE)


def test_a_finding_that_is_not_a_package_keeps_its_own_id(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, {"finding_ids": ["b" * 32], "settled": [False]})
    secret = {"finding_id": "s" * 32, "source_kind": "secret"}
    with pytest.raises(bridge.NativePackageAuditProjectionError):
        bridge.native_package_identities([secret], [{}], None, store=_STORE)
