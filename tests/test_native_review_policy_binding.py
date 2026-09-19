"""Production local review reuse is isolated by the verified native domain."""

from __future__ import annotations

import copy
import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.hook_native_review_binding import NATIVE_REVIEW_BINDING_FIELD
from codex_plugin_scanner.guard.native_decision_receipt import canonical_receipt_bytes
from codex_plugin_scanner.guard.native_hook_edge import _encode_hook_envelope

from .test_native_command_observations import _observations, _receipt
from .test_native_review_approval_coordination import _edge, _worker


def _bound_edge() -> dict:
    edge = _edge("cursor")
    observations = _observations()
    receipt = _receipt(observations)
    receipt["harness"] = "cursor"
    edge["result"]["reason_code"] = receipt["reason_code"]
    edge["result"]["command_extensions"] = observations
    edge["receipt"] = receipt
    _bind_receipt(edge)
    return edge


def _unbound_edge() -> dict:
    edge = _edge("cursor")
    receipt = _receipt(None)
    receipt["harness"] = "cursor"
    edge["result"]["reason_code"] = receipt["reason_code"]
    receipt["decision_id"] = hashlib.sha256(canonical_receipt_bytes(receipt)).hexdigest()
    edge["receipt"] = receipt
    return edge


def _bind_receipt(edge: dict) -> None:
    receipt = edge["receipt"]
    receipt["command_extensions"] = copy.deepcopy(edge["result"]["command_extensions"]["binding"])
    receipt["decision_id"] = hashlib.sha256(canonical_receipt_bytes(receipt)).hexdigest()


def _review(worker, tmp_path: Path, *, payload: dict | None = None) -> dict:
    return worker.review_http_payload(
        payload=payload
        or {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "cat .env"}},
        params={},
        default_harness="cursor",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
        deadline=time.monotonic() + 5.0,
    )


def _resolve(store, response: dict) -> str:
    request_id = response["approval_request_id"]
    assert store.resolve_harness_native_approval_request(
        request_id,
        reason="Synthetic native prompt resolution",
        resolved_at=datetime.now(tz=timezone.utc).isoformat(),
        expected_harness="cursor",
    )
    return request_id


def test_bound_review_records_domain_and_consumes_once_without_receipt_persistence(tmp_path, monkeypatch) -> None:
    edge = _bound_edge()
    worker, store = _worker(tmp_path, monkeypatch, edge, publish_native_policy=False)
    try:
        first = _review(worker, tmp_path)
        request_id = _resolve(store, first)
        row = store.get_approval_request(request_id)
        binding = row["action_envelope_json"][NATIVE_REVIEW_BINDING_FIELD]
        assert binding["policy_digest"] == edge["receipt"]["policy_digest"]
        assert binding["command_extensions"] == edge["receipt"]["command_extensions"]
        assert worker.activity_writer is None
        assert _review(worker, tmp_path)["approval_reuse_status"] == "accepted"
        # Renewal cannot replenish the already-consumed capability. A fresh
        # user approval remains usable once within the same verified domain.
        edge["receipt"]["policy_generation"] += 1
        _bind_receipt(edge)
        renewed = _review(worker, tmp_path)
        assert renewed["policy_action"] == "review"
        assert "approval_reuse_status" not in renewed
        assert _resolve(store, renewed) != request_id
        assert _review(worker, tmp_path)["approval_reuse_status"] == "accepted"
        assert _review(worker, tmp_path)["policy_action"] == "review"
    finally:
        worker.close()


def test_verified_policy_binding_does_not_enable_mutable_launcher_reuse(tmp_path, monkeypatch) -> None:
    edge = _bound_edge()
    worker, store = _worker(tmp_path, monkeypatch, edge, publish_native_policy=False)
    payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "ollama push test"}}
    try:
        first_id = _resolve(store, _review(worker, tmp_path, payload=payload))
        repeated = _review(worker, tmp_path, payload=payload)
        assert repeated["policy_action"] == "review"
        assert repeated["approval_request_id"] != first_id
        assert "approval_reuse_status" not in repeated
    finally:
        worker.close()


@pytest.mark.parametrize(
    "field",
    [
        "program_digest",
        "catalog_digest",
        "trust_digest",
        "control_revision",
        "managed_control_revision",
        "control_effective_digest",
        "policy_digest",
        "rule_digest",
        "runtime_identity",
    ],
)
def test_changed_verified_policy_domain_never_reuses_prior_allow(tmp_path, monkeypatch, field) -> None:
    edge = _bound_edge()
    worker, store = _worker(tmp_path, monkeypatch, edge, publish_native_policy=False)
    try:
        old_id = _resolve(store, _review(worker, tmp_path))
        target = (
            edge["receipt"]
            if field in {"policy_digest", "rule_digest", "runtime_identity"}
            else edge["result"]["command_extensions"]["binding"]
        )
        target[field] = target[field] + 1 if isinstance(target[field], int) else "f" * 64
        _bind_receipt(edge)
        response = _review(worker, tmp_path)
        assert response["policy_action"] == "review"
        assert response["approval_request_id"] != old_id
        assert "approval_reuse_status" not in response
    finally:
        worker.close()


def test_pending_dedup_does_not_replace_the_policy_a_user_is_reviewing(tmp_path, monkeypatch) -> None:
    edge = _bound_edge()
    worker, store = _worker(tmp_path, monkeypatch, edge, publish_native_policy=False)
    try:
        first = _review(worker, tmp_path)
        original = store.get_approval_request(first["approval_request_id"])
        assert _review(worker, tmp_path)["approval_request_id"] == first["approval_request_id"]
        edge["receipt"]["policy_digest"] = "f" * 64
        _bind_receipt(edge)
        second = _review(worker, tmp_path)
        assert second["approval_request_id"] != first["approval_request_id"]
        retained = store.get_approval_request(first["approval_request_id"])
        assert (
            retained["action_envelope_json"][NATIVE_REVIEW_BINDING_FIELD]
            == original["action_envelope_json"][NATIVE_REVIEW_BINDING_FIELD]
        )
    finally:
        worker.close()


def test_unbound_native_review_fails_closed(tmp_path, monkeypatch) -> None:
    edge = _unbound_edge()
    worker, store = _worker(tmp_path, monkeypatch, edge, publish_native_policy=False)
    try:
        response = _review(worker, tmp_path)
        assert response["policy_action"] == "block"
        assert response["reason_code"] == "native_review_policy_binding_invalid"
        assert "approval_request_id" not in response
        assert store.list_approval_requests(status="pending") == []
    finally:
        worker.close()


def test_payload_binding_cannot_replace_missing_native_receipt(tmp_path, monkeypatch) -> None:
    edge = _bound_edge()
    worker, store = _worker(tmp_path, monkeypatch, edge, publish_native_policy=False)
    try:
        request_id = _resolve(store, _review(worker, tmp_path))
        recorded = store.get_approval_request(request_id)["action_envelope_json"][NATIVE_REVIEW_BINDING_FIELD]
        edge.pop("receipt")
        response = _review(
            worker,
            tmp_path,
            payload={
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "cat .env"},
                NATIVE_REVIEW_BINDING_FIELD: recorded,
            },
        )
        assert response["policy_action"] == "block"
        assert response["reason_code"] == "native_review_policy_binding_invalid"
        assert store.list_approval_requests(status="pending") == []
    finally:
        worker.close()


@pytest.mark.parametrize("reason", ["native_command_permission_disabled", "native_destructive_command"])
def test_native_blocks_cannot_be_overridden_by_prior_local_allow(tmp_path, monkeypatch, reason) -> None:
    edge = _bound_edge()
    worker, store = _worker(tmp_path, monkeypatch, edge, publish_native_policy=False)
    try:
        _resolve(store, _review(worker, tmp_path))
        edge["result"].update(minimum_action="block", policy_action="block", reason_code=reason)
        response = _review(worker, tmp_path)
        assert response["policy_action"] == "block"
        assert response["reason_code"] == reason
        assert "approval_reuse_status" not in response
        assert store.list_approval_requests(status="pending") == []
    finally:
        worker.close()


def test_presence_flag_is_not_added_to_native_wire_snapshot(tmp_path) -> None:
    encoded = _encode_hook_envelope(
        payload={"hook_event_name": "PreToolUse"},
        harness="cursor",
        event="PreToolUse",
        guard_home=tmp_path,
        home_dir=tmp_path,
        cwd=tmp_path,
        source_ref_external_allowed=False,
        deadline_budget_ms=500,
        snapshot={
            "generation": 1,
            "policy_digest": "a" * 64,
            "runtime_identity": "b" * 64,
            "command_extensions_bound": True,
        },
    )
    assert encoded is not None
    assert set(json.loads(encoded)["policy_snapshot"]) == {"generation", "policy_digest", "runtime_identity"}
