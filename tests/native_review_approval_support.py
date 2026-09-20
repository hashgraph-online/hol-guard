"""Shared native review fixtures with exact synthetic request evidence."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.native_decision_receipt import canonical_receipt_bytes
from codex_plugin_scanner.guard.store import GuardStore


def _test_request_digest(harness: str, payload: object, workspace: object) -> str:
    semantic = dict(payload) if isinstance(payload, dict) else payload
    if isinstance(semantic, dict):
        for key in (
            "event",
            "eventName",
            "hook_event_name",
            "hookEventName",
            "hook_name",
            "hookName",
            "timestamp",
            "timestamp_ms",
            "timestampMs",
            "created_at",
            "createdAt",
            "received_at",
            "receivedAt",
        ):
            semantic.pop(key, None)
    encoded = json.dumps(
        {"harness": harness, "payload": semantic, "workspace": str(workspace) if workspace is not None else None},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _bound_review_evidence(
    *,
    harness: str,
    payload: dict[str, object],
    workspace: Path | None,
    native_result: dict[str, object],
) -> tuple[dict[str, object], dict[str, object]]:
    """Attach the current verified native command-policy domain to a test review."""

    from .test_native_command_observations import _observations

    result = copy.deepcopy(native_result)
    observations = _observations()
    result["command_extensions"] = observations
    result.setdefault("decision", "deny")
    result.setdefault("policy_action", "review")
    result.setdefault("minimum_action", result["policy_action"])
    result.setdefault("reason_code", "native_pre_tool_unknown_review")
    result.setdefault("reason", "HOL Guard requires review for this bounded action.")

    digest = _test_request_digest(harness, payload, workspace)
    receipt: dict[str, object] = {
        "schema": "guard-native-hook-decision-receipt.v1",
        "version": 1,
        "authority": "rust",
        "decision_id": "0" * 64,
        "request_id": f"sha256:{digest}",
        "request_digest": digest,
        "harness": harness,
        "event_name": "PreToolUse",
        "payload_kind": "inline",
        "policy_generation": 1,
        "policy_digest": "a" * 64,
        "rule_digest": "b" * 64,
        "runtime_identity": "c" * 64,
        "decision": result["decision"],
        "model_output_action": "not_applicable",
        "policy_action": result["policy_action"],
        "observed_policy_action": result.get("observed_policy_action"),
        "reason_code": result["reason_code"],
        "workspace_bound": workspace is not None,
        "source_ref_external_allowed": False,
        "reviewed_output_sha256": result.get("reviewed_output_sha256"),
        "observe_mode": result.get("observe_mode") is True,
        "deadline_budget_ms": None,
        "command_extensions": copy.deepcopy(observations["binding"]),
    }
    receipt["decision_id"] = hashlib.sha256(canonical_receipt_bytes(receipt)).hexdigest()
    return result, receipt


def _worker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    edge: dict[str, object],
    *,
    publish_native_policy: bool = True,
) -> tuple[HookWorker, GuardStore]:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.native_mode",
        lambda: "auto",
    )

    def review_raw_hook_native(*_args: object, **kwargs: object) -> dict[str, object]:
        rendered = copy.deepcopy(edge)
        result = rendered["result"]
        assert isinstance(result, dict)
        if "receipt" in rendered or "command_extensions" in result:
            return rendered
        from .test_native_command_observations import _observations

        harness = str(rendered["harness"])
        workspace = kwargs.get("cwd")
        digest = _test_request_digest(harness, kwargs.get("payload"), workspace)
        observations = _observations()
        result["command_extensions"] = observations
        receipt = {
            "schema": "guard-native-hook-decision-receipt.v1",
            "version": 1,
            "authority": "rust",
            "decision_id": "0" * 64,
            "request_id": f"sha256:{digest}",
            "request_digest": digest,
            "harness": harness,
            "event_name": "PreToolUse",
            "payload_kind": "inline",
            "policy_generation": 1,
            "policy_digest": "a" * 64,
            "rule_digest": "b" * 64,
            "runtime_identity": "c" * 64,
            "decision": result["decision"],
            "model_output_action": "not_applicable",
            "policy_action": result["policy_action"],
            "observed_policy_action": None,
            "reason_code": result["reason_code"],
            "workspace_bound": workspace is not None,
            "source_ref_external_allowed": False,
            "reviewed_output_sha256": None,
            "observe_mode": False,
            "deadline_budget_ms": None,
            "command_extensions": copy.deepcopy(observations["binding"]),
        }
        receipt["decision_id"] = hashlib.sha256(canonical_receipt_bytes(receipt)).hexdigest()
        rendered["receipt"] = receipt
        return rendered

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_raw_hook_native",
        review_raw_hook_native,
    )
    store = GuardStore(tmp_path / "guard-home")
    store.upsert_runtime_state(
        session_id="native-review",
        daemon_host="127.0.0.1",
        daemon_port=4781,
        started_at="2026-09-05T00:00:00+00:00",
        last_heartbeat_at="2026-09-05T00:00:00+00:00",
    )
    return HookWorker(store=store, publish_native_policy=publish_native_policy), store
