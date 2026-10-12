#!/usr/bin/env python3
"""Record Copilot hook settle vectors from the Python implementation.

Run at the commit that still carries the Python Copilot settle logic
(``run_native_copilot_pretool`` / ``run_native_copilot_permission_request``
with their inline action, receipt, activity and response decisions):

    git checkout 9987159fc8 -- src/codex_plugin_scanner/guard/cli/commands_hook_native_copilot.py
    .venv/bin/python scripts/ci/record_hook_copilot_settle_vectors.py

Each vector drives the old function with a stubbed native tool-call decision
and records, in order, every effect it ran (silent review, observe queue,
receipt, command activity, usage, response, approval queue) and its return
value. The resident's ``copilot_settle`` query must name the same effects.
"""

from __future__ import annotations

import argparse
import gzip
import itertools
import json
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from codex_plugin_scanner.guard import approvals as approvals_module  # noqa: E402
from codex_plugin_scanner.guard import blocked_request_mode, native_policy_snapshot_acked  # noqa: E402
from codex_plugin_scanner.guard.cli import commands_hook_native_copilot as copilot  # noqa: E402
from codex_plugin_scanner.guard.mcp_tool_calls import ToolCallDecision  # noqa: E402
from codex_plugin_scanner.guard.models import GuardArtifact  # noqa: E402
from codex_plugin_scanner.guard.tool_decision_evidence import tool_decision_scanner_evidence  # noqa: E402

OUTPUT = ROOT / "rust/crates/guard-runtime/tests/fixtures/hook_copilot_settle_vectors.json.gz"
ENVELOPE = {"action_type": "tool_call", "tool": "fs.write"}
ACTIONS = ("allow", "warn", "review", "require-reapproval", "sandbox-required", "block")
REUSE = (
    (None, None, None, None),
    ("accepted", "approval_reuse_accepted", "review", "allow"),
    ("rejected", "approval_reuse_current_block", "block", "allow"),
    ("rejected", "approval_reuse_no_saved_decision", "review", None),
    ("rejected", "approval_reuse_saved_block", "review", "block"),
    ("not-applicable", None, None, None),
)
EDGES = (
    None,
    {"policy_action": "block"},
    {"minimum_action": "sandbox-required"},
    {"decision": "deny"},
    {"policy_action": "bogus"},
    {"policy_action": "review", "decision": "deny"},
    {"policy_action": "", "minimum_action": "block"},
)
# (recording_only, posture override is watch, acknowledged snapshot records only)
RECORDING = ((False, False, False), (True, False, False), (True, True, False), (True, True, True))
SUMMARIES = (
    "Tool call writes outside the workspace.",
    "Guard flagged the tool call.",
    "Open HOL Guard to approve or keep this blocked: https://g.test/a#guard-token=abc.def",
)


def _artifact(index: int) -> GuardArtifact:
    return GuardArtifact(
        artifact_id=f"copilot:mcp:server:tool-{index % 3}",
        name=("fs.write", "Guard shell", "approve-me")[index % 3],
        harness="copilot",
        artifact_type="tool_call",
        source_scope=("project", "global")[index % 2],
        config_path="/w/.copilot/mcp.json",
        command=None if index % 4 == 0 else "node server.js",
    )


def _decision(action: str, reuse: tuple[Any, ...], normalized: bool, summary: str, index: int) -> ToolCallDecision:
    status, reason_code, current, saved = reuse
    return ToolCallDecision(
        action=action,  # type: ignore[arg-type]
        source=("policy", "inline-approved", "approval-center")[index % 3],
        signals=(("writes_files",), (), ("network", "secrets"))[index % 3],
        summary=summary,
        risk_categories=("filesystem",),
        normalization_reason_code="guard_action_unknown" if normalized else None,
        original_action="bogus" if normalized else None,
        approval_reuse_status=status,
        approval_reuse_reason_code=reason_code,
        current_action=current,
        saved_action=saved,
    )


def _record(stage: str, case: dict[str, Any], index: int) -> dict[str, Any]:
    recording_only, posture_watch, acked = case["recording"]
    artifact = _artifact(index)
    arguments = None if index % 5 == 0 else {"path": f"/w/file-{index % 7}.txt", "mode": "w"}
    decision = _decision(case["action"], case["reuse"], case["normalized"], case["summary"], index)
    effects: list[dict[str, Any]] = []
    acked_queried: list[bool] = []
    receipt_ids = itertools.count(1)

    def receipt(verdict: str):
        def run(**kwargs: Any) -> Any:
            effects.append(
                {
                    "effect": "receipt",
                    "verdict": verdict,
                    "decision_source": kwargs["decision_source"],
                    "policy_action": kwargs["policy_action"],
                    "remember": kwargs.get("remember"),
                    "scanner_evidence": list(kwargs["additional_scanner_evidence"]),
                }
            )
            return SimpleNamespace(receipt_id=f"receipt-{next(receipt_ids)}")

        return run

    def activity(**kwargs: Any) -> None:
        effects.append(
            {
                "effect": "activity",
                "event": kwargs["event"],
                "policy_action": kwargs["policy_action"],
                "prompted": kwargs["prompted"],
                "reuse_status": kwargs["approval_reuse_status"].value,
            }
        )

    def observe(**kwargs: Any) -> None:
        effects.append(
            {
                "effect": "observe_queue",
                "executable_action": kwargs["executable_action"],
                "observed_policy_action": kwargs["observed_policy_action"],
                "changed_fields": list(kwargs["changed_fields"]),
                "risk_summary": kwargs["risk_summary"],
                "scanner_evidence": list(kwargs["scanner_evidence"]),
            }
        )

    def silent_review(**kwargs: Any) -> None:
        effects.append({"effect": "silent_review", "artifact": kwargs["evaluation"]["artifacts"][0]})

    def usage(**kwargs: Any) -> None:
        effects.append({"effect": "usage", "policy_action": kwargs["policy_action"]})

    def acked_snapshot(_store: object, harness: str) -> bool:
        acked_queried.append(True)
        return acked

    def permission_response(**kwargs: Any) -> None:
        effects.append(
            {
                "effect": "permission_response",
                "behavior": kwargs["behavior"],
                "message": kwargs.get("message"),
                "interrupt": kwargs.get("interrupt"),
                "approval_reuse": kwargs.get("approval_reuse"),
                "scanner_evidence": list(kwargs.get("scanner_evidence", ())),
            }
        )

    queue: dict[str, Any] = {}

    class _Client:
        def start_session(self, **_kwargs: Any) -> dict[str, str]:
            return {"session_id": "s1"}

        def queue_blocked_operation(self, **kwargs: Any) -> dict[str, Any]:
            queue["evaluation_artifact"] = kwargs["evaluation"]["artifacts"][0]
            return {}

    def bind(**kwargs: Any) -> list[object]:
        queue["response_payload"] = dict(kwargs["response_payload"])
        return []

    original_reason = copilot._copilot_hook_reason

    def copilot_reason(*values: object) -> str:
        if values and values[-1] == "<review-context>":
            queue["deny_reason"] = values[0]
        return original_reason(*values)

    patches: dict[tuple[object, str], object] = {
        (copilot, "evaluate_tool_call"): lambda **_kwargs: decision,
        (copilot, "allow_tool_call"): receipt("allow"),
        (copilot, "block_tool_call"): receipt("block"),
        (copilot, "record_pre_hook_command_activity_best_effort"): activity,
        (copilot, "queue_observe_mode_request"): observe,
        (copilot, "_record_harness_usage_for_hook"): usage,
        (copilot, "harness_is_recording_only"): lambda _config, _harness: recording_only,
        (copilot, "harness_posture_override"): lambda _config, _harness: "watch" if posture_watch else None,
        (copilot, "_action_envelope_json"): lambda _envelope: dict(ENVELOPE) if index % 2 else None,
        (copilot, "_runtime_detection"): lambda *_args: SimpleNamespace(to_dict=lambda: {}),
        (copilot, "_emit_copilot_permission_request_response"): permission_response,
        (copilot, "_copilot_hook_reason"): copilot_reason,
        (copilot, "schedule_guard_daemon_ensure"): lambda *_args, **_kwargs: "http://127.0.0.1:1/approvals",
        (copilot, "get_adapter"): lambda _harness: SimpleNamespace(approval_flow=lambda **_kwargs: None),
        (copilot, "_codex_browser_wait_metadata"): lambda **_kwargs: {},
        (copilot, "_hook_command_text"): lambda _payload: None,
        (copilot, "capture_retry_lineage"): lambda *_args, **_kwargs: None,
        (copilot, "load_guard_surface_daemon_client"): lambda _home: _Client(),
        (copilot, "_approval_surface_policy_for_flow"): lambda *_args: None,
        (copilot, "_bind_hook_blocked_operation_queue"): bind,
        (copilot, "approval_center_hint"): lambda **_kwargs: None,
        (copilot, "_preferred_approval_review_url"): lambda *_args, **_kwargs: None,
        (copilot, "_localize_pending_approval_copy"): lambda *_args, **_kwargs: None,
        (copilot, "_native_approval_center_context"): lambda *_args, **_kwargs: "<review-context>",
        (blocked_request_mode, "asks_for_approval"): lambda _config: case["asks"],
        (native_policy_snapshot_acked, "recording_only_from_acked_snapshot"): acked_snapshot,
        (approvals_module, "record_unprompted_review"): silent_review,
    }
    saved = {key: getattr(key[0], key[1], None) for key in patches}
    stream = _Stream()
    try:
        for (module, name), value in patches.items():
            setattr(module, name, value)
        config = SimpleNamespace(receipt_redaction_level="standard", approval_surface_policy="auto")
        home = Path(tempfile.gettempdir())
        common = {
            "action_envelope": None,
            "config": config,
            "context": SimpleNamespace(guard_home=home, home_dir=home),
            "output_stream": stream,
            "payload": {"tool_name": "fs.write"},
            "runtime_workspace": None,
            "store": SimpleNamespace(guard_home=home),
        }
        args = argparse.Namespace(harness=case["harness"], json=case["json"])
        if stage == "pre_tool_use":
            result = copilot.run_native_copilot_pretool(
                args,
                copilot_hook_stage="pretooluse",
                copilot_runtime_tool_call=(artifact, "sha256:artifact", arguments),
                native_edge_result=case["edge"],
                **common,
            )
        else:
            result = copilot.run_native_copilot_permission_request(
                args,
                copilot_permission_request=(artifact, "sha256:artifact", arguments),
                guard_home=home,
                managed_install=None,
                **common,
            )
    finally:
        for (module, name), value in saved.items():
            setattr(module, name, value)
    if queue:
        # The approval-queue branch owns its usage and response effects.
        cut = next(i for i, effect in enumerate(effects) if effect["effect"] == "usage")
        effects[cut:] = [{"effect": "queue_approval", **queue}]
    documents = list(stream.documents)
    effects.extend(_pretool_response(document) for document in documents)
    evidence = _final_evidence(effects, list(tool_decision_scanner_evidence(decision)))
    launch = json.dumps(arguments, sort_keys=True) if arguments is not None else artifact.command
    inputs: dict[str, Any] = {
        "stage": stage,
        "harness_is_copilot": case["harness"] == "copilot",
        "decision": {
            "action": decision.action,
            "source": decision.source,
            "summary": decision.summary,
            "signals": list(decision.signals),
            "normalization_reason_code": decision.normalization_reason_code,
            "original_action": decision.original_action,
            "approval_reuse_status": decision.approval_reuse_status,
            "approval_reuse_reason_code": decision.approval_reuse_reason_code,
            "current_action": decision.current_action,
            "saved_action": decision.saved_action,
        },
        "artifact": {
            "artifact_id": artifact.artifact_id,
            "artifact_name": artifact.name,
            "artifact_hash": "sha256:artifact",
            "artifact_type": artifact.artifact_type,
            "source_scope": artifact.source_scope,
            "config_path": artifact.config_path,
            "launch_target": launch,
            "action_envelope_json": dict(ENVELOPE) if index % 2 else None,
            "canonical_harness": "copilot",
        },
        "native_edge": case["edge"],
        "recording_only": recording_only,
        "posture_watch": posture_watch,
        "asks_for_approval": case["asks"],
    }
    if acked_queried:
        inputs["acked_recording_only"] = acked
    return {
        "name": f"{stage}-{index}",
        "inputs": inputs,
        "needs_acked_snapshot": bool(acked_queried),
        "json_requested": case["json"],
        "pretool_documents": documents,
        "expected": {
            "approval_reuse": copilot._copilot_approval_reuse_evidence(decision),
            "scanner_evidence": evidence,
            "effects": effects,
            "exit_code": result,
        },
    }


def _pretool_response(document: dict[str, Any]) -> dict[str, Any]:
    output = document.get("hookSpecificOutput", document)
    return {
        "effect": "pretool_response",
        "permission_decision": output["permissionDecision"],
        "reason": output.get("permissionDecisionReason", ""),
    }


def _final_evidence(effects: list[dict[str, Any]], decision_evidence: list[Any]) -> list[Any]:
    """Every effect sees the same final evidence; strip it from the effects."""

    carried = [effect.pop("scanner_evidence") for effect in effects if "scanner_evidence" in effect]
    for effect in effects:
        effect.pop("approval_reuse", None)
        effect.pop("remember", None)
        if effect["effect"] == "observe_queue":
            effect.pop("risk_summary")
    if not carried:
        return decision_evidence
    assert all(entry == carried[0] for entry in carried), carried
    return carried[0]


class _Stream:
    def __init__(self) -> None:
        self.documents: list[Any] = []

    def write(self, text: str) -> None:
        if text.strip():
            self.documents.append(json.loads(text))

    def flush(self) -> None:
        return None


def _cases() -> list[tuple[str, dict[str, Any]]]:
    cases: list[tuple[str, dict[str, Any]]] = []
    # Pre-tool: every action x reuse x edge, cycling the other axes.
    for n, (action, reuse, edge) in enumerate(itertools.product(ACTIONS, REUSE, EDGES)):
        cases.append(
            (
                "pre_tool_use",
                {
                    "action": action,
                    "reuse": reuse,
                    "edge": edge,
                    "recording": RECORDING[n % 4],
                    "asks": n % 3 == 0,
                    "harness": "copilot" if n % 5 else "cursor",
                    "json": n % 2 == 1,
                    "normalized": n % 11 == 0,
                    "summary": SUMMARIES[n % 3],
                },
            )
        )
    # Pre-tool: every action x recording x asks x harness x json, cycling the rest.
    for n, (action, recording, asks, harness, as_json) in enumerate(
        itertools.product(ACTIONS, RECORDING, (False, True), ("copilot", "cursor"), (False, True))
    ):
        cases.append(
            (
                "pre_tool_use",
                {
                    "action": action,
                    "reuse": REUSE[n % len(REUSE)],
                    "edge": EDGES[(n // 2) % len(EDGES)],
                    "recording": recording,
                    "asks": asks,
                    "harness": harness,
                    "json": as_json,
                    "normalized": n % 7 == 0,
                    "summary": SUMMARIES[n % 3],
                },
            )
        )
    # Permission request: every action x reuse x recording x asks.
    for n, (action, reuse, recording, asks) in enumerate(
        itertools.product(ACTIONS, REUSE, ((False, False, False), (True, False, False)), (False, True))
    ):
        cases.append(
            (
                "permission_request",
                {
                    "action": action,
                    "reuse": reuse,
                    "edge": None,
                    "recording": recording,
                    "asks": asks,
                    "harness": "copilot",
                    "json": False,
                    "normalized": n % 7 == 0,
                    "summary": SUMMARIES[n % 3],
                },
            )
        )
    return cases


def main() -> int:
    vectors = [_record(stage, case, index) for index, (stage, case) in enumerate(_cases())]
    document = {"schema": "guard-hook-copilot-settle-vectors.v1", "vectors": vectors}
    raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    OUTPUT.write_bytes(gzip.compress(raw, mtime=0))
    print(f"wrote {len(vectors)} vectors to {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
