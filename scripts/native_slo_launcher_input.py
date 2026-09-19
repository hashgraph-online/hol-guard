"""Frozen malformed stdin contracts through all four installed priority argv.

Use an otherwise idle DaemonFixture(runtime, setup="normal"). Unknown empty
inputs reach native review; a real controlled block releases browser waiters.
No availability continuation or launcher-only rejection counts as native allow.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from codex_plugin_scanner.guard.codex_hook_launch_runtime import run_isolated_hook_process
from scripts.native_probe_receipts import wait_for_route_corpus
from scripts.native_slo_adapter import route_counts
from scripts.native_slo_contract import assert_privacy_safe, clear_proof_environment
from scripts.native_slo_daemon_fixture import DaemonFixture, witnessed_route
from scripts.native_slo_priority_launchers import (
    LauncherSession,
    RegisteredLauncher,
    install_priority_launchers,
    registered_launcher,
)
from scripts.native_slo_registered_surfaces_evidence import SurfaceAttempt, SurfaceEvidence

INPUT_LIMIT = 1_000_000
_PROCESS_SECONDS = 10.0
_OUTPUT_LIMIT = 2 * 1024 * 1024
_KINDS = ("invalid_ascii_json", "nonobject_json", "empty", "oversize")
_ROUTES = frozenset((h, e) for h in ("codex", "claude-code") for e in ("PreToolUse", "PostToolUse"))
_UNKNOWN_REASON = "HOL Guard requires review because this PreToolUse action is not yet supported for automatic allow."
_SIZE_REASON = "HOL Guard blocked this action because hook input exceeded the safe size limit."
_CODEX_UNAVAILABLE_REASON = (
    "HOL Guard could not authenticate the local daemon. Run `hol-guard daemon repair`, then retry."
)
_CLAUDE_INVALID_REASON = (
    'HOL Guard could not reach the local daemon (daemon returned HTTP 400: {"error": "invalid_request_body"}; '
    "fallback exited 2) and continued this action without native review."
)


@dataclass(frozen=True, slots=True)
class InputCase:
    harness: str
    registration_event: str
    kind: str
    stdin: str

    @property
    def case_id(self) -> str:
        return f"input/{self.harness}/{self.registration_event}/{self.kind}"

    @property
    def requires_review(self) -> bool:
        return self.kind in {"empty", "nonobject_json"}

    @property
    def expected_route(self) -> str:
        return "native_resident" if self.requires_review else "engine_bypassed"

    @property
    def delivery(self) -> str:
        if self.requires_review:
            return "review_ask" if self.harness == "claude-code" else "review_deny"
        return "launcher_limit_block" if self.kind == "oversize" else "availability_continuation"


def input_cases(launcher: RegisteredLauncher) -> tuple[InputCase, ...]:
    """Inputs are fixed independently of the production parser/renderers."""
    if (launcher.harness, launcher.event) not in _ROUTES:
        raise ValueError("priority_launcher_input_route_unsupported")
    prefix = '{"hook_event_name":"' + launcher.event + '","tool_name":'
    raw = {
        "invalid_ascii_json": prefix,
        "nonobject_json": "[]",
        "empty": "",
        # Truncate inside the padding. Claude recovers the event from its prefix;
        # Codex's pre-parse size branch always emits a PreToolUse denial.
        "oversize": prefix + '"' + "x" * (INPUT_LIMIT - len(prefix)),
    }
    return tuple(InputCase(launcher.harness, launcher.event, kind, raw[kind]) for kind in _KINDS)


def _exact(actual: Mapping[str, object], wanted: Mapping[str, object]) -> None:
    # JSON equality is type strict for booleans/numbers, unlike Python dict ==.
    if json.dumps(actual, sort_keys=True, allow_nan=False) != json.dumps(wanted, sort_keys=True, allow_nan=False):
        raise RuntimeError("priority_launcher_input_stdout_contract")


def _permission(decision: str, reason: str, *, continuation: bool = False) -> dict[str, object]:
    result: dict[str, object] = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }
    if continuation:
        result["continue"] = True
    return result


def _review_stdout(case: InputCase, response: Mapping[str, object], approval: Mapping[str, object], port: int) -> None:
    request_id = approval.get("request_id")
    if not isinstance(request_id, str) or re.fullmatch(r"[a-f0-9]{32}", request_id) is None:
        raise RuntimeError("priority_launcher_input_review_identity")
    url = f"http://127.0.0.1:{port}/requests/{request_id}"
    specific = response.get("hookSpecificOutput")
    reason = specific.get("permissionDecisionReason") if isinstance(specific, Mapping) else None
    prefix = _UNKNOWN_REASON + " Open HOL Guard to approve or keep this blocked: "
    pattern = re.escape(prefix + url) + r"(?:#guard-token=[A-Za-z0-9_~%+.\-]+)?\."
    if not isinstance(reason, str) or re.fullmatch(pattern, reason) is None:
        raise RuntimeError("priority_launcher_input_review_reason")
    expected = _permission("ask" if case.harness == "claude-code" else "deny", reason)
    if case.harness == "claude-code":
        expected.update(
            policy_action="review",
            reason_code="native_pre_tool_unknown_review",
            reason=reason,
            approval_url=url,
            approval_request_id=request_id,
            primary_approval_request_id=request_id,
            primary_approval_url=url,
            guardApprovalRequestId=request_id,
            guardApprovalUrl=url,
            approval_requests=[{"request_id": request_id, "approval_url": url}],
            prompted=True,
            approval_center_url=f"http://127.0.0.1:{port}",
        )
    _exact(response, expected)


def validate_input_delivery(
    case: InputCase,
    response: Mapping[str, object],
    *,
    approval: Mapping[str, object] | None = None,
    port: int = 0,
) -> None:
    """Freeze complete JSON shape/content; only exact local review IDs vary."""
    if case.requires_review:
        if approval is None or type(port) is not int or not 1 <= port <= 65535:
            raise RuntimeError("priority_launcher_input_review_evidence_missing")
        _review_stdout(case, response, approval, port)
    elif case.kind == "oversize":
        if case.harness == "codex":
            expected = _permission("deny", _CODEX_UNAVAILABLE_REASON)
        elif case.registration_event == "PostToolUse":
            expected = {
                "decision": "block",
                "reason": _SIZE_REASON,
                "hookSpecificOutput": {"hookEventName": "PostToolUse"},
            }
        else:
            expected = {**_permission("deny", _SIZE_REASON), "systemMessage": _SIZE_REASON}
        _exact(response, expected)
    elif case.kind == "invalid_ascii_json":
        reason = _CLAUDE_INVALID_REASON if case.harness == "claude-code" else _CODEX_UNAVAILABLE_REASON
        expected = (
            {}
            if case.harness == "claude-code" and case.registration_event == "PostToolUse"
            else _permission("allow", reason, continuation=True)
        )
        _exact(response, expected)
    else:
        raise ValueError("priority_launcher_input_case_unsupported")


def _block_resolution(session: DaemonFixture, operation_id: str) -> Mapping[str, object]:
    deadline = time.monotonic() + 1.0
    while True:
        result = session.control("launcher_approval_result", operation_id=operation_id)
        if result.get("state") != "waiting":
            break
        if time.monotonic() >= deadline:
            raise TimeoutError("priority_launcher_input_resolution_deadline")
        time.sleep(0.01)
    if (
        result.get("state") != "resolved"
        or result.get("resolution") != "block"
        or result.get("approval_durable") is not True
        or result.get("authority") != "ordinary_local_review"
        or result.get("matching") != "exact_identity_and_new_row"
    ):
        raise RuntimeError("priority_launcher_input_resolution_unproven")
    # We require a real resolved block, not an allow-consumption or successful
    # suspended-resume claim. Legacy and candidate continuation capabilities differ.
    return result


def _validate_witness(case: InputCase, evidence: Mapping[str, object], route: str) -> None:
    setup = evidence.get("setup")
    if (
        not isinstance(setup, Mapping)
        or any(
            setup.get(field) is not True
            for field in ("isolated_store", "effective_policy_allow", "policy_ack_current", "python_oracle_disabled")
        )
        or setup.get("fault_scope") != "none"
    ):
        raise RuntimeError("priority_launcher_input_setup_unproven")
    if route != case.expected_route:
        raise RuntimeError("priority_launcher_input_route_mismatch")
    native = evidence.get("native_result")
    if not case.requires_review:
        if native is not None:
            raise RuntimeError("priority_launcher_input_unexpected_native_work")
        return
    wanted = {
        "authority": "rust",
        "decision": "deny",
        "policy_action": "review",
        "minimum_action": "review",
        "reason_code": "native_pre_tool_unknown_review",
        "reason": _UNKNOWN_REASON,
        "explicitly_benign": False,
    }
    if not isinstance(native, Mapping) or any(
        type(native.get(k)) is not type(v) or native.get(k) != v for k, v in wanted.items()
    ):
        raise RuntimeError("priority_launcher_input_native_review_unproven")
    action = native.get("action")
    if not isinstance(action, Mapping) or any(
        action.get(k) != v
        for k, v in {"harness": case.harness, "event": "PreToolUse", "action_type": "unknown"}.items()
    ):
        raise RuntimeError("priority_launcher_input_native_action_mismatch")


def _run_case(
    session: DaemonFixture, launcher: RegisteredLauncher, case: InputCase, attempt: SurfaceAttempt
) -> dict[str, object]:
    attempt.stage = "registration"
    if registered_launcher(launcher.config_path, launcher.harness, launcher.event) != launcher:
        raise RuntimeError("priority_launcher_input_registration_changed")
    environment = dict(os.environ)
    clear_proof_environment(environment)
    configured = dict(launcher.environment)
    if clear_proof_environment(configured):
        raise RuntimeError("priority_launcher_input_registration_override")
    environment.update(configured)
    environment["HOME"] = environment["USERPROFILE"] = str(session.root)
    if launcher.harness == "codex":
        environment["CODEX_HOME"] = str(session.root / ".codex")
    attempt.stage = "setup"
    session.control("case_before")
    metrics = session.daemon._server.hook_worker.metrics
    before = route_counts(metrics.snapshot())
    operation_id: str | None = None
    if case.requires_review:
        begun = session.control(
            "launcher_approval_begin", harness=case.harness, payload={}, resolution="block", timeout_seconds=8
        )
        begun_id = begun.get("operation_id")
        if begun.get("state") != "waiting" or not isinstance(begun_id, str):
            raise RuntimeError("priority_launcher_input_resolution_setup")
        operation_id = begun_id
    attempt.stage = "process"
    started = time.perf_counter()
    result = run_isolated_hook_process(
        launcher.argv,
        input_text=case.stdin,
        cwd=session.workspace,
        environment=environment,
        timeout_seconds=_PROCESS_SECONDS,
        output_limit=_OUTPUT_LIMIT,
    )
    elapsed_ms = (time.perf_counter() - started) * 1000
    attempt.attempted_exit = result.returncode
    if result.returncode != 0 or result.timed_out or result.containment_failed or result.output_limit_exceeded:
        raise RuntimeError("priority_launcher_input_process_contract")
    attempt.stage = "readback_after"
    if registered_launcher(launcher.config_path, launcher.harness, launcher.event) != launcher:
        raise RuntimeError("priority_launcher_input_registration_changed")
    attempt.stage = "route"
    snapshot = (
        wait_for_route_corpus(metrics, expected=sum(before.values()) + 1)
        if case.requires_review
        else metrics.snapshot()
    )
    after = route_counts(snapshot)
    route = witnessed_route(before, after)
    attempt.route = route
    attempt.stage = "witness"
    evidence = session.control("case_result")
    try:
        _validate_witness(case, evidence, route)
    except Exception as error:
        from scripts.native_slo_surface_failure import enrich_surface_failure

        enriched = enrich_surface_failure(
            error,
            case_id=case.case_id,
            registration_digest=launcher.registration_sha256,
            stage=attempt.stage,
            expected_route=case.expected_route,
            observed_route=route,
            routes_before=before,
            routes_after=after,
            evidence=evidence,
        )
        if enriched is error:
            raise
        raise enriched from error
    approval = _block_resolution(session, operation_id) if operation_id is not None else None
    attempt.stage = "delivery"
    try:
        response: object = json.loads(result.stdout)
    except (ValueError, UnicodeDecodeError) as error:
        raise RuntimeError("priority_launcher_input_stdout_invalid_json") from error
    if not isinstance(response, Mapping):
        raise RuntimeError("priority_launcher_input_stdout_invalid_object")
    validate_input_delivery(case, cast(Mapping[str, object], response), approval=approval, port=session.daemon.port)
    attempt.stage = "complete"
    return {
        "harness": case.harness,
        "registration_event": case.registration_event,
        "case": case.kind,
        "route": route,
        "delivery": case.delivery,
        "elapsed_ms": elapsed_ms,
        "input_bytes": len(case.stdin.encode("utf-8")),
        "controlled_block": approval is not None,
    }


def run_registered_input_corpus(session: DaemonFixture, *, evidence_file: Path) -> dict[str, object]:
    """Run exactly 16 source-derived contracts; first failure retains evidence."""
    observations: list[dict[str, object]] = []
    with SurfaceEvidence(evidence_file) as journal:
        launchers = install_priority_launchers(cast(LauncherSession, cast(object, session)))
        if len(launchers) != 4 or {(item.harness, item.event) for item in launchers} != _ROUTES:
            raise RuntimeError("priority_launcher_input_registration_incomplete")
        for launcher in launchers:
            for case in input_cases(launcher):
                journal.offer(case.case_id, launcher.registration_sha256)
                attempt = SurfaceAttempt()
                try:
                    observation = _run_case(session, launcher, case, attempt)
                except BaseException:
                    journal.finish("failed", attempt)
                    raise
                journal.finish("completed", attempt)
                observations.append(observation)
    if len(observations) != 16:
        raise RuntimeError("priority_launcher_input_incomplete")
    return assert_privacy_safe(
        {
            "schema": "hol-guard.registered-launcher-input.v1",
            "boundary": "INSTALLED_LAUNCHER",
            "validated_cases": len(observations),
            "configuration": "registered_argv_and_env",
            "case_digest": hashlib.sha256(
                json.dumps([(o["harness"], o["registration_event"], o["case"]) for o in observations]).encode()
            ).hexdigest(),
            "coverage": {
                key: dict(Counter(str(row[key]) for row in observations))
                for key in ("harness", "registration_event", "case", "route", "delivery")
            },
            "observations": observations,
            "stdout_and_exit_checked": True,
            "native_and_delivered_checked_independently": True,
            "implemented_scope_passed": True,
            "qualification_complete": False,
            "latency_claim": "semantic_preflight_no_tail_claim",
            "native_allow_count": 0,
            "limits": {
                "stdin_bytes": INPUT_LIMIT + 1,
                "stdout_bytes": _OUTPUT_LIMIT,
                "process_seconds": _PROCESS_SECONDS,
            },
            "remaining": ["invalid_utf8_raw_bytes", "all_platform_execution", "native_v3_v4_approval_api"],
        }
    )
