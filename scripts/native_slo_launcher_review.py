"""Witness actual local approval resolution and Codex live-hook completion.

The private fixture observes the production completion function; it never
substitutes its result or constructs continuation/approval authority.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Mapping
from contextlib import ExitStack
from dataclasses import replace
from importlib import import_module
from typing import Any
from unittest.mock import patch

from scripts.native_slo_adapter import route_counts
from scripts.native_slo_contract import assert_privacy_safe
from scripts.native_slo_failure import failure_evidence
from scripts.native_slo_launcher_approval import LauncherApprovalControl
from scripts.native_slo_workloads import ExpectedResponse, QualificationCase


def approved_review_case(case: QualificationCase) -> QualificationCase:
    """Freeze the current launcher delivery; the native expectation stays review."""
    if case.event != "PreToolUse" or case.expected.reason_class != "review":
        raise ValueError("launcher review case is not an initial review")
    if case.harness == "codex":
        expected = ExpectedResponse(
            "implicit_allow",
            "not_applicable",
            "approved_review",
            {"hookSpecificOutput.hookEventName": "PreToolUse"},
        )
    elif case.harness == "claude-code":
        expected = ExpectedResponse(
            "allow",
            "not_applicable",
            "approved_review",
            {
                "continue": True,
                "policy_action": "allow",
                "reason_code": case.expected.reason_code,
                "hookSpecificOutput.hookEventName": "PreToolUse",
                "hookSpecificOutput.permissionDecision": "allow",
                "approval_reuse_status": "accepted",
            },
        )
    else:
        raise ValueError("launcher review harness unsupported")
    return replace(case, expected=expected)


class LauncherReviewFixture:
    """Bounded sibling control state for one private daemon fixture."""

    def __init__(self, session: Any, *, before_resolve: Callable[[str], None] | None = None) -> None:
        self.session = session
        self.controller = LauncherApprovalControl(session, before_resolve=before_resolve)
        self._fault_fixture: Any = None
        self._before: dict[str, dict[str, int]] = {}
        self._native_before: dict[str, int] = {}
        self._completions: list[dict[str, object]] = []
        self._native_evaluations: list[dict[str, object]] = []
        self._overflow = False
        self._witness_lock = threading.Lock()
        self._patch: ExitStack | None = None

    def _runner_routes(self) -> dict[str, int]:
        return dict(route_counts(self.session.daemon._server.hook_process_runner.stats()))

    def _capture_completion(self) -> None:
        if self._patch is not None:
            return
        from codex_plugin_scanner.guard.daemon import server

        def observe_completion(original: Any) -> Any:
            def observed(*args: Any, **kwargs: Any) -> dict[str, object]:
                result = original(*args, **kwargs)
                with self._witness_lock:
                    if len(self._completions) >= 128:
                        self._overflow = True
                    else:
                        self._completions.append(
                            {
                                "request_id": kwargs.get("request_id"),
                                "completed": result.get("completed") is True,
                                "action": result.get("action"),
                                "replayed": result.get("replayed") is True,
                                "error": result.get("error"),
                                "fresh_allow_authorized": kwargs.get("fresh_allow_authorized") is True,
                            }
                        )
                return result

            return observed

        worker = self.session.daemon._server.hook_worker
        original_native = worker._review_raw_hook_native

        def observe_native(**kwargs: Any) -> Any:
            edge = original_native(**kwargs)
            result = edge.get("result") if isinstance(edge, Mapping) else None
            witness: dict[str, object] = (
                {key: result.get(key) for key in ("decision", "policy_action", "minimum_action", "reason_code")}
                if isinstance(result, Mapping)
                else {"available": False}
            )
            with self._witness_lock:
                if len(self._native_evaluations) >= 128:
                    self._overflow = True
                else:
                    self._native_evaluations.append(witness)
            return edge

        with ExitStack() as stack:
            stack.enter_context(patch.object(worker, "_review_raw_hook_native", observe_native))
            stack.enter_context(
                patch.object(
                    server, "complete_codex_live_decision", observe_completion(server.complete_codex_live_decision)
                )
            )
            module_name = "codex_plugin_scanner.guard.daemon.codex_native_live_decision"
            try:
                native_completion = import_module(module_name)
            except ModuleNotFoundError as error:
                if error.name != module_name:
                    raise
            else:
                stack.enter_context(
                    patch.object(
                        native_completion,
                        "complete_codex_live_decision",
                        observe_completion(native_completion.complete_codex_live_decision),
                    )
                )
            self._patch = stack.pop_all()

    def dispatch(self, operation: str, request: Mapping[str, Any]) -> dict[str, object]:
        try:
            if operation in {"launcher_approval_fault_begin", "launcher_approval_fault_result"}:
                if self._fault_fixture is None:
                    from scripts.native_slo_approval_fault_fixture import LauncherApprovalFaultFixture

                    self._fault_fixture = LauncherApprovalFaultFixture(self.session)
                return self._fault_fixture.dispatch(operation, request)
            if operation == "launcher_approval_begin":
                payload = request.get("payload")
                if not isinstance(payload, Mapping):
                    raise ValueError("qualification launcher review payload missing")
                self._capture_completion()
                before = self._runner_routes()
                with self._witness_lock:
                    native_before = len(self._native_evaluations)
                result = self.controller.begin(
                    str(request.get("harness")),
                    payload,
                    resolution=str(request.get("resolution", "allow")),
                    timeout_seconds=request.get("timeout_seconds", 8),
                )
                self._before[str(result["operation_id"])] = before
                self._native_before[str(result["operation_id"])] = native_before
                return result
            if operation != "launcher_approval_result":
                raise ValueError("qualification launcher review operation unsupported")
            operation_id = str(request.get("operation_id"))
            result = self.controller.result(operation_id)
            if result.get("state") == "waiting":
                return result
            before = self._before[operation_id]
            after = self._runner_routes()
            delta = {name: after.get(name, 0) - before.get(name, 0) for name in set(before) | set(after)}
            request_id = result.get("request_id")
            with self._witness_lock:
                if self._overflow or any(value < 0 for value in delta.values()):
                    raise RuntimeError("qualification launcher review witness invalid")
                completions = [dict(item) for item in self._completions if item["request_id"] == request_id]
                native_evaluations = [
                    dict(item) for item in self._native_evaluations[self._native_before[operation_id] :]
                ]
            row = self.session.store.get_approval_request(request_id) if isinstance(request_id, str) else None
            resume = self.session.store.get_request_resume(request_id) if isinstance(request_id, str) else None
            continuation = row.get("continuation_snapshot") if isinstance(row, Mapping) else None
            return assert_privacy_safe(
                {
                    **result,
                    "live_decision": completions,
                    "native_evaluations": native_evaluations,
                    "revalidation_routes": {name: value for name, value in delta.items() if value},
                    "continuation_status": resume.get("status", "absent") if isinstance(resume, Mapping) else "absent",
                    "continuation_capability": continuation.get("capability", "absent")
                    if isinstance(continuation, Mapping)
                    else "absent",
                }
            )
        except Exception as error:
            return {"state": "failed", "failure": failure_evidence(error)}

    def close(self) -> None:
        try:
            try:
                if self._fault_fixture is not None:
                    self._fault_fixture.close()
            finally:
                self.controller.close()
        finally:
            if self._patch is not None:
                self._patch.close()
                self._patch = None


def await_resolution(session: Any, operation_id: str, *, timeout_seconds: float = 1.0) -> Mapping[str, object]:
    deadline = time.monotonic() + timeout_seconds
    while True:
        result = session.control("launcher_approval_result", operation_id=operation_id)
        if result.get("state") != "waiting":
            return result
        if time.monotonic() >= deadline:
            raise TimeoutError("qualification launcher review resolution deadline")
        time.sleep(0.01)


def validate_resolution(result: Mapping[str, object], *, harness: str) -> None:
    if (
        result.get("state") != "resolved"
        or result.get("resolution") != "allow"
        or result.get("approval_durable") is not True
        or result.get("authority") != "ordinary_local_review"
        or result.get("matching") != "exact_identity_and_new_row"
        or result.get("binding_present") is not True
    ):
        raise RuntimeError("qualification launcher review resolution unproven")
    if harness == "claude-code":
        routes = result.get("revalidation_routes")
        if result.get("live_decision") or not isinstance(routes, Mapping) or any(routes.values()):
            raise RuntimeError("qualification Claude review continuation was unexpected")
        return
    completions = result.get("live_decision")
    native_evaluations = result.get("native_evaluations")
    if (
        harness != "codex"
        or not isinstance(completions, list)
        or len(completions) != 1
        or not isinstance(completions[0], Mapping)
        or completions[0].get("completed") is not True
        or completions[0].get("fresh_allow_authorized") is not True
        or completions[0].get("replayed") is not False
        or completions[0].get("action") != "allow"
        or result.get("continuation_status") not in {"resumed", "sent"}
        or result.get("continuation_capability") != "suspended-response"
        or result.get("revalidation_routes") != {}
        or not isinstance(native_evaluations, list)
        or len(native_evaluations) != 2
        or any(
            not isinstance(item, Mapping)
            or item.get("decision") != "deny"
            or item.get("policy_action") != "review"
            or item.get("minimum_action") != "review"
            for item in native_evaluations
        )
    ):
        raise RuntimeError("qualification Codex browser continuation unproven")
