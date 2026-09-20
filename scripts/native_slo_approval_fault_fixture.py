"""Private fault controls around actual installed Codex approval completion.

Only timing and transport delivery are injected. The original registered hook,
local approval API, native evaluator, receipt writer, and consume transaction
remain the production implementations. No reviewed tool is executed here.
"""

from __future__ import annotations

import hashlib
import json
import socket
import threading
import time
from collections.abc import Mapping
from contextlib import ExitStack, suppress
from datetime import datetime, timezone
from importlib import import_module
from typing import Any
from unittest.mock import patch
from urllib.parse import urlsplit

from scripts.native_slo_adapter import route_counts
from scripts.native_slo_contract import assert_privacy_safe
from scripts.native_slo_failure import failure_evidence
from scripts.native_slo_launcher_review import LauncherReviewFixture
from scripts.native_slo_mixed_receipt_reader import InstalledReceiptReader
from scripts.native_slo_mixed_server import MixedScenarioFixture

SCENARIOS = (
    "approval_wait_expiry",
    "resident_restart_pending",
    "stricter_policy_pending",
    "ambiguous_completion_retry",
)
_BINDING_FIELDS = ("generation", "policy_digest", "runtime_identity")
_NATIVE_FIELDS = ("decision", "policy_action", "minimum_action", "reason_code")
_RECEIPT_FIELDS = ("decision_id", "request_digest", "policy_generation", "policy_digest", "runtime_identity")
_MAX_WITNESSES = 8
_EXPIRY_WAIT_SECONDS = 2


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _binding(snapshot: object) -> dict[str, object]:
    if not isinstance(snapshot, Mapping) or type(snapshot.get("generation")) is not int:
        raise RuntimeError("qualification_approval_binding_missing")
    if any(not isinstance(snapshot.get(key), str) for key in _BINDING_FIELDS[1:]):
        raise RuntimeError("qualification_approval_binding_missing")
    return {key: snapshot[key] for key in _BINDING_FIELDS}


class LauncherApprovalFaultFixture:
    """One bounded fault and one exact launcher operation per disposable daemon."""

    def __init__(self, session: Any) -> None:
        self.session = session
        self.review = LauncherReviewFixture(session, before_resolve=self._pending)
        self._stack = ExitStack()
        self._lock = threading.RLock()
        self._cancel = threading.Event()
        self._scenario: str | None = None
        self._operation_id: str | None = None
        self._request_id: str | None = None
        self._expiry: datetime | None = None
        self._reader: InstalledReceiptReader | None = None
        self._receipts: list[dict[str, Any] | None] = []
        self._native: list[dict[str, object]] = []
        self._posts: list[dict[str, object]] = []
        self._responses: list[dict[str, object]] = []
        self._fault: dict[str, object] = {"applied": False}
        self._native_completion_available = False
        self._overflow = False
        self._in_flight = 0
        self._drops = 0
        self._routes_before: dict[str, int] = {}

    def _routes(self) -> dict[str, int]:
        return dict(route_counts(self.session.daemon._server.hook_worker.metrics.snapshot()))

    def _append(self, target: list[dict[str, object]], value: dict[str, object]) -> None:
        with self._lock:
            if len(target) >= _MAX_WITNESSES:
                self._overflow = True
            else:
                target.append(value)

    def _pending(self, request_id: str) -> None:
        # The real queue first inserts the request, then attaches the live
        # operation. Wait for that attachment, without inventing its metadata.
        self._request_id = request_id
        deadline = time.monotonic() + 0.4
        operation = None
        while time.monotonic() < deadline:
            operation = self.session.store.get_guard_operation_for_approval_request(request_id)
            if isinstance(operation, Mapping):
                break
            if self._cancel.wait(0.005):
                raise RuntimeError("qualification_approval_fault_cancelled")
        metadata = operation.get("metadata") if isinstance(operation, Mapping) else None
        self._fault["pending_observed"] = self.session.store.get_approval_request(request_id).get("status") == "pending"
        self._fault["original_wait_present"] = isinstance(metadata, Mapping) and isinstance(
            metadata.get("codex_browser_wait_deadline_at"), str
        )
        if self._fault["original_wait_present"] is not True:
            # Older installed arms really lack this capability. Still resolve
            # their real row and retain the observed failed/unsupported result.
            self._fault["unsupported"] = "original_native_wait_unavailable"
            return
        from codex_plugin_scanner.guard.codex_live_hook_target import codex_live_hook_wait_deadline

        assert isinstance(metadata, Mapping) and isinstance(operation, Mapping)
        expiry = codex_live_hook_wait_deadline(self.session.store, operation=operation, metadata=metadata)
        if expiry is None or expiry <= datetime.now(timezone.utc):
            raise RuntimeError("qualification_approval_original_wait_not_live")
        self._expiry = expiry
        worker = self.session.daemon._server.hook_worker
        before = _binding(worker.policy_snapshot_publisher.current_snapshot_binding())
        self._fault.update(binding_before=before, original_wait_live=True)
        if self._scenario == "resident_restart_pending":
            self._fault["containment_attempted"] = True
            self._fault["contained"] = self.session.stop_resident() is True
            if self._fault["contained"] is not True:
                raise RuntimeError("qualification_approval_resident_containment_failed")
            after = MixedScenarioFixture(self.session)._ack("allow", previous_generation=0)
            self._fault.update(applied=True, acknowledged=True, binding_after=_binding(after))
        elif self._scenario == "stricter_policy_pending":
            from codex_plugin_scanner.guard.config import update_guard_settings

            self._fault["mutation_attempted"] = True
            update_guard_settings(self.session.guard_home, {"default_action": "block", "subprocess_action": "block"})
            self._fault["mutation_returned"] = True
            previous_generation = before["generation"]
            assert isinstance(previous_generation, int)
            after = MixedScenarioFixture(self.session)._ack("block", previous_generation=previous_generation)
            self._fault.update(applied=True, acknowledged=True, binding_after=_binding(after), effective_action="block")

    def _hold_expiry(self) -> None:
        if self._expiry is None:
            return
        remaining = (self._expiry - datetime.now(timezone.utc)).total_seconds()
        if not 0 < remaining <= _EXPIRY_WAIT_SECONDS + 0.1:
            raise RuntimeError("qualification_approval_expiry_delay_outside_bound")
        self._fault["delay_entered"] = True
        # The original HTTP monotonic deadline and recorded browser deadline
        # are unchanged. Only the actual service invocation is delayed.
        if self._cancel.wait(remaining + 0.01):
            raise RuntimeError("qualification_approval_fault_cancelled")
        self._fault.update(applied=True, original_wait_expired=datetime.now(timezone.utc) >= self._expiry)

    def _install_observers(self) -> None:
        from codex_plugin_scanner.guard.daemon import server
        from codex_plugin_scanner.guard.native_decision_receipt import (
            receipt_matches_edge,
            validate_native_decision_receipt,
        )

        self.review._capture_completion()
        worker = self.session.daemon._server.hook_worker
        native = worker._review_raw_hook_native

        def observe_native(**kwargs: Any) -> Any:
            edge = native(**kwargs)
            receipt = validate_native_decision_receipt(edge.get("receipt")) if isinstance(edge, Mapping) else None
            result = edge.get("result") if isinstance(edge, Mapping) else None
            row: dict[str, object] = {
                "rust_authority": isinstance(edge, Mapping) and edge.get("authority") == "rust",
                "receipt_valid": receipt is not None and receipt_matches_edge(edge, receipt),
                "program_binding_present": isinstance(receipt, Mapping)
                and isinstance(receipt.get("command_extensions"), Mapping),
                **{key: result.get(key) if isinstance(result, Mapping) else None for key in _NATIVE_FIELDS},
                **{key: receipt.get(key) if receipt is not None else None for key in _RECEIPT_FIELDS},
            }
            with self._lock:
                if len(self._native) >= _MAX_WITNESSES:
                    self._overflow = True
                else:
                    row["evaluation_index"] = len(self._native)
                    self._native.append(row)
                    self._receipts.append(dict(receipt) if receipt is not None else None)
            return edge

        self._stack.enter_context(patch.object(worker, "_review_raw_hook_native", observe_native))
        module_name = "codex_plugin_scanner.guard.daemon.codex_native_live_decision"
        try:
            native_completion = import_module(module_name)
        except ModuleNotFoundError as error:
            if error.name != module_name:
                raise
        else:
            original = native_completion.complete_native_codex_live_decision
            self._native_completion_available = True

            def observe_completion(*args: Any, **kwargs: Any) -> Any:
                if kwargs.get("request_id") != self._request_id:
                    return original(*args, **kwargs)
                with self._lock:
                    self._in_flight += 1
                try:
                    if self._scenario == "approval_wait_expiry" and not self._fault.get("delay_entered"):
                        self._hold_expiry()
                    return original(*args, **kwargs)
                finally:
                    with self._lock:
                        self._in_flight -= 1

            self._stack.enter_context(
                patch.object(native_completion, "complete_native_codex_live_decision", observe_completion)
            )

        handle = server._GuardDaemonHandler._handle_codex_live_decision
        write = server._GuardDaemonHandler._write_json

        def observe_post(handler: Any, request_id: str, payload: Mapping[str, object]) -> None:
            if request_id == self._request_id:
                self._append(self._posts, {"request_id": request_id, "body_digest": _digest(payload)})
            return handle(handler, request_id, payload)

        def observe_write(handler: Any, payload: dict[str, Any], **kwargs: Any) -> None:
            if urlsplit(handler.path).path != f"/v1/requests/{self._request_id}/live-decision":
                return write(handler, payload, **kwargs)
            response: dict[str, object] = {
                "completed": payload.get("completed") is True,
                "action": payload.get("action"),
                "replayed": payload.get("replayed") is True,
                "error": payload.get("error"),
                "status": kwargs.get("status", 200),
                "delivered": True,
            }
            with self._lock:
                drop = (
                    self._scenario == "ambiguous_completion_retry"
                    and self._drops == 0
                    and response["completed"] is True
                    and response["action"] == "allow"
                )
                if drop:
                    self._drops += 1
                    response["delivered"] = False
                    self._fault.update(applied=True, completed_response_dropped=True)
            self._append(self._responses, response)
            if drop:
                # The transaction has really returned completed. Close this
                # connection before any response bytes; the original bridge's
                # existing bounded retry is the only retry driver.
                handler.close_connection = True
                with suppress(OSError):
                    handler.connection.shutdown(socket.SHUT_RDWR)
                handler.connection.close()
                return None
            return write(handler, payload, **kwargs)

        self._stack.enter_context(patch.object(server._GuardDaemonHandler, "_handle_codex_live_decision", observe_post))
        self._stack.enter_context(patch.object(server._GuardDaemonHandler, "_write_json", observe_write))

    def dispatch(self, operation: str, request: Mapping[str, Any]) -> dict[str, object]:
        try:
            if operation == "launcher_approval_fault_begin":
                scenario = request.get("scenario")
                if scenario not in SCENARIOS or self._scenario is not None:
                    raise ValueError("qualification_approval_fault_case_invalid")
                if self.session.daemon._server.hook_worker.test_oracle is not None:
                    raise RuntimeError("qualification_approval_fault_requires_native")
                self._scenario = str(scenario)
                self._reader = InstalledReceiptReader(
                    self.session.store, profile=str(request.get("receipt_profile", "candidate"))
                )
                if scenario == "approval_wait_expiry":
                    from codex_plugin_scanner.guard.config import update_guard_settings

                    config = update_guard_settings(
                        self.session.guard_home, {"approval_wait_timeout_seconds": _EXPIRY_WAIT_SECONDS}
                    )
                    if config.approval_wait_timeout_seconds != _EXPIRY_WAIT_SECONDS:
                        raise RuntimeError("qualification_approval_expiry_setting_unproven")
                    MixedScenarioFixture(self.session)._ack("allow", previous_generation=0)
                    self._fault["configured_wait_seconds"] = _EXPIRY_WAIT_SECONDS
                self._routes_before = self._routes()
                self._install_observers()
                begun = self.review.dispatch(
                    "launcher_approval_begin",
                    {
                        "harness": "codex",
                        "payload": request.get("payload"),
                        "resolution": "allow",
                        "timeout_seconds": 8,
                    },
                )
                self._operation_id = str(begun.get("operation_id"))
                return begun
            if operation != "launcher_approval_fault_result" or request.get("operation_id") != self._operation_id:
                raise ValueError("qualification_approval_fault_operation_invalid")
            return self._result()
        except Exception as error:
            return assert_privacy_safe(
                {"state": "failed", "fault": dict(self._fault), "failure": failure_evidence(error)}
            )

    def _result(self) -> dict[str, object]:
        result = self.review.dispatch("launcher_approval_result", {"operation_id": self._operation_id})
        with self._lock:
            native = [dict(row) for row in self._native]
            receipts = list(self._receipts)
            posts, responses = [dict(row) for row in self._posts], [dict(row) for row in self._responses]
            fault = dict(self._fault)
            in_flight, overflow = self._in_flight, self._overflow
        assert self._reader is not None
        for row, receipt in zip(native, receipts, strict=True):
            stored = self._reader.read(str(row.get("decision_id")))
            row["committed"] = stored is not None
            row["commit_binding_valid"] = (
                stored is not None
                and receipt is not None
                and all(stored.get(key) == value for key, value in receipt.items())
            )
        authority: dict[str, object] = {"records": 0, "claimed": 0}
        if self._request_id is not None:
            with self.session.store._connect() as connection:
                counts = connection.execute(
                    "select count(*), coalesce(sum(claimed_at is not null), 0) "
                    "from guard_local_once_approvals where request_id = ?",
                    (self._request_id,),
                ).fetchone()
            authority = {"records": int(counts[0]), "claimed": int(counts[1])}
            from codex_plugin_scanner.guard import codex_live_decision

            row = self.session.store.get_approval_request(self._request_id)
            if isinstance(row, Mapping):
                now = datetime.now(timezone.utc).isoformat()
                for name, resolver_name in (
                    ("unclaimed_verified", "resolve_codex_live_allow_authority"),
                    ("claimed_verified", "resolve_codex_consumed_allow_authority"),
                ):
                    resolver = getattr(codex_live_decision, resolver_name, None)
                    authority[name] = (
                        callable(resolver)
                        and resolver(self.session.store, request=row, request_id=self._request_id, now=now) is not None
                    )
        after = self._routes()
        routes = {
            name: after.get(name, 0) - self._routes_before.get(name, 0)
            for name in set(after) | set(self._routes_before)
        }
        return assert_privacy_safe(
            {
                **result,
                "scenario": self._scenario,
                "native_completion_available": self._native_completion_available,
                "fault": fault,
                "native_witnesses": native,
                "distinct_receipt_identities": len({row.get("decision_id") for row in native}),
                "posts": posts,
                "responses": responses,
                "local_once": authority,
                "whole_operation_routes": {key: value for key, value in routes.items() if value},
                "witness_overflow": overflow,
                "settled": in_flight == 0
                and result.get("state") != "waiting"
                and all(row["committed"] for row in native),
                "reviewed_tool_execution": "outside_registered_hook_scope",
            }
        )

    def close(self) -> None:
        self._cancel.set()
        try:
            self.review.controller.close()
        finally:
            try:
                self._stack.close()
            finally:
                self.review.close()
