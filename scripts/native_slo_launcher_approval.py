"""Private fixture control for real registered-launcher local approval waits.

This helper observes and resolves production approval rows. It does not invoke
the separate native v3/v4 approval API, run the reviewed tool, or open a browser.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from codex_plugin_scanner.guard.approval_gate import ApprovalGateInput
from codex_plugin_scanner.guard.approvals import apply_approval_resolution
from codex_plugin_scanner.guard.daemon.hook_native_review_approval import (
    _native_review_launch_target,
    _native_review_tool_name,
)
from codex_plugin_scanner.guard.daemon.hook_request_parsing import pre_tool_command
from codex_plugin_scanner.guard.runtime.actions import normalize_harness_payload
from codex_plugin_scanner.guard.sqlite_tuning import sqlite_connect_timeout_override
from codex_plugin_scanner.guard.store import GuardStore
from scripts.native_slo_adapter import route_counts
from scripts.native_slo_contract import assert_privacy_safe
from scripts.native_slo_failure import failure_evidence

_MAX_OPERATIONS = 32
_MAX_WAIT_SECONDS = 8.0
_IDENTIFIER = re.compile(r"[A-Za-z0-9_.:-]{1,64}\Z")
# SQLite primary result codes; sqlite3 exposes named constants only on 3.11+.
_SQLITE_READ_CONTENTION_CODES = frozenset({5, 6})  # SQLITE_BUSY, SQLITE_LOCKED


class _PendingReadContentionError(sqlite3.OperationalError):
    """Retain an actual contention error that preceded SELECT completion."""

    def __init__(self, error: sqlite3.OperationalError, code: int) -> None:
        super().__init__("qualification_launcher_approval_pending_read_contention")
        self.original = error
        self.sqlite_errorcode = code


class _Session(Protocol):
    store: GuardStore
    workspace: Path
    daemon: Any


def resolve_launcher_review(
    store: GuardStore,
    request_id: str,
    action: str,
    *,
    approval_gate_input: ApprovalGateInput | None = None,
) -> dict[str, object]:
    """Resolve one exact pending row through the existing gated service.

    Artifact/no-policy persistence retains ordinary resolved-row reuse. It is
    not a one-use native consumption proof. Optional credentials stay local.
    """
    if action not in {"allow", "block"} or re.fullmatch(r"[a-f0-9]{32}", request_id) is None:
        raise ValueError("qualification_launcher_approval_invalid_resolution")
    with sqlite_connect_timeout_override(0.05):
        apply_approval_resolution(
            store=store,
            request_id=request_id,
            action=action,
            scope="artifact",
            workspace=None,
            reason="Synthetic registered launcher qualification approval",
            persist_policy=False,
            resolve_scope_matches=False,
            approval_gate_input=approval_gate_input,
        )
        row = store.get_approval_request(request_id)
    if row is None or row.get("status") != "resolved" or row.get("resolution_action") != action:
        raise RuntimeError("qualification_launcher_approval_resolution_unproven")
    envelope = row.get("action_envelope_json")
    binding = envelope.get("native_review_policy_binding") if isinstance(envelope, Mapping) else None
    digest = hashlib.sha256(
        json.dumps(binding, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
    ).hexdigest()
    return assert_privacy_safe(
        {
            "request_id": request_id,
            "resolution": action,
            "scope": "artifact",
            "approval_durable": True,
            "binding_present": binding is not None,
            "binding_digest": digest,
            "authority": "ordinary_local_review",
        }
    )


@dataclass
class _Operation:
    operation_id: str
    harness: str
    tool: str
    command: str | None
    launch_target: str
    workspace: str
    input_digest: str
    watermark: int
    resolution: str
    deadline: float
    before: dict[str, int]
    done: threading.Event = field(default_factory=threading.Event)
    cancel: threading.Event = field(default_factory=threading.Event)
    thread: threading.Thread | None = None
    evidence: dict[str, object] | None = None


class LauncherApprovalControl:
    """One active waiter, at most 32 retained operations, bounded control results."""

    def __init__(
        self,
        session: _Session,
        *,
        approval_gate_input: ApprovalGateInput | None = None,
        before_resolve: Callable[[str], None] | None = None,
    ) -> None:
        self.session = session
        self._gate_input = approval_gate_input
        self._before_resolve = before_resolve
        self._operations: dict[str, _Operation] = {}
        self._lock = threading.Lock()
        self._closed = False

    def _routes(self) -> dict[str, int]:
        return dict(route_counts(self.session.daemon._server.hook_worker.metrics.snapshot()))

    def begin(
        self,
        harness: str,
        payload: Mapping[str, object],
        *,
        resolution: str = "allow",
        timeout_seconds: float = _MAX_WAIT_SECONDS,
    ) -> dict[str, object]:
        """Capture identity before spawning the actual registered hook process."""
        if harness not in {"claude", "claude-code", "codex"} or resolution not in {"allow", "block"}:
            raise ValueError("qualification_launcher_approval_invalid_case")
        harness = "claude-code" if harness == "claude" else harness
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= _MAX_WAIT_SECONDS
        ):
            raise ValueError("qualification_launcher_approval_invalid_deadline")
        command = pre_tool_command(payload)
        tool = _native_review_tool_name(payload)
        launch_target = _native_review_launch_target(payload)
        missing_command_block = (
            command is None and resolution == "block" and tool == "tool" and launch_target == "tool:tool"
        )
        if (
            (command is None and not missing_command_block)
            or (command is not None and len(command.encode("utf-8")) > 2048)
            or _IDENTIFIER.fullmatch(tool) is None
        ):
            raise ValueError("qualification_launcher_approval_invalid_identity")
        if payload.get("hook_event_name", "PreToolUse") != "PreToolUse":
            raise ValueError("qualification_launcher_approval_invalid_event")
        deadline = time.monotonic() + timeout_seconds
        with self._lock:
            if self._closed or len(self._operations) >= _MAX_OPERATIONS:
                raise RuntimeError("qualification_launcher_approval_capacity")
            if any(not operation.done.is_set() for operation in self._operations.values()):
                raise RuntimeError("qualification_launcher_approval_already_active")
            with sqlite_connect_timeout_override(0.05), self.session.store._connect() as connection:
                watermark = int(
                    connection.execute("select coalesce(max(rowid), 0) from approval_requests").fetchone()[0]
                )
            identity = {
                "harness": harness,
                "tool": tool,
                "command": command,
                "launch_target": launch_target,
                "workspace": str(self.session.workspace),
            }
            digest = hashlib.sha256(
                json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
            ).hexdigest()
            operation = _Operation(
                uuid.uuid4().hex,
                harness,
                tool,
                command,
                launch_target,
                str(self.session.workspace),
                digest,
                watermark,
                resolution,
                deadline,
                self._routes(),
            )
            operation.thread = threading.Thread(
                target=self._run, args=(operation,), name="launcher-approval-control", daemon=True
            )
            self._operations[operation.operation_id] = operation
            operation.thread.start()
        return assert_privacy_safe({"operation_id": operation.operation_id, "state": "waiting", "input_digest": digest})

    def _new_pending(self, operation: _Operation) -> str | None:
        # Production local review currently does not retain tool_use_id. Match
        # its exact command/tool/harness/workspace and require a new SQL row.
        # A pre-existing deduplicated row is never silently selected.
        read_finished = False
        try:
            # Keep the ordinary storage gate and connection settings, but do
            # not enter _connect's pre-yield database recovery/write path.
            with (
                sqlite_connect_timeout_override(0.05),
                self.session.store._hold_storage_gate(exclusive=False),
                self.session.store._connect_once() as connection,
            ):
                rows = connection.execute(
                    """select request_id from approval_requests
                       where rowid > ? and status = 'pending' and policy_action = 'review'
                         and harness = ? and artifact_name = ? and launch_target = ? and workspace = ?
                         and artifact_id = ? and artifact_type = 'tool_call'
                       order by rowid limit 2""",
                    (
                        operation.watermark,
                        operation.harness,
                        operation.tool,
                        operation.launch_target,
                        operation.workspace,
                        f"{operation.harness}:native-pretool:{operation.tool}",
                    ),
                ).fetchall()
                # Store context exit may perform commit housekeeping. An
                # exception after this point is ambiguous and never retried.
                read_finished = True
        except sqlite3.OperationalError as error:
            code = getattr(error, "sqlite_errorcode", None)
            if not read_finished and type(code) is int and code & 0xFF in _SQLITE_READ_CONTENTION_CODES:
                raise _PendingReadContentionError(error, code) from error
            raise
        if len(rows) > 1:
            raise RuntimeError("qualification_launcher_approval_ambiguous")
        return str(rows[0][0]) if rows else None

    def _verify_identity(self, operation: _Operation, request_id: str, *, status: str) -> str:
        with sqlite_connect_timeout_override(0.05):
            row = self.session.store.get_approval_request(request_id)
        expected = {
            "status": status,
            "harness": operation.harness,
            "artifact_name": operation.tool,
            "artifact_id": f"{operation.harness}:native-pretool:{operation.tool}",
            "artifact_type": "tool_call",
            "launch_target": operation.launch_target,
            "workspace": operation.workspace,
        }
        if row is None or any(row.get(key) != value for key, value in expected.items()):
            raise RuntimeError("qualification_launcher_approval_identity_changed")
        envelope = row.get("action_envelope_json")
        # The pinned baseline has the legacy empty envelope. The Codex native
        # continuation repair uses canonical normalization. Both are exact
        # reviewed block-only profiles; neither can authorize an unknown allow.
        empty_profile = (
            (envelope.get("action_type"), envelope.get("tool_name")) if isinstance(envelope, Mapping) else None
        )
        canonical_empty = (
            operation.harness == "codex" and operation.command is None and empty_profile == ("config_change", None)
        )
        expected_envelope: dict[str, object] = {
            "harness": operation.harness,
            "tool_name": None if canonical_empty else operation.tool,
            "command": operation.command,
            "workspace": operation.workspace,
            "event_name": "PreToolUse",
            "action_type": "shell_command"
            if operation.command is not None
            else "config_change"
            if canonical_empty
            else "mcp_tool",
        }
        if (
            operation.harness == "codex"
            and isinstance(envelope, Mapping)
            and envelope.get("workspace_hash") is not None
        ):
            # Current native Codex presentation redacts workspace and command
            # paths. Their canonical projection and the unredacted row scope
            # and launch target must match the identity captured before launch.
            # Keep the pinned baseline's legacy, unhashed envelope separate.
            canonical = normalize_harness_payload(
                "codex",
                "PreToolUse",
                {"tool_name": operation.tool, "tool_input": {"command": operation.command}}
                if operation.command is not None
                else {},
                workspace=operation.workspace,
                home_dir=getattr(self.session, "root", self.session.store.guard_home.parent),
            ).to_dict()
            for field_name in ("workspace", "workspace_hash", "command", "tool_name", "action_type"):
                expected_envelope[field_name] = canonical[field_name]
            expected_envelope["schema_version"] = 1
        if not isinstance(envelope, Mapping) or any(
            envelope.get(key) != value for key, value in expected_envelope.items()
        ):
            raise RuntimeError("qualification_launcher_approval_identity_changed")
        return hashlib.sha256(
            json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
        ).hexdigest()

    def _run(self, operation: _Operation) -> None:
        durable: dict[str, object] | None = None
        read_contention: dict[str, object] = {}
        read_contention_count = 0
        try:
            while True:
                if operation.cancel.is_set():
                    raise RuntimeError("qualification_launcher_approval_cancelled")
                if time.monotonic() >= operation.deadline:
                    raise TimeoutError("qualification_launcher_approval_deadline")
                try:
                    request_id = self._new_pending(operation)
                except _PendingReadContentionError as error:
                    # Only the pre-selection read may be retried. Retain the
                    # observed contention and use the original deadline and
                    # polling delay; approval resolution is never repeated.
                    read_contention_count += 1
                    read_contention = {
                        "read_contention": {
                            "count": read_contention_count,
                            "sqlite_errorcode": error.sqlite_errorcode,
                            "last_failure": failure_evidence(error.original),
                        }
                    }
                    request_id = None
                if request_id is not None:
                    identity = self._verify_identity(operation, request_id, status="pending")
                    durable = {"request_id": request_id, "approval_durable": False}
                    if self._before_resolve is not None:
                        self._before_resolve(request_id)
                        if self._verify_identity(operation, request_id, status="pending") != identity:
                            raise RuntimeError("qualification_launcher_approval_identity_changed")
                    if operation.cancel.is_set() or time.monotonic() >= operation.deadline:
                        raise TimeoutError("qualification_launcher_approval_deadline")
                    evidence = resolve_launcher_review(
                        self.session.store, request_id, operation.resolution, approval_gate_input=self._gate_input
                    )
                    durable = evidence
                    if self._verify_identity(operation, request_id, status="resolved") != identity:
                        raise RuntimeError("qualification_launcher_approval_identity_changed")
                    if operation.cancel.is_set() or time.monotonic() >= operation.deadline:
                        raise TimeoutError("qualification_launcher_approval_resolution_late")
                    after = self._routes()
                    delta = {
                        name: after.get(name, 0) - operation.before.get(name, 0)
                        for name in set(after) | set(operation.before)
                    }
                    if any(value < 0 for value in delta.values()):
                        raise RuntimeError("qualification_launcher_approval_counter_regression")
                    operation.evidence = assert_privacy_safe(
                        {
                            **evidence,
                            **read_contention,
                            "operation_id": operation.operation_id,
                            "state": "resolved",
                            "input_digest": operation.input_digest,
                            "matching": "exact_identity_and_new_row",
                            "routes": delta,
                        }
                    )
                    return
                operation.cancel.wait(min(0.01, max(0, operation.deadline - time.monotonic())))
        except Exception as error:
            operation.evidence = assert_privacy_safe(
                {
                    **(durable or {}),
                    **read_contention,
                    "operation_id": operation.operation_id,
                    "state": "failed",
                    "failure": failure_evidence(error),
                }
            )
        finally:
            operation.done.set()

    def result(self, operation_id: str) -> dict[str, object]:
        """Poll without blocking the private fixture's bounded control pipe."""
        with self._lock:
            operation = self._operations.get(operation_id)
            if operation is None:
                raise ValueError("qualification_launcher_approval_unknown_operation")
            if not operation.done.is_set():
                return {"operation_id": operation_id, "state": "waiting"}
            assert operation.evidence is not None
            return dict(operation.evidence)

    def close(self) -> None:
        """Cancel polling; require the owner to contain a stuck resolver process."""
        with self._lock:
            self._closed = True
            operations = tuple(self._operations.values())
            for operation in operations:
                operation.cancel.set()
        for operation in operations:
            if operation.thread is not None:
                operation.thread.join(timeout=1.0)
                if operation.thread.is_alive():
                    raise RuntimeError("qualification_launcher_approval_cleanup_unproven")


__all__ = ["LauncherApprovalControl", "resolve_launcher_review"]
