"""Bounded failure-only evidence for the existing installed default-auto probe.

Delivery observations run outside the hook request. Publisher fields are read
under its existing lock without waiting or changing expiry/readiness state.
The caller's client ContextVar is never attributed to a daemon worker request.
"""

from __future__ import annotations

import json
import os
import re
import threading
from collections.abc import Mapping
from contextlib import suppress
from contextvars import ContextVar, Token
from pathlib import Path
from types import TracebackType

from codex_plugin_scanner.guard.native_approval_errors import FINITE_FAILURE_CODES
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_resident_client import native_resident_client_failure_code
from codex_plugin_scanner.guard.native_runtime import NativeRuntimeCapabilities, NativeRuntimeIdentity
from scripts.native_slo_contract import MAX_READINESS_P95_MS

_ACTIVE: ContextVar[DefaultAutoFailureCapture | None] = ContextVar("default_auto_failure_capture", default=None)
_HARNESS = frozenset(
    {
        "antigravity",
        "claude-code",
        "cline",
        "codex",
        "copilot",
        "cursor",
        "gemini",
        "grok",
        "hermes",
        "kimi",
        "omp",
        "openclaw",
        "opencode",
        "paseo",
        "pi",
        "zcode",
    }
)
_CODES = FINITE_FAILURE_CODES | frozenset(
    {
        "guardconfigsourceerror",
        "oserror",
        "runtimeerror",
        "typeerror",
        "valueerror",
        "attributeerror",
        "operationalerror",
        "databaseerror",
        "native_policy_snapshot_ack_invalid",
        "native_policy_snapshot_ack_mismatch",
        "native_policy_snapshot_expired",
        "native_policy_snapshot_integrity_key_unavailable",
        "native_policy_snapshot_native_disabled",
        "native_policy_snapshot_protocol_unsupported",
        "native_policy_snapshot_publish_failed",
        "native_policy_snapshot_resident_changed",
        "native_policy_snapshot_runtime_unavailable",
        "native_policy_snapshot_workspace_capacity",
        "native_client_containment_failed",
        "native_client_timed_out",
        "native_client_output_limit_exceeded",
        "native_client_status_missing",
        "native_client_exit_nonzero",
        "native_client_output_missing",
        "native_client_process_failed",
        "native_client_launcher_failed",
        "native_client_request_invalid",
        "native_client_start_failed",
        "native_client_stdin_unavailable",
        "native_client_stream_failed",
        "native_exact_safe_command",
        "native_command_control_authority_block",
        "native_command_control_mutation_in_progress",
        "native_policy_warning",
        "native_policy_block",
        "native_hook_unavailable",
        "native_post_tool_unavailable",
        "native_pre_tool_unavailable",
        "native_degraded_emergency_safe",
        "output_secret_match",
        "output_clean",
    }
)
_ROUTES = frozenset({"native_resident", "native_oneshot", "native_fail_safe", "native_degraded", "python_semantic"})
_RECEIPTS = frozenset(
    {
        "receipt_accepted",
        "receipt_processed",
        "receipt_deduped",
        "receipt_dropped",
        "receipt_failures",
        "receipt_durable_pending",
    }
)


def _code(value: object) -> str | None:
    return value if type(value) is str and value in _CODES else None if value is None else "other"


def _integer(value: object) -> int | None:
    return value if type(value) is int and 0 <= value <= 2**63 - 1 else None


def _choice(value: object, choices: set[str] | frozenset[str]) -> str:
    return value if type(value) is str and value in choices else "other"


def _hex(value: object, length: int) -> str | None:
    return value if type(value) is str and re.fullmatch(f"[0-9a-f]{{{length}}}", value) else None


def _counts(value: object, fields: frozenset[str]) -> dict[str, int]:
    if type(value) is not dict:
        return {}
    return {field: count for field in fields if (count := _integer(value.get(field))) is not None}


def _publisher(daemon: object) -> object:
    return getattr(getattr(getattr(daemon, "_server", None), "hook_worker", None), "policy_snapshot_publisher", None)


def _publisher_state(publisher: object) -> dict[str, object]:
    if type(publisher) is not NativePolicySnapshotPublisher:
        return {"available": False}
    condition = publisher._condition
    if not condition.acquire(blocking=False):
        return {"available": False, "busy": True}
    try:
        snapshot = publisher._snapshot
        return {
            "available": True,
            "epoch": _integer(publisher._epoch),
            "snapshot_generation": _integer(snapshot.get("generation")) if type(snapshot) is dict else None,
            "ack_recorded": publisher._acked is True,
            "closed": publisher._closed is True,
            "last_error": _code(publisher._last_error),
        }
    finally:
        condition.release()


def _client_context() -> dict[str, object]:
    return {
        "scope": "probe_context_only",
        "daemon_worker_attribution": False,
        "code": _code(native_resident_client_failure_code()),
    }


def _failure_category(error: BaseException) -> str:
    return (
        type(error).__name__
        if type(error) in {RuntimeError, AssertionError, ValueError, TypeError, OSError, TimeoutError}
        else "other"
    )


class DefaultAutoFailureCapture:
    """Own one probe invocation; write separate evidence only on original failure."""

    def __init__(self, success_path: Path | None) -> None:
        self._path = success_path.with_name(success_path.stem + "-failure.json") if success_path is not None else None
        self._owner = threading.get_ident()
        self._token: Token[DefaultAutoFailureCapture | None] | None = None
        self._publisher: object = None
        self._corpus_active = False
        self._corpus_observed = False
        self._identity: dict[str, object] = {}
        self._deliveries: list[dict[str, object]] = []
        self._corpus: dict[str, object] = {}
        self._incomplete = False
        self._primary_failure: str | None = None
        self._expected_sha = _hex(os.environ.get("SOURCE_SHA"), 40)

    def __enter__(self) -> DefaultAutoFailureCapture:
        self._token = _ACTIVE.set(self)
        return self

    def bind_identity(self, identity: NativeRuntimeIdentity, capabilities: NativeRuntimeCapabilities) -> None:
        try:
            self._identity = {
                "build_sha": _hex(capabilities.build_sha, 40),
                "runtime_sha256": _hex(identity.sha256, 64),
                "rule_digest": _hex(capabilities.rule_digest, 64),
                "runtime_size": _integer(identity.size),
                "protocol_version": _integer(capabilities.protocol_version),
                "target": _choice(
                    capabilities.target,
                    {"x86_64-windows", "x86_64-linux", "aarch64-linux", "x86_64-macos", "aarch64-macos"},
                ),
            }
        except Exception:
            self._incomplete = True

    def bind_corpus(self, daemon: object) -> None:
        self._publisher = _publisher(daemon)
        self._corpus_active = True

    def _owned_state(self, daemon: object) -> dict[str, object]:
        if not self._corpus_active or _publisher(daemon) is not self._publisher:
            return {"available": False, "owned_publisher_changed_or_retired": True}
        return _publisher_state(self._publisher)

    def delivery(self, daemon: object, harness: str, event: str, response: object) -> None:
        if not self._corpus_active:
            return
        if len(self._deliveries) == 21:
            self._incomplete = True
            return
        value = response if type(response) is dict else {}
        self._deliveries.append(
            {
                "index": len(self._deliveries),
                "harness": _choice(harness, _HARNESS),
                "event": _choice(event, {"PreToolUse", "PostToolUse"}),
                "response_present": type(response) is dict,
                "reason_code": _code(value.get("reason_code")),
                "decision": _choice(value.get("decision"), {"allow", "deny", "block", "review", "ask"}),
                "publisher_after_delivery": self._owned_state(daemon),
                "publisher_attribution": "state_observed_after_delivery_not_request_cause",
            }
        )

    def observe_corpus(self, daemon: object, worker_stats: object) -> None:
        if not self._corpus_active or self._corpus_observed:
            return
        stats = worker_stats if isinstance(worker_stats, Mapping) else {}
        self._corpus = {
            "capture_boundary": "before_mode_changes_and_daemon_cleanup",
            "routes": _counts(stats.get("routes"), _ROUTES),
            "publisher": self._owned_state(daemon),
            "client_context": _client_context(),
        }
        self._corpus_observed = True

    def end_corpus(self, daemon: object, worker_stats: object, evidence_stats: object) -> None:
        if not self._corpus_observed:
            self.observe_corpus(daemon, worker_stats)
            self._corpus["capture_boundary"] = "early_exit_before_daemon_cleanup"
        self._corpus["receipt_counts"] = _counts(evidence_stats, _RECEIPTS)
        self._corpus_active = False
        self._publisher = None

    def corpus_failure(self, error: BaseException) -> None:
        if self._corpus_active:
            self._primary_failure = _failure_category(error)

    def __exit__(
        self, kind: type[BaseException] | None, error: BaseException | None, trace: TracebackType | None
    ) -> None:
        del kind, trace
        try:
            if error is not None and self._path is not None:
                # Nothing in diagnostic construction or persistence may replace
                # the original exception or turn a failed gate into success.
                with suppress(Exception):
                    self._write_failure(error)
        finally:
            self._corpus_active = False
            self._publisher = None
            if self._token is not None:
                _ACTIVE.reset(self._token)
                self._token = None

    def _write_failure(self, error: BaseException) -> None:
        report: dict[str, object] = {
            "schema": "hol-guard.native-default-auto-failure.v1",
            "passed": False,
            "qualification": False,
            "expected_build_sha": self._expected_sha,
            "installed_identity": self._identity,
            "required_native_decisions": 21,
            "allowed_fail_safe_decisions": 0,
            "readiness_budget_ms": MAX_READINESS_P95_MS,
            "original_failure_category": _failure_category(error),
            "primary_failure_before_cleanup": self._primary_failure,
        }
        try:
            detailed = {
                **report,
                "deliveries": self._deliveries,
                "corpus": self._corpus,
                "detail_incomplete": self._incomplete,
            }
            encoded = json.dumps(detailed, sort_keys=True, separators=(",", ":"))
            if len(encoded.encode("utf-8")) > 32 * 1024:
                raise ValueError("diagnostic_bound_exceeded")
        except Exception:
            encoded = json.dumps({**report, "detail_incomplete": True}, sort_keys=True)
        assert self._path is not None
        with self._path.open("x", encoding="utf-8") as handle:
            handle.write(encoded + "\n")


def _observe(method: str, *args: object) -> None:
    capture = _ACTIVE.get()
    if capture is None or threading.get_ident() != capture._owner:
        return
    try:
        getattr(capture, method)(*args)
    except Exception:
        capture._incomplete = True


def bind_corpus(daemon: object) -> None:
    _observe("bind_corpus", daemon)


def observe_delivery(daemon: object, harness: str, event: str, response: object) -> None:
    _observe("delivery", daemon, harness, event, response)


def observe_corpus(daemon: object, worker_stats: object) -> None:
    _observe("observe_corpus", daemon, worker_stats)


def end_corpus(daemon: object, worker_stats: object, evidence_stats: object) -> None:
    _observe("end_corpus", daemon, worker_stats, evidence_stats)


def observe_corpus_failure(error: BaseException) -> None:
    _observe("corpus_failure", error)
