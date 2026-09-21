"""Installed small/max-inline Python diagnostics with private attempt evidence.

The caller supplies a separate DaemonFixture(runtime, setup='normal'). No
instrumented latency is eligible for a headline SLO sample.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHandler
from codex_plugin_scanner.guard.native_hook_edge import _MAX_REQUEST_BYTES
from scripts.native_probe_receipts import wait_for_route_corpus
from scripts.native_slo_daemon_fixture import witnessed_route
from scripts.native_slo_failure import failure_evidence
from scripts.native_slo_registered_surfaces_evidence import SurfaceEvidence
from scripts.native_slo_workloads import (
    QualificationCase,
    _native_post,
    _post_expected,
    _validate_projection,
    corpus_manifest,
    validate_native_result,
    validate_setup,
)

_MAX_COUNT = 100
_SMALL_WIRE_BYTES = 1024
_MAX_JOURNAL_BYTES = 8 * 1024 * 1024
_MAX_RECORD_BYTES = 8192
_MAX_REPORT_BYTES = 256 * 1024
_MAX_RECORDS = 4 * _MAX_COUNT * 2 + 10
_ROUTES = frozenset({"native_resident", "native_oneshot", "native_fail_safe", "python_semantic"})
_SEMANTIC_FIELDS = (
    "decision",
    "continue",
    "policy_action",
    "model_output_action",
    "reason_code",
    "observe_mode",
    "observed_policy_action",
    "reviewed_output_sha256",
    "minimum_action",
    "hookSpecificOutput.hookEventName",
    "hookSpecificOutput.permissionDecision",
)
_ENUMS = frozenset(
    {
        "allow",
        "deny",
        "block",
        "warn",
        "review",
        "allow_original",
        "reviewed_excerpt",
        "PostToolUse",
        "output_scan_allow",
        "output_secret_match",
    }
)


def _encoded(value: object) -> bytes:
    # Exact serialization used by native_slo_session._request; fixtures are
    # ASCII, so characters and UTF-8 bytes are equal here, by construction.
    return json.dumps(value, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _identity(value: object) -> dict[str, object]:
    encoded = _encoded(value)
    return {"bytes": len(encoded), "sha256": hashlib.sha256(encoded).hexdigest()}


def _semantic_evidence(value: Mapping[str, object]) -> dict[str, object]:
    evidence = _identity(value)
    projection: dict[str, object] = {}
    for field in _SEMANTIC_FIELDS:
        current: object = value
        for part in field.split("."):
            if not isinstance(current, Mapping) or part not in current:
                break
            current = current[part]
        else:
            if (
                current is None
                or type(current) is bool
                or (isinstance(current, str) and (current in _ENUMS or re.fullmatch(r"[0-9a-f]{64}", current)))
            ):
                projection[field] = current
            else:
                # Keep unexpected values identifiable without copying output
                # text, paths, or arbitrary strings into the private journal.
                projection[field] = {"unexpected_value": _identity(current)}
    evidence["semantic"] = projection
    return evidence


def phase_cases() -> tuple[QualificationCase, ...]:
    """Create exact HTTP-wire sizes, not 5 MiB source-reference substitutes."""
    http_limit = _GuardDaemonHandler._MAX_BODY_BYTES
    if corpus_manifest()["http_body_bytes"] != http_limit or not _SMALL_WIRE_BYTES < http_limit < _MAX_REQUEST_BYTES:
        raise RuntimeError("qualification phase ingress bound contract changed")
    cases: list[QualificationCase] = []
    for size_class, target in (("small_inline", _SMALL_WIRE_BYTES), ("maximum_supported_inline", http_limit)):
        for kind in ("benign", "block"):
            content = "" if kind == "benign" else "gh" + "p_" + "b" * 30 + " "
            request: dict[str, object] = {
                "hook_event_name": "PostToolUse",
                "tool_name": "Read",
                "tool_response": [{"type": "text", "text": content}],
                "guard_remaining_ms": 4000,
            }
            remaining = target - len(_encoded(request))
            if remaining < 0:
                raise RuntimeError("qualification phase fixture exceeds wire target")
            content += ("const guard_value = 1; " * ((remaining + 21) // 22))[:remaining]
            request["tool_response"] = [{"type": "text", "text": content}]
            if len(_encoded(request)) != target or not content.isascii():
                raise RuntimeError("qualification phase wire size mismatch")
            digest = hashlib.sha256(content.encode("ascii")).hexdigest()
            reason = "output_scan_allow" if kind == "benign" else "output_secret_match"
            cases.append(
                QualificationCase(
                    case_id=f"phase-{size_class}-{kind}",
                    harness="claude-code",
                    event="PostToolUse",
                    canonical_event="PostToolUse",
                    size_class=size_class,
                    payload=request,
                    expected=_post_expected("claude-code", kind, reason, digest),
                    expected_route="native_resident",
                    setup="normal",
                    surface="installed_canonical",
                    content_bytes=len(content),
                    wire_bytes=target,
                    payload_kind="inline",
                    native_expected=_native_post(kind, reason, digest),
                )
            )
    return tuple(cases)


class _Journal(SurfaceEvidence):
    """Reuse exclusive owned 0600 creation; keep separate diagnostic bounds."""

    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self.digest = hashlib.sha256()

    def __enter__(self) -> _Journal:
        _ = super().__enter__()
        return self

    def append(self, value: dict[str, object], *, report: bool = False) -> None:
        encoded = _encoded(value) + b"\n"
        bound = _MAX_REPORT_BYTES + _MAX_RECORD_BYTES if report else _MAX_RECORD_BYTES
        if len(encoded) > bound or self.size + len(encoded) > _MAX_JOURNAL_BYTES or self.records >= _MAX_RECORDS:
            raise RuntimeError("qualification phase journal bound exceeded")
        assert self.stream is not None
        if self.stream.write(encoded) != len(encoded):
            raise RuntimeError("qualification phase journal short write")
        self.stream.flush()
        os.fsync(self.stream.fileno())
        self.digest.update(encoded)
        self.size += len(encoded)
        self.records += 1

    def reserve_attempt(self) -> None:
        # Reserve offered+terminal plus both possible phase reports and the
        # run failure record BEFORE issuing an external request.
        if (
            self.records + 5 > _MAX_RECORDS
            or self.size + 5 * _MAX_RECORD_BYTES + 2 * _MAX_REPORT_BYTES > _MAX_JOURNAL_BYTES
        ):
            raise RuntimeError("qualification phase journal cannot retain next attempt")


def _counts(snapshot: Mapping[str, object]) -> dict[str, int]:
    routes = snapshot.get("routes")
    if not isinstance(routes, Mapping) or any(
        key not in _ROUTES or type(value) is not int or value < 0 for key, value in routes.items()
    ):
        raise RuntimeError("qualification phase route inventory invalid")
    return cast(dict[str, int], dict(routes))


def _attempt(session: Any, case: QualificationCase, sample: int, journal: _Journal) -> None:
    journal.reserve_attempt()
    request_identity = _identity(case.payload)
    if request_identity["bytes"] != case.wire_bytes:
        raise RuntimeError("qualification phase request changed wire size")
    base: dict[str, object] = {
        "schema": "hol-guard.phase-attempt.v1",
        "case_id": case.case_id,
        "sample": sample,
        "wire_bytes": case.wire_bytes,
        "content_bytes": case.content_bytes,
        "kind": "inline",
        "request_sha256": request_identity["sha256"],
    }
    journal.append({**base, "status": "offered"})
    record: dict[str, object] = {**base, "status": "failed", "stage": "setup"}
    errors: list[Exception] = []
    before: dict[str, int] | None = None
    delivered: Mapping[str, object] | None = None
    witness: Mapping[str, object] | None = None
    route: str | None = None
    metrics: Any = None
    captured = False
    record["request_started"] = False
    try:
        if session.control("case_before").get("reset") is not True:
            raise RuntimeError("qualification phase native capture reset missing")
        captured = True
        metrics = session.daemon._server.hook_worker.metrics
        record["stage"] = "route_before"
        snapshot = metrics.snapshot()
        record["before_identity"] = _identity(snapshot)
        before = _counts(snapshot)
        record["routes_before"] = before
        record["stage"] = "request"
        record["request_started"] = True
        started = time.perf_counter()
        try:
            delivered, elapsed = session.request(case.harness, case.payload)
        finally:
            record["request_call_ms"] = (time.perf_counter() - started) * 1000
        if type(elapsed) not in (int, float) or not math.isfinite(elapsed) or elapsed < 0:
            raise RuntimeError("qualification phase request timing invalid")
        record["http_request_ms"] = elapsed
        if not isinstance(delivered, Mapping):
            raise RuntimeError("qualification phase delivered response invalid")
        record["delivered"] = _semantic_evidence(delivered)
    except Exception as error:
        errors.append(error)
    # Retain available post-request facts even if the adapter raised; never
    # replace an earlier failure with a later capture/control failure.
    if before is not None and metrics is not None:
        try:
            if not errors:
                record["stage"] = "route_after"
            snapshot = wait_for_route_corpus(metrics, expected=sum(before.values()) + 1)
            record["after_identity"] = _identity(snapshot)
            after = _counts(snapshot)
            record["routes_after"] = after
            route = witnessed_route(before, after)
            record["route"] = route
        except Exception as error:
            errors.append(error)
    record["capture_reset_acknowledged"] = captured
    if captured:
        try:
            if not errors:
                record["stage"] = "native_capture"
            received = session.control("case_result")
            if not isinstance(received, Mapping):
                raise RuntimeError("qualification phase native capture invalid")
            witness = cast(Mapping[str, object], received)
            native = witness.get("native_result")
            record["native"] = (
                _semantic_evidence(native)
                if isinstance(native, Mapping)
                else {"observed": native is not None, "invalid_or_absent": _identity(native)}
            )
            record["setup_identity"] = _identity(witness.get("setup"))
        except Exception as error:
            errors.append(error)
    if not errors:
        try:
            record["stage"] = "oracle"
            assert delivered is not None and witness is not None and route is not None
            setup = witness.get("setup")
            native = witness.get("native_result")
            if not isinstance(setup, Mapping) or (native is not None and not isinstance(native, Mapping)):
                raise RuntimeError("qualification phase native witness invalid")
            validate_setup(case, setup)
            # Use the same frozen projection without validate_case's default
            # HTTP status. This adapter API exposes parsed delivery, not the
            # actual status; capacity substitution must still fail this oracle.
            if route != case.expected_route:
                raise AssertionError(f"native_qualification_mismatch:{case.case_id}:route")
            _validate_projection(case.expected, delivered, case.case_id)
            validate_native_result(case, native)
            record["status"] = "validated"
            record["stage"] = "complete"
        except Exception as error:
            errors.append(error)
    if errors:
        record["failures"] = [failure_evidence(error) for error in errors]
    journal.append(record)
    if errors:
        raise errors[0]


def _phase_group(
    session: Any, cases: tuple[QualificationCase, ...], count: int, journal: _Journal
) -> dict[str, object]:
    group = cases[0].size_class
    journal.append({"schema": "hol-guard.phase-group.v1", "size_class": group, "status": "starting"})
    started = False
    failure: Exception | None = None
    phase_report: Mapping[str, object] | None = None
    try:
        # A failed/lost start ACK may still follow successful installation.
        # Attempt cleanup in that case too; the fixture owner contains a
        # broken control process if cleanup cannot be acknowledged.
        started = True
        if session.control("phases_start").get("started") is not True:
            raise RuntimeError("qualification phase start acknowledgment missing")
        for sample in range(count):
            for case in cases:
                _attempt(session, case, sample, journal)
    except Exception as error:
        failure = error
    finally:
        if started:
            try:
                finished = session.control("phases_finish")
                if not isinstance(finished, Mapping):
                    raise RuntimeError("qualification phase report invalid")
                phase_report = cast(Mapping[str, object], finished)
                if (
                    phase_report.get("schema") != "hol-guard-python-phase-diagnostics.v2"
                    or phase_report.get("headline_timing_eligible") is not False
                    or phase_report.get("scope") != "diagnostic_instrumented_run"
                    or len(_encoded(phase_report)) > _MAX_REPORT_BYTES
                ):
                    raise RuntimeError("qualification phase report invalid")
                journal.append(
                    {
                        "schema": "hol-guard.phase-group.v1",
                        "size_class": group,
                        "status": "finished",
                        "report": phase_report,
                    },
                    report=True,
                )
                if failure is None:
                    _validate_phase_counts(phase_report, cases[0].wire_bytes, count * len(cases))
            except Exception as error:
                journal.append(
                    {
                        "schema": "hol-guard.phase-group.v1",
                        "size_class": group,
                        "status": "finish_failed",
                        "failure": failure_evidence(error),
                    }
                )
                if failure is None:
                    failure = error
    if failure is not None:
        raise failure
    assert phase_report is not None
    return {
        "wire_bytes": cases[0].wire_bytes,
        "kind": "inline",
        "attempted": count * len(cases),
        "validated": count * len(cases),
        "phase_report": phase_report,
    }


def _validate_phase_counts(report: Mapping[str, object], wire_bytes: int, attempts: int) -> None:
    """Prove these supported inline requests crossed the measured boundaries."""
    routes = report.get("by_route")
    if not isinstance(routes, Mapping):
        raise RuntimeError("qualification phase spans missing")
    hook = routes.get("claude-code.PostToolUse")
    transport = routes.get("claude-code.transport_unclassified")
    if not isinstance(hook, Mapping) or not isinstance(transport, Mapping):
        raise RuntimeError("qualification phase routes missing")
    for phase in (
        "daemon_hook_inclusive",
        "envelope_encode",
        "native_client_inclusive",
        "edge_json_loads",
        "edge_json_dumps",
    ):
        span = hook.get(phase)
        if not isinstance(span, Mapping) or type(span.get("count")) is not int or span.get("count") != attempts:
            raise RuntimeError("qualification phase call counts incomplete")
    read = transport.get("http_body_read")
    work = read.get("work") if isinstance(read, Mapping) else None
    if not isinstance(work, Mapping) or work.get("returned_bytes") != wire_bytes * attempts:
        raise RuntimeError("qualification phase observed wire bytes mismatch")
    if any(
        type(report.get(key)) is not int or report.get(key) != 0
        for key in ("discarded_samples", "discarded_series_updates")
    ):
        raise RuntimeError("qualification phase attribution was discarded")


def measure_installed_phases(session: Any, count: int, evidence_file: Path) -> dict[str, object]:
    """Run count benign AND block attempts per size (4*count total, max 400).

    Requires a separate setup='normal' fixture with the existing native-result
    capture. Fails on the first mismatch while retaining the offered/terminal
    attempt and phase report; calls phases_finish even on request/oracle error.
    The supplied fixture owner must close it after control-pipe failures.
    """
    if type(count) is not int or not 1 <= count <= _MAX_COUNT:
        raise ValueError("qualification phase count outside bound")
    if getattr(session, "setup", None) != "normal":
        raise ValueError("qualification phase requires isolated normal capture fixture")
    cases = phase_cases()
    oracle_digest = hashlib.sha256(Path(__file__).with_name("native_slo_workloads.py").read_bytes()).hexdigest()
    with _Journal(evidence_file) as journal:
        journal.append(
            {
                "schema": "hol-guard.phase-run.v1",
                "status": "started",
                "count_per_case": count,
                "oracle_sha256": oracle_digest,
                "http_body_limit_bytes": _GuardDaemonHandler._MAX_BODY_BYTES,
                "native_envelope_limit_bytes": _MAX_REQUEST_BYTES,
            }
        )
        try:
            groups = {
                name: _phase_group(session, tuple(case for case in cases if case.size_class == name), count, journal)
                for name in ("small_inline", "maximum_supported_inline")
            }
        except Exception as error:
            journal.append({"schema": "hol-guard.phase-run.v1", "status": "failed", "failure": failure_evidence(error)})
            raise
        journal.append({"schema": "hol-guard.phase-run.v1", "status": "validated", "attempted": 4 * count})
        return {
            "schema": "hol-guard.installed-phase-run.v1",
            "scope": "diagnostic_instrumented_run",
            "headline_timing_eligible": False,
            "boundary": "AUTHENTICATED_DAEMON_ADAPTER",
            "count_per_case": count,
            "attempted": 4 * count,
            "validated": 4 * count,
            "groups": groups,
            "oracle_sha256": oracle_digest,
            "journal_sha256": journal.digest.hexdigest(),
            "journal_records": journal.records,
            "journal_bytes": journal.size,
            "large_source_reference_included": False,
        }
