"""Frozen delivery cases through the exact installed priority registrations.

The independent daemon corpus supplies expected semantic outcomes. Codex's
documented stdout field projection is frozen here, separately from production
renderers. Native results and daemon route witnesses are checked independently
of stdout, so a launcher availability response cannot count as evaluated allow.
"""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import sys
import time
from collections import Counter
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import TextIO, cast

from codex_plugin_scanner.guard.codex_hook_launch_runtime import run_isolated_hook_process
from scripts.native_probe_receipts import wait_for_route_corpus
from scripts.native_slo_adapter import route_counts
from scripts.native_slo_contract import assert_privacy_safe, clear_proof_environment
from scripts.native_slo_corpus_run import _IMPLEMENTED_SETUPS
from scripts.native_slo_daemon_fixture import DaemonFixture, witnessed_route
from scripts.native_slo_failure import failure_evidence
from scripts.native_slo_launcher_review import approved_review_case, await_resolution, validate_resolution
from scripts.native_slo_priority_launchers import (
    LauncherSession,
    RegisteredLauncher,
    install_priority_launchers,
    registered_launcher,
)
from scripts.native_slo_workloads import (
    ExpectedResponse,
    QualificationCase,
    build_cases,
    platform_scope_summary,
    validate_case,
    validate_native_result,
    validate_setup,
)

_SUPPORTED = frozenset(
    (harness, event) for harness in ("claude-code", "codex") for event in ("PreToolUse", "PostToolUse")
)
_STDOUT_LIMIT = 2 * 1024 * 1024


def installed_expectation(case: QualificationCase) -> QualificationCase:
    """Freeze the externally documented Codex field filter, not its renderer."""
    if (case.harness, case.event) not in _SUPPORTED or not case.surface.startswith("installed_"):
        raise ValueError("launcher corpus case is not an installed registration")
    if case.harness != "codex":
        return replace(case, boundary="registered_launcher")
    top = {"continue", "stopReason", "suppressOutput", "systemMessage", "hookSpecificOutput"}
    if case.event == "PostToolUse":
        top.update({"decision", "reason"})
    post_specific = {"hookEventName", "additionalContext", "updatedMCPToolOutput"}

    def retained(path: str) -> bool:
        parts = path.split(".")
        return parts[0] in top and not (
            case.event == "PostToolUse"
            and len(parts) > 1
            and parts[0] == "hookSpecificOutput"
            and parts[1] not in post_specific
        )

    return replace(
        case,
        boundary="registered_launcher",
        expected=ExpectedResponse(
            case.expected.decision,
            case.expected.model_action,
            case.expected.reason_class,
            {key: value for key, value in case.expected.fields.items() if retained(key)},
            tuple(key for key in case.expected.nonempty_fields if retained(key)),
            case.expected.exact_empty,
        ),
    )


def _run_registered(
    session: DaemonFixture,
    launcher: RegisteredLauncher,
    case: QualificationCase,
    *,
    process_evidence: dict[str, object] | None = None,
    approval_wait: bool = False,
) -> tuple[Mapping[str, object], float]:
    if registered_launcher(launcher.config_path, launcher.harness, launcher.event) != launcher:
        raise RuntimeError("launcher corpus registration changed")
    environment = dict(os.environ)
    clear_proof_environment(environment)
    environment.update(launcher.environment)
    environment["HOME"] = str(session.root)
    environment["USERPROFILE"] = str(session.root)
    if launcher.harness == "codex":
        environment["CODEX_HOME"] = str(session.root / ".codex")
    if approval_wait:
        # Exercise normal polling/finalization without opening a GUI/browser.
        environment.pop("DISPLAY", None)
        environment.pop("WAYLAND_DISPLAY", None)
        environment["BROWSER"] = shlex.join((sys.executable, "-I", "-c", "pass", "%s"))
    payload = dict(case.payload)
    payload["tool_use_id"] = "installed-corpus-" + hashlib.sha256(case.case_id.encode()).hexdigest()[:24]
    encoded = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
    started = time.perf_counter()
    result = run_isolated_hook_process(
        launcher.argv,
        input_text=encoded,
        cwd=session.workspace,
        environment=environment,
        timeout_seconds=10,
        output_limit=_STDOUT_LIMIT,
    )
    elapsed = (time.perf_counter() - started) * 1000
    if process_evidence is not None:
        process_evidence.update(
            returncode=result.returncode,
            elapsed_ms=elapsed,
            timed_out=result.timed_out,
            containment_failed=result.containment_failed,
            stream_limit_exceeded=result.output_limit_exceeded,
            stdout_sha256=hashlib.sha256(result.stdout.encode("utf-8")).hexdigest(),
            stdout_bytes=len(result.stdout.encode("utf-8")),
            browser_opening="suppressed" if approval_wait else "not_requested",
        )
    if result.returncode != 0 or result.timed_out or result.containment_failed or result.output_limit_exceeded:
        raise RuntimeError("launcher corpus process contract failed")
    try:
        response: object = json.loads(result.stdout)
    except (ValueError, UnicodeDecodeError) as error:
        raise RuntimeError("launcher corpus stdout is not JSON") from error
    if not isinstance(response, Mapping):
        raise RuntimeError("launcher corpus stdout is not an object")
    return cast(Mapping[str, object], response), elapsed


def _selected(case: QualificationCase) -> bool:
    return (
        (case.harness, case.event) in _SUPPORTED
        and case.surface.startswith("installed_")
        and case.expected_http_status == 200
    )


def validate_installed_response(case: QualificationCase, response: Mapping[str, object], route: str) -> None:
    if case.harness == "codex":
        if case.expected.reason_class == "approved_review" and response != {
            "hookSpecificOutput": {"hookEventName": "PreToolUse"}
        }:
            raise RuntimeError("launcher corpus Codex completion stdout mismatch")
        allowed = {"continue", "stopReason", "suppressOutput", "systemMessage", "hookSpecificOutput"}
        if case.event == "PostToolUse":
            allowed.update({"decision", "reason"})
        specific = response.get("hookSpecificOutput")
        specific_allowed = {"hookEventName", "permissionDecision", "permissionDecisionReason"}
        if case.event == "PostToolUse":
            specific_allowed = {"hookEventName", "additionalContext", "updatedMCPToolOutput"}
        if not set(response) <= allowed or (isinstance(specific, Mapping) and not set(specific) <= specific_allowed):
            raise RuntimeError("launcher corpus Codex stdout schema mismatch")
    validate_case(case, response, route)


def _attempt(
    session: DaemonFixture,
    launcher: RegisteredLauncher,
    case: QualificationCase,
    *,
    stage: str,
    evidence: TextIO,
    operation_id: str | None = None,
) -> tuple[str, float]:
    """Retain every offered process and its exact bounded outcome before raising."""
    attempt: dict[str, object] = {
        "case_digest": hashlib.sha256(case.case_id.encode()).hexdigest(),
        "harness": case.harness,
        "event": case.event,
        "setup": case.setup,
        "stage": stage,
        "status": "offered",
        "registration_sha256": launcher.registration_sha256,
        "argv_sha256": hashlib.sha256(json.dumps(launcher.argv).encode()).hexdigest(),
    }
    evidence.write(json.dumps(attempt, separators=(",", ":")) + "\n")
    evidence.flush()
    metrics = None
    try:
        metrics = session.daemon._server.hook_worker.metrics
        before = route_counts(metrics.snapshot())
        attempt["routes_before"] = dict(before)
        session.control("case_before")
        response, elapsed = _run_registered(
            session,
            launcher,
            case,
            process_evidence=attempt,
            approval_wait=operation_id is not None,
        )
        after = route_counts(
            metrics.snapshot()
            if case.expected_route == "engine_bypassed"
            else wait_for_route_corpus(
                metrics, expected=sum(before.values()) + (2 if stage == "browser_wait_completion" else 1)
            )
        )
        attempt.update(routes_before=dict(before), routes_after=dict(after))
        if stage == "browser_wait_completion":
            delta = {key: after.get(key, 0) - before.get(key, 0) for key in set(before) | set(after)}
            if {key: count for key, count in delta.items() if count} != {"native_resident": 2}:
                raise RuntimeError("qualification Codex native evaluation count mismatch")
            route = "native_resident"
        else:
            route = witnessed_route(before, after)
        attempt["route"] = route
        result = session.control("case_result")
        setup_evidence, native_evidence = result.get("setup"), result.get("native_result")
        if not isinstance(setup_evidence, Mapping) or (
            native_evidence is not None and not isinstance(native_evidence, Mapping)
        ):
            raise RuntimeError("launcher corpus fault witness is malformed")
        validate_setup(case, setup_evidence)
        validate_native_result(case, native_evidence)
        attempt["native_action"] = (
            native_evidence.get("minimum_action", "not_applicable") if native_evidence else "absent"
        )
        if operation_id is not None:
            resolution = await_resolution(session, operation_id)
            attempt["approval"] = dict(resolution)
            validate_resolution(resolution, harness=case.harness)
        validate_installed_response(case, response, route)
        attempt["delivery"] = case.expected.decision
    except Exception as error:
        attempt.update(status="failed", failure=failure_evidence(error))
        if metrics is not None and "routes_after" not in attempt:
            try:
                attempt["routes_after"] = dict(route_counts(metrics.snapshot()))
            except Exception as metric_error:
                attempt["routes_failure"] = failure_evidence(metric_error)
        if operation_id is not None and "approval" not in attempt:
            try:
                attempt["approval"] = dict(session.control("launcher_approval_result", operation_id=operation_id))
            except Exception as control_error:
                attempt["approval_failure"] = failure_evidence(control_error)
        evidence.write(json.dumps(assert_privacy_safe(attempt), separators=(",", ":")) + "\n")
        evidence.flush()
        raise
    evidence.write(json.dumps(assert_privacy_safe({**attempt, "status": "validated"}), separators=(",", ":")) + "\n")
    evidence.flush()
    return route, elapsed


def run_registered_contract_corpus(runtime: Path, *, evidence_file: Path) -> dict[str, object]:
    """Run ordinary registrations across sizes, source refs, posture and faults.

    Review continuation is separately exercised by run_registered_approval_corpus;
    it remains an explicit coverage obligation in this report.
    """
    return _run_registered_corpus(runtime, evidence_file=evidence_file, review_only=False)


def run_registered_approval_corpus(runtime: Path, *, evidence_file: Path) -> dict[str, object]:
    """Require both real review flows without blocking unrelated baseline timing."""
    return _run_registered_corpus(runtime, evidence_file=evidence_file, review_only=True)


def _run_registered_corpus(runtime: Path, *, evidence_file: Path, review_only: bool) -> dict[str, object]:
    evidence_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    validated: list[str] = []
    validated_ids: list[str] = []
    selected_cases: dict[str, QualificationCase] = {}
    review_harnesses: set[str] = set()
    offered_attempts = 0
    counts = {name: Counter() for name in ("harness", "event", "setup", "size", "route", "delivery", "representation")}
    with evidence_file.open("w", encoding="utf-8") as evidence:
        evidence_file.chmod(0o600)
        for setup in sorted({"normal"} if review_only else _IMPLEMENTED_SETUPS):
            with DaemonFixture(runtime, setup=setup) as session:
                launchers = {
                    (launcher.harness, launcher.event): launcher
                    for launcher in install_priority_launchers(cast(LauncherSession, cast(object, session)))
                }
                for original in build_cases(session.workspace):
                    if (
                        original.setup != setup
                        or not _selected(original)
                        or (original.expected.reason_class == "review") != review_only
                    ):
                        continue
                    case = installed_expectation(original)
                    selected_cases[case.case_id] = case
                    case_digest = hashlib.sha256(case.case_id.encode()).hexdigest()
                    launcher = launchers[case.harness, case.event]
                    if original.expected.reason_class == "review":
                        try:
                            begun = session.control(
                                "launcher_approval_begin",
                                harness=case.harness,
                                payload=dict(case.payload),
                                resolution="allow",
                                timeout_seconds=8,
                            )
                            operation_id = begun.get("operation_id")
                            if begun.get("state") != "waiting" or not isinstance(operation_id, str):
                                raise RuntimeError("qualification launcher approval could not start")
                        except Exception as error:
                            evidence.write(
                                json.dumps(
                                    assert_privacy_safe(
                                        {
                                            "case_digest": case_digest,
                                            "stage": "approval_setup",
                                            "status": "failed",
                                            "failure": failure_evidence(error),
                                        }
                                    ),
                                    separators=(",", ":"),
                                )
                                + "\n"
                            )
                            evidence.flush()
                            raise
                        if case.harness == "claude-code":
                            _attempt(
                                session,
                                launcher,
                                case,
                                stage="initial_ask",
                                evidence=evidence,
                                operation_id=operation_id,
                            )
                            offered_attempts += 1
                        route, _ = _attempt(
                            session,
                            launcher,
                            approved_review_case(case),
                            stage="resolved_retry" if case.harness == "claude-code" else "browser_wait_completion",
                            evidence=evidence,
                            operation_id=operation_id,
                        )
                        review_harnesses.add(case.harness)
                    else:
                        route, _ = _attempt(session, launcher, case, stage="ordinary", evidence=evidence)
                    offered_attempts += 1
                    validated.append(case_digest)
                    validated_ids.append(case.case_id)
                    for name, value in (
                        ("harness", case.harness),
                        ("event", case.event),
                        ("setup", case.setup),
                        ("size", case.size_class),
                        ("route", route),
                        ("delivery", case.expected.reason_class),
                        ("representation", case.payload_kind),
                    ):
                        counts[name][value] += 1
    remaining = set() if review_harnesses == {"claude-code", "codex"} else {"browser_approval_continuation"}
    if not validated:
        raise RuntimeError("installed launcher corpus was empty")
    if review_only and remaining:
        raise RuntimeError("installed launcher approval corpus coverage incomplete")
    platform_scope = platform_scope_summary(tuple(selected_cases.values()), validated_ids)
    remaining.update(platform_scope["missing_scopes"])
    return assert_privacy_safe(
        {
            "schema": "hol-guard.registered-launcher-corpus.v1",
            "boundary": "INSTALLED_LAUNCHER",
            "scope": "priority_approval" if review_only else "priority_fault_corpus",
            "validated_cases": len(validated),
            "validated_attempts": offered_attempts,
            "review_harnesses": sorted(review_harnesses),
            "validated_digest": hashlib.sha256(json.dumps(sorted(validated)).encode()).hexdigest(),
            "coverage": {name: dict(count) for name, count in counts.items()},
            "configuration": "registered_argv_and_env",
            "stdout_and_exit_checked": True,
            "native_and_delivered_checked_independently": True,
            "implemented_scope_passed": True,
            "platform_scope": platform_scope,
            "latency_claim": "semantic_preflight_no_tail_claim",
            "remaining": sorted(remaining | {"nonpriority_registered_launchers", "malformed_launcher_input"}),
            "qualification_complete": False,
        }
    )
