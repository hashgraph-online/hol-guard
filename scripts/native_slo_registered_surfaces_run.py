"""Execute real registered hook processes against an otherwise idle fixture.

This tranche is a semantic smoke proof at small pre-tool/1 KiB inline output
sizes. It does not claim full host application activation, load, cold resident,
large/source-reference output, Watch, approval-resume or fault qualification.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Protocol, cast

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.codex_hook_launch_runtime import run_isolated_hook_process
from scripts.native_probe_receipts import wait_for_route_corpus
from scripts.native_slo_adapter import route_counts
from scripts.native_slo_contract import clear_proof_environment
from scripts.native_slo_daemon_fixture import witnessed_route
from scripts.native_slo_priority_launchers import LauncherSession
from scripts.native_slo_registered_surfaces import (
    SURFACE_EVENTS,
    RegisteredSurface,
    SurfaceUnavailableError,
    install_registered_surface,
    read_registered_surfaces,
)
from scripts.native_slo_registered_surfaces_evidence import SurfaceAttempt, SurfaceEvidence
from scripts.native_slo_workloads import (
    ExpectedResponse,
    QualificationCase,
    _validate_projection,
    build_cases,
    installed_response_expectation,
    validate_native_result,
    validate_setup,
)


class SurfaceSession(LauncherSession, Protocol):
    def control(self, operation: str, **arguments: object) -> Mapping[str, object]: ...


def surface_cases(cases: Sequence[QualificationCase], surface: RegisteredSurface) -> tuple[QualificationCase, ...]:
    """Select actual aliases and intrinsic file/MCP reviews from the frozen corpus."""
    return tuple(
        case
        for case in cases
        if case.harness == surface.harness
        and case.event == surface.event
        and case.setup == "normal"
        and case.size_class in {"small", "1k"}
        and case.case_id.split("/")[2] in {"benign", "dangerous", "normal", "block"}
        and "guard_source_ref" not in case.payload
    )


def delivery_expectation(case: QualificationCase) -> tuple[ExpectedResponse, int]:
    """Independent delivered contracts, frozen separately from runtime renderers."""
    if case.harness in {"cursor", "cline"}:
        return installed_response_expectation(case)
    if case.harness not in {"copilot", "kimi", "grok", "zcode"}:
        raise ValueError("registered_surface_delivery_unqualified")
    if case.setup != "normal":
        raise ValueError("registered_surface_setup_unqualified")
    restrictive = case.expected.policy_action in {"block", "review", "require-reapproval", "sandbox-required"}
    if case.harness == "copilot":
        # Copilot consumes its binary top-level command-hook disposition.
        # A Claude-shaped daemon object does not prove this contract.
        pre = case.canonical_event == "PreToolUse"
        return ExpectedResponse(
            ("deny" if restrictive else "allow") if pre else "observation_only",
            "not_applicable" if pre else "unreviewed_original",
            case.expected.reason_class,
            {"permissionDecision": "deny" if restrictive else "allow"},
            ("permissionDecisionReason",) if restrictive else (),
        ), 0
    # The CLI bridge preserves these canonical native fields for Kimi/Grok/
    # ZCode. Kimi/Grok/ZCode gate pre-tools with exit 2;
    # post-tools return zero, including an explicit output-block JSON result.
    code = 2 if restrictive and case.canonical_event == "PreToolUse" else 0
    return case.expected, code


def validate_surface_delivery(
    case: QualificationCase,
    response: Mapping[str, object],
    exit_code: int,
    stderr: str,
) -> None:
    expected, wanted_exit = delivery_expectation(case)
    if type(exit_code) is not int or exit_code != wanted_exit:
        raise AssertionError("registered_surface_exit_mismatch")
    _validate_projection(expected, response, case.case_id)
    if case.harness == "copilot":
        permitted = {"permissionDecision", "permissionDecisionReason", "approval_reuse", "scanner_evidence"}
        if not set(response) <= permitted:
            raise AssertionError("registered_surface_copilot_schema_mismatch")
    if case.harness == "kimi" and wanted_exit == 2 and not stderr.strip():
        raise AssertionError("registered_surface_kimi_block_reason_missing")


def _context(session: LauncherSession) -> HarnessContext:
    return HarnessContext(home_dir=session.root, workspace_dir=session.workspace, guard_home=session.guard_home)


def observe_registered_surface(
    session: LauncherSession,
    surface: RegisteredSurface,
    case: QualificationCase,
    *,
    attempt: SurfaceAttempt | None = None,
) -> tuple[dict[str, object], float]:
    """Include process creation, exact stdin, bounded stdout/stderr and exit."""
    if (case.harness, case.event) != (surface.harness, surface.event):
        raise ValueError("registered_surface_case_route_mismatch")
    if attempt is not None:
        attempt.stage = "registration"
    current = read_registered_surfaces(_context(session), surface.harness)
    if surface not in current:
        raise RuntimeError("registered_surface_registration_changed")
    environment = dict(os.environ)
    clear_proof_environment(environment)
    configured = dict(surface.environment)
    if clear_proof_environment(configured):
        raise RuntimeError("registered_surface_proof_override_in_registration")
    environment.update(configured)
    environment.pop("HOL_GUARD_CLINE_CANARY", None)
    environment["HOME"] = str(session.root)
    environment["USERPROFILE"] = str(session.root)
    encoded = json.dumps(case.payload, separators=(",", ":"), ensure_ascii=True)
    if len(encoded.encode()) > 256 * 1024:
        raise ValueError("registered_surface_smoke_payload_limit")
    started = time.perf_counter()
    if attempt is not None:
        attempt.stage = "process"
    completed = run_isolated_hook_process(
        surface.argv,
        input_text=encoded,
        cwd=surface.cwd,
        environment=environment,
        timeout_seconds=10.0,
        output_limit=2 * 1024 * 1024,
    )
    elapsed_ms = (time.perf_counter() - started) * 1000
    if attempt is not None:
        attempt.attempted_exit = completed.returncode
    if (
        completed.returncode is None
        or completed.timed_out
        or completed.containment_failed
        or completed.output_limit_exceeded
    ):
        raise RuntimeError("registered_surface_process_containment_failed")
    if attempt is not None:
        attempt.stage = "delivery"
    try:
        response: object = json.loads(completed.stdout)
    except (ValueError, UnicodeDecodeError) as error:
        raise RuntimeError("registered_surface_stdout_not_json") from error
    if not isinstance(response, dict):
        raise RuntimeError("registered_surface_stdout_not_object")
    validate_surface_delivery(case, response, completed.returncode, completed.stderr)
    if attempt is not None:
        attempt.stage = "readback_after"
    if surface not in read_registered_surfaces(_context(session), surface.harness):
        raise RuntimeError("registered_surface_registration_changed")
    # Raw stdout/stderr contain synthetic sensitive samples and must not escape
    # into logs or qualification artifacts. Only semantic checks are retained.
    return {"stdout_checked": True, "exit_checked": True}, elapsed_ms


def remaining_surface_assessment() -> list[dict[str, object]]:
    """Scope statements supported by installed adapters, not HTTP route names."""
    return [
        {
            "harness": "pi",
            "status": "separate_probe",
            "boundary": "generated_extension_tool_result_callback",
            "probe": "ci/native_runtime/probe_installed_pi_output.py",
            "full_host_activation": False,
        },
        {
            "harness": "omp",
            "status": "separate_probe",
            "boundary": "generated_extension_tool_result_callback",
            "probe": "ci/native_runtime/probe_installed_pi_output.py",
            "full_host_activation": False,
        },
        {
            "harness": "hermes",
            "status": "not_executed",
            "pre": "config_yaml_pre_tool_call_and_exact_shell_allowlist",
            "post": "unavailable",
        },
        {
            "harness": "openclaw",
            "status": "not_executed",
            "pre": "managed_overlay_and_pretool_bundle_only_read",
            "host_activation": "unproven",
            "post": "unavailable",
        },
        {
            "harness": "opencode",
            "status": "not_executed",
            "pre": "global_plugin_tool_execute_before",
            "host_activation": "unproven",
            "post": "unavailable",
        },
        {"harness": "grok", "post": "unavailable"},
        {"harness": "zcode", "post": "normalizer_only_not_installed"},
        {"harness": "antigravity", "pre": "preflight_only", "post": "unavailable"},
        {"harness": "gemini", "pre": "detected_external_only", "post": "unavailable"},
        {"harness": "paseo", "pre": "unavailable", "post": "unavailable"},
    ]


def run_registered_surface_corpus(
    session: SurfaceSession,
    *,
    harnesses: Sequence[str] = tuple(SURFACE_EVENTS),
    evidence_file: Path | None = None,
) -> dict[str, object]:
    """Run semantic smoke cases; caller owns installed artifact and normal policy.

    The fixture must expose case_before/case_result witnesses. For Cline it
    must additionally use the production default Guard home for its private
    HOME. Unsupported paths remain explicit; every attempted process failure
    or semantic/route mismatch raises and fails the qualification block.
    """
    with SurfaceEvidence(evidence_file) as evidence:
        return _run_registered_surface_corpus(session, harnesses=harnesses, journal=evidence)


def _run_registered_surface_corpus(
    session: SurfaceSession,
    *,
    harnesses: Sequence[str],
    journal: SurfaceEvidence,
) -> dict[str, object]:
    if not harnesses or len(set(harnesses)) != len(harnesses) or any(item not in SURFACE_EVENTS for item in harnesses):
        raise ValueError("registered_surface_harness_selection_invalid")
    cases = build_cases(session.workspace)
    reports: list[dict[str, object]] = []
    unavailable: list[dict[str, object]] = []
    for harness in harnesses:
        try:
            surfaces = install_registered_surface(_context(session), harness)
        except SurfaceUnavailableError as error:
            unavailable.append({"harness": harness, "reason": str(error), "executed": False})
            continue
        for surface in surfaces:
            selected = surface_cases(cases, surface)
            if not selected:
                raise RuntimeError("registered_surface_empty_case_selection")
            for case in selected:
                attempt = SurfaceAttempt()
                journal.offer(f"{surface.scope}/{case.case_id}", surface.registration_sha256)
                try:
                    session.control("case_before")
                    metrics = session.daemon._server.hook_worker.metrics
                    before = route_counts(metrics.snapshot())
                    process, elapsed_ms = observe_registered_surface(session, surface, case, attempt=attempt)
                    attempt.stage = "route"
                    after = route_counts(wait_for_route_corpus(metrics, expected=sum(before.values()) + 1))
                    route = witnessed_route(before, after)
                    attempt.route = route
                    evidence: Mapping[str, object] | None = None
                    try:
                        if route != case.expected_route:
                            raise AssertionError("registered_surface_native_route_mismatch")
                        attempt.stage = "witness"
                        evidence = session.control("case_result")
                        validate_setup(case, cast(Mapping[str, object], evidence["setup"]))
                        validate_native_result(case, cast(Mapping[str, object] | None, evidence["native_result"]))
                    except Exception as error:
                        from scripts.native_slo_surface_failure import enrich_surface_failure

                        enriched = enrich_surface_failure(
                            error,
                            case_id=case.case_id,
                            registration_digest=surface.registration_sha256,
                            stage=attempt.stage,
                            expected_route=case.expected_route,
                            observed_route=route,
                            routes_before=before,
                            routes_after=after,
                            surface_scope=surface.scope,
                            evidence=evidence,
                            read_evidence=(lambda: session.control("case_result"))
                            if attempt.stage == "route"
                            else None,
                        )
                        if enriched is error:
                            raise
                        raise enriched from error
                    attempt.stage = "complete"
                except BaseException:
                    journal.finish("failed", attempt)
                    raise
                else:
                    journal.finish("completed", attempt)
                expected, expected_exit = delivery_expectation(case)
                reports.append(
                    {
                        "harness": harness,
                        "event": surface.event,
                        "scope": surface.scope,
                        "case_id": case.case_id,
                        "registration_sha256": surface.registration_sha256,
                        "artifact_sha256": dict(surface.artifact_sha256),
                        "matchers_read_back": len(surface.matchers),
                        "matched_tool": "Bash" if surface.matchers else "event_slot",
                        "route": route,
                        "delivery": expected.decision,
                        "model_action": expected.model_action,
                        "latency_ms": elapsed_ms,
                        "exit_code": expected_exit,
                        **process,
                    }
                )
    return {
        "schema": "hol-guard.registered-surfaces-smoke.v1",
        "boundary": "INSTALLED_LAUNCHER",
        "evidence_class": "semantic_smoke",
        "process_startup_included": True,
        "full_host_activation": False,
        "qualification_complete": False,
        "oracle_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "validated_cases": len(reports),
        "cases": reports,
        "unsupported": unavailable,
        "remaining_surfaces": remaining_surface_assessment(),
        "remaining_dimensions": [
            "load",
            "cold_resident",
            "large_output",
            "source_reference",
            "watch",
            "faults",
            "approval_resume",
        ],
    }
