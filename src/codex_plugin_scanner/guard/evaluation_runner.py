"""Bounded built-in evaluation adapters.

The first runner phase exercises only disposable local witnesses through a
fixed synthetic adapter.  It deliberately does not invoke the installed
Guard host, inspect host traces, or produce an :class:`EvaluationResult`.
Those bindings are required before an enforcement outcome can be reported.
"""

from __future__ import annotations

import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast
from urllib.parse import urlsplit
from urllib.request import Request

from .adapters.hook_python_subprocess import run_probe
from .evaluation_contracts import EVALUATION_STATUSES, EvaluationContractError, EvaluationProfile
from .evaluation_preflight import EvaluationSetup
from .evaluation_witness import FileWitnessPair, LocalSideEffectWitness, WitnessObservation
from .mdm.contracts import ManagedNetworkPolicy
from .mdm.network import managed_urlopen

SHELL_CASE_ID = "eval.shell.disposable_delete"
EGRESS_CASE_ID = "eval.egress.loopback"
BUILT_IN_CASE_IDS = (SHELL_CASE_ID, EGRESS_CASE_ID)
SYNTHETIC_PROOF_TYPE = "synthetic_adapter_test"
_SYNTHETIC_BOUNDARY_REASON = "synthetic_adapter_does_not_bind_installed_host"
_MAX_ADAPTER_OUTPUT_BYTES = 2 * 64 * 1024
_MAX_ADAPTER_TIMEOUT_SECONDS = 30.0
_MAX_SYNTHETIC_DURATION_SECONDS = 120.0
_LOOPBACK_POLICY = ManagedNetworkPolicy(proxy_mode="none")


class EvaluationRunnerError(EvaluationContractError):
    """A privacy-safe runner failure with a stable code and status."""

    def __init__(self, code: str, message: str, *, status: str = "blocked_environment") -> None:
        super().__init__(message)
        self.code = code
        self.status = status


class _WitnessSetupError(Exception):
    """Internal marker separating witness setup from case execution."""


class _WitnessCaseError(Exception):
    """Internal marker for non-contract witness operation failures."""


class _WitnessCleanupError(Exception):
    """Internal marker separating witness cleanup from case execution."""


@dataclass(frozen=True, slots=True)
class EvaluationRunContext:
    deadline: float
    output_limit_bytes: int


class EvaluationAdapter(Protocol):
    """Common case adapter shape reserved for a future host-bound adapter."""

    mode: str
    proof_type: str

    def run_case(
        self,
        case_id: str,
        witness: LocalSideEffectWitness,
        *,
        ctx: EvaluationRunContext,
    ) -> dict[str, object]: ...


def _profile_case_ids(profile: EvaluationProfile) -> tuple[str, ...]:
    expected = cast(list[object], profile.data["expectedCapabilities"])
    ids: list[str] = []
    for item in expected:
        if not isinstance(item, Mapping):
            raise EvaluationRunnerError("case_profile_invalid", "evaluation cases are invalid", status="not_run")
        case_id = item.get("capabilityId")
        action = item.get("expectedAction")
        if not isinstance(case_id, str) or case_id not in BUILT_IN_CASE_IDS or action != "block":
            raise EvaluationRunnerError(
                "case_not_supported",
                "profile cases are not supported by this runner",
                status="not_run",
            )
        if case_id in ids:
            raise EvaluationRunnerError("case_profile_invalid", "evaluation cases are invalid", status="not_run")
        ids.append(case_id)
    if not ids:
        raise EvaluationRunnerError("case_profile_invalid", "evaluation cases are invalid", status="not_run")
    return tuple(ids)


def validate_case_selection(profile: EvaluationProfile, requested: Sequence[str] | None = None) -> tuple[str, ...]:
    """Require built-in IDs and exact coverage of the profile capabilities."""

    expected = _profile_case_ids(profile)
    selected = expected if requested is None else tuple(requested)
    if not selected or any(case_id not in BUILT_IN_CASE_IDS for case_id in selected):
        raise EvaluationRunnerError(
            "case_not_supported",
            "requested evaluation case is not supported",
            status="not_run",
        )
    if len(set(selected)) != len(selected) or set(selected) != set(expected):
        raise EvaluationRunnerError(
            "case_coverage_invalid",
            "requested cases do not cover the profile capabilities",
            status="not_run",
        )
    return selected


def _ensure_time(ctx: EvaluationRunContext) -> None:
    if time.monotonic() >= ctx.deadline:
        raise EvaluationRunnerError("run_timeout", "evaluation run exceeded its configured deadline")


def _remaining(ctx: EvaluationRunContext) -> float:
    _ensure_time(ctx)
    return max(0.001, ctx.deadline - time.monotonic())


def _fixed_file_control(pair: FileWitnessPair, *, ctx: EvaluationRunContext) -> None:
    """Write the generated allowed marker with one fixed Python template."""

    if pair.allowed_target.parent != pair.denied_target.parent:
        raise EvaluationRunnerError("fixture_rejected", "generated fixture is outside the owned witness")
    target_literal = repr(str(pair.allowed_target))
    command = [
        str(Path(sys.executable)),
        "-c",
        f"from pathlib import Path\nPath({target_literal}).write_bytes(b'synthetic-control')\n",
    ]
    timeout_seconds = min(_remaining(ctx), _MAX_ADAPTER_TIMEOUT_SECONDS)
    try:
        result = run_probe(
            command,
            cwd=pair.allowed_target.parent,
            env={},
            timeout_seconds=timeout_seconds,
            output_limit_bytes=min(ctx.output_limit_bytes, _MAX_ADAPTER_OUTPUT_BYTES),
        )
    except EvaluationRunnerError:
        raise
    except (OSError, RuntimeError, ValueError):
        raise EvaluationRunnerError("control_failed", "allowed control did not complete") from None
    if result.timed_out:
        raise EvaluationRunnerError("run_timeout", "evaluation run exceeded its configured deadline")
    if result.output_overflow:
        raise EvaluationRunnerError("output_limit_exceeded", "evaluation output exceeded its configured limit")
    if result.capture_incomplete:
        raise EvaluationRunnerError("control_capture_incomplete", "evaluation control capture was incomplete")
    if result.returncode != 0:
        raise EvaluationRunnerError("control_failed", "allowed control did not complete")


def _fixed_network_control(url: str, *, ctx: EvaluationRunContext) -> None:
    """Send one empty POST to the generated loopback witness route."""

    try:
        parsed = urlsplit(url)
        valid_route = (
            parsed.scheme == "http"
            and parsed.hostname == "127.0.0.1"
            and parsed.port is not None
            and parsed.path.startswith("/probe/")
            and not parsed.query
            and not parsed.fragment
        )
    except ValueError:
        valid_route = False
    if not valid_route:
        raise EvaluationRunnerError("fixture_rejected", "generated receiver route is invalid")
    _ensure_time(ctx)
    try:
        request = Request(url, data=b"", method="POST")
        with managed_urlopen(
            request,
            timeout=min(_remaining(ctx), _MAX_ADAPTER_TIMEOUT_SECONDS),
            policy=_LOOPBACK_POLICY,
        ) as response:
            if response.status != 204:
                raise EvaluationRunnerError("control_failed", "allowed control did not complete")
    except EvaluationRunnerError:
        raise
    except (OSError, ValueError):
        raise EvaluationRunnerError("control_failed", "allowed control did not complete") from None


def _case_record(
    case_id: str,
    *,
    status: str,
    observation: WitnessObservation | None = None,
    error: EvaluationRunnerError | None = None,
) -> dict[str, object]:
    record: dict[str, object] = {
        "caseId": case_id,
        "status": status,
        "expectedAction": "block",
        "observedAction": None,
        "proofType": SYNTHETIC_PROOF_TYPE,
        "receiverReady": observation.receiver_ready if observation is not None else False,
        "deniedReached": observation.denied_reached if observation is not None else False,
        "allowedReached": observation.allowed_reached if observation is not None else False,
        "controlObserved": observation.allowed_reached if observation is not None else False,
        "hostEventBound": False,
        "guardDecisionBound": False,
        "reason": _SYNTHETIC_BOUNDARY_REASON if error is None else str(error),
    }
    if error is not None:
        record["errorCode"] = error.code
    return record


def _run_shell_case(witness: LocalSideEffectWitness, *, ctx: EvaluationRunContext) -> dict[str, object]:
    _ensure_time(ctx)
    if not witness.check_file_ready():
        raise EvaluationRunnerError("receiver_not_ready", "file witness is not ready")
    pair = witness.new_file_pair()
    _ensure_time(ctx)
    # The denied adapter is a local stub: it performs no write.  The allowed
    # control uses the fixed bounded subprocess template above.
    _fixed_file_control(pair, ctx=ctx)
    _ensure_time(ctx)
    observation = witness.observe_file_pair(pair)
    if not observation.receiver_conditions_met:
        raise EvaluationRunnerError("control_not_observed", "file witness did not observe the allowed control")
    return _case_record(SHELL_CASE_ID, status="blocked_environment", observation=observation)


def _run_egress_case(witness: LocalSideEffectWitness, *, ctx: EvaluationRunContext) -> dict[str, object]:
    _ensure_time(ctx)
    pair = witness.new_network_pair()
    if not witness.check_network_ready(timeout_seconds=min(_remaining(ctx), 2.0)):
        raise EvaluationRunnerError("receiver_not_ready", "loopback receiver is not ready")
    _ensure_time(ctx)
    # The denied adapter is a local stub: it makes no request.  The allowed
    # control uses only the generated loopback endpoint.
    _fixed_network_control(pair.allowed_url, ctx=ctx)
    _ensure_time(ctx)
    observation = witness.observe_network_pair(pair)
    if not observation.receiver_conditions_met:
        raise EvaluationRunnerError("control_not_observed", "loopback witness did not observe the allowed control")
    return _case_record(EGRESS_CASE_ID, status="blocked_environment", observation=observation)


def _run_case(case_id: str, witness: LocalSideEffectWitness, *, ctx: EvaluationRunContext) -> dict[str, object]:
    if case_id == SHELL_CASE_ID:
        return _run_shell_case(witness, ctx=ctx)
    if case_id == EGRESS_CASE_ID:
        return _run_egress_case(witness, ctx=ctx)
    raise EvaluationRunnerError("case_not_supported", "requested evaluation case is not supported", status="not_run")


class SyntheticAdapter:
    """Fixed local adapter; it cannot produce installed-host enforcement proof."""

    mode = "synthetic_adapter"
    proof_type = SYNTHETIC_PROOF_TYPE

    def run_case(
        self,
        case_id: str,
        witness: LocalSideEffectWitness,
        *,
        ctx: EvaluationRunContext,
    ) -> dict[str, object]:
        return _run_case(case_id, witness, ctx=ctx)


def _summary(cases: Sequence[Mapping[str, object]]) -> dict[str, int]:
    counts = {"passed": 0, "failed": 0, "blockedEnvironment": 0, "unsupported": 0, "notRun": 0}
    for case in cases:
        status = case.get("status")
        if not isinstance(status, str):
            counts["failed"] += 1
            continue
        key = {
            "blocked_environment": "blockedEnvironment",
            "not_run": "notRun",
        }.get(status, status)
        if key in counts:
            counts[key] += 1
        else:
            counts["failed"] += 1
    return counts


def _append_aborted(cases: list[dict[str, object]], remaining: Sequence[str]) -> None:
    for case_id in remaining:
        cases.append(
            _case_record(
                case_id,
                status="not_run",
                error=EvaluationRunnerError("run_aborted", "evaluation run stopped after an earlier case"),
            )
        )


def _enter_witness(witness: LocalSideEffectWitness) -> LocalSideEffectWitness:
    try:
        return witness.__enter__()
    except Exception as exc:
        raise _WitnessSetupError from exc


def _run_adapter_case(
    adapter: EvaluationAdapter,
    case_id: str,
    witness: LocalSideEffectWitness,
    *,
    ctx: EvaluationRunContext,
) -> dict[str, object]:
    try:
        return adapter.run_case(case_id, witness, ctx=ctx)
    except EvaluationRunnerError:
        raise
    except Exception as exc:
        raise _WitnessCaseError from exc


def _exit_witness(witness: LocalSideEffectWitness) -> None:
    try:
        witness.__exit__(None, None, None)
    except Exception as exc:
        raise _WitnessCleanupError from exc


def run_synthetic_cases(
    profile: EvaluationProfile,
    setup: EvaluationSetup,
    *,
    requested: Sequence[str] | None = None,
    adapter: EvaluationAdapter | None = None,
) -> dict[str, object]:
    """Run selected built-in cases and return a non-evaluative report."""

    selected = validate_case_selection(profile, requested)
    if setup.report.status != "passed" or setup.root_path is None:
        raise EvaluationRunnerError("setup_unavailable", "evaluation setup is unavailable")
    limits = cast(Mapping[str, object], profile.data["resourceLimits"])
    duration = float(cast(int, limits["maxDurationSeconds"]))
    output_limit = cast(int, limits["maxOutputBytes"])
    deadline = time.monotonic() + min(duration, _MAX_SYNTHETIC_DURATION_SECONDS)
    ctx = EvaluationRunContext(deadline=deadline, output_limit_bytes=output_limit)
    selected_adapter = SyntheticAdapter() if adapter is None else adapter
    if selected_adapter.mode != "synthetic_adapter" or selected_adapter.proof_type != SYNTHETIC_PROOF_TYPE:
        raise EvaluationRunnerError("adapter_rejected", "evaluation adapter is not synthetic", status="not_run")
    cases: list[dict[str, object]] = []
    cleanup_error: EvaluationRunnerError | None = None
    witness = LocalSideEffectWitness(setup=setup, network_enabled=EGRESS_CASE_ID in selected)
    try:
        active_witness = _enter_witness(witness)
    except _WitnessSetupError:
        raise EvaluationRunnerError("witness_setup_failed", "synthetic witness setup failed") from None
    try:
        for index, case_id in enumerate(selected):
            try:
                cases.append(_run_adapter_case(selected_adapter, case_id, active_witness, ctx=ctx))
            except EvaluationRunnerError as error:
                cases.append(_case_record(case_id, status=error.status, error=error))
                _append_aborted(cases, selected[index + 1 :])
                break
            except _WitnessCaseError:
                error = EvaluationRunnerError("witness_failed", "synthetic witness operation failed")
                cases.append(_case_record(case_id, status=error.status, error=error))
                _append_aborted(cases, selected[index + 1 :])
                break
    finally:
        try:
            _exit_witness(witness)
        except _WitnessCleanupError:
            cleanup_error = EvaluationRunnerError("witness_cleanup_failed", "synthetic witness cleanup failed")
    if cleanup_error is not None and not cases:
        raise cleanup_error
    statuses = {s if isinstance(s := case.get("status"), str) else "" for case in cases}
    if "failed" in statuses or not statuses or not statuses <= EVALUATION_STATUSES:
        status = "failed"
    elif "blocked_environment" in statuses:
        status = "blocked_environment"
    elif "unsupported" in statuses:
        status = "unsupported"
    elif "not_run" in statuses:
        status = "not_run"
    else:
        status = "passed"
    report: dict[str, object] = {
        "mode": "synthetic_adapter",
        "proofBoundary": SYNTHETIC_PROOF_TYPE,
        "setupBoundary": "fixture_only",
        "hostExecution": "not_run",
        "status": status,
        "cases": cases,
        "summary": _summary(cases),
    }
    if cleanup_error is not None:
        report["cleanupErrorCode"] = cleanup_error.code
    return report


__all__ = [
    "BUILT_IN_CASE_IDS",
    "EGRESS_CASE_ID",
    "SHELL_CASE_ID",
    "SYNTHETIC_PROOF_TYPE",
    "EvaluationAdapter",
    "EvaluationRunContext",
    "EvaluationRunnerError",
    "SyntheticAdapter",
    "run_synthetic_cases",
    "validate_case_selection",
]
