"""CLI orchestration for the fixture-only synthetic evaluation stage."""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .evaluation_cli_recovery import (
    _CliError,
    _recovery_token_path,
    _remove_recovery_token,
    _write_recovery_token,
)
from .evaluation_contracts import EvaluationContractError, EvaluationProfile
from .evaluation_preflight import setup_evaluation
from .evaluation_runner import EvaluationRunnerError, run_synthetic_cases


@dataclass(frozen=True, slots=True)
class SyntheticCommandResult:
    status: str
    run: Mapping[str, object] | None
    cleanup: Mapping[str, object]
    error: _CliError | None


def _empty_report(status: str, *, reason: str | None = None) -> dict[str, object]:
    report: dict[str, object] = {
        "mode": "synthetic_adapter",
        "proofBoundary": "synthetic_adapter_test",
        "setupBoundary": "fixture_only",
        "hostExecution": "not_run",
        "status": status,
        "cases": [],
        "summary": {"passed": 0, "failed": 0, "blockedEnvironment": 0, "unsupported": 0, "notRun": 0},
    }
    if reason is not None:
        report["reason"] = reason
    return report


def run_synthetic_command(
    profile: EvaluationProfile,
    requested: Sequence[str] | None,
) -> SyntheticCommandResult:
    """Allocate, run, and recover one fixture-only synthetic evaluation."""

    if os.name == "nt":
        error = _CliError(
            "recovery_windows_unavailable",
            "private recovery token storage is unavailable on Windows",
            status="blocked_environment",
        )
        return SyntheticCommandResult(
            status=error.status,
            run=_empty_report(error.status),
            cleanup={"removed": False, "recoveryTokenRetained": False},
            error=error,
        )

    setup = setup_evaluation(profile, allow_host_execution=False, execution_mode="synthetic_adapter")
    if setup.report.status != "passed":
        return SyntheticCommandResult(
            status=setup.report.status,
            run=_empty_report(setup.report.status, reason=setup.report.reason),
            cleanup={"removed": False, "recoveryTokenRetained": False},
            error=_CliError(
                "setup_unavailable",
                "synthetic evaluation setup is unavailable",
                status=setup.report.status,
            ),
        )

    target_scope = cast(Mapping[str, object], profile.data["targetScope"])
    declared_parent = Path(cast(str, target_scope["rootPath"]))
    token_path: Path | None = None
    token_written = False
    run_report: Mapping[str, object] | None = None
    runner_error: _CliError | None = None
    cleanup_removed = False
    token_retained = False
    try:
        root_path = setup.root_path
        if root_path is None:
            raise _CliError("cleanup_token_unavailable", "evaluation setup did not produce a cleanup token")
        token_path = _recovery_token_path(root_path, declared_parent=declared_parent)
        _write_recovery_token(setup, declared_parent=declared_parent)
        token_written = True
        try:
            run_report = run_synthetic_cases(profile, setup, requested=requested)
        except EvaluationRunnerError as error:
            runner_error = _CliError(
                error.code,
                "synthetic evaluation run could not complete",
                status=error.status,
            )
            run_report = _empty_report(error.status)
        except Exception:
            runner_error = _CliError(
                "runner_failed",
                "synthetic evaluation run could not complete",
                status="blocked_environment",
            )
            run_report = _empty_report("blocked_environment")
    except _CliError as error:
        runner_error = error
    finally:
        try:
            cleanup_removed = setup.cleanup()
        except EvaluationContractError:
            cleanup_removed = False
        if cleanup_removed and token_written and token_path is not None:
            try:
                _remove_recovery_token(token_path, expected_parent=Path(os.path.realpath(declared_parent)))
            except _CliError:
                token_retained = True
        elif token_written:
            token_retained = True

    if runner_error is None and run_report is not None:
        status = cast(str, run_report.get("status", "blocked_environment"))
    elif runner_error is not None:
        status = runner_error.status
    else:
        status = "blocked_environment"
    cleanup: dict[str, object] = {"removed": cleanup_removed, "recoveryTokenRetained": token_retained}
    if not cleanup_removed:
        cleanup["reason"] = "cleanup_failed"
        if runner_error is None:
            runner_error = _CliError(
                "cleanup_failed",
                "synthetic evaluation cleanup failed",
                status="blocked_environment",
            )
            status = runner_error.status
    return SyntheticCommandResult(status=status, run=run_report, cleanup=cleanup, error=runner_error)


__all__ = ["SyntheticCommandResult", "run_synthetic_command"]
