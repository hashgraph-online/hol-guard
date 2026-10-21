"""Stable, value-free CLI responses for evidence package failures."""

from __future__ import annotations

from .evaluation_cli_recovery import _CliError
from .evaluation_contracts import EvaluationContractError
from .evaluation_evidence_package import EvaluationEvidencePackageError

_PACKAGE_ERRORS: dict[str, tuple[str, str, str]] = {
    "output_exists": ("output_exists", "evaluation evidence package already exists", "blocked_environment"),
    "output_scope": (
        "output_scope_invalid",
        "evaluation evidence output is outside the profile private temporary scope",
        "blocked_environment",
    ),
    "output_limit": (
        "evidence_package_invalid",
        "evaluation evidence package exceeds the declared output limit",
        "failed",
    ),
    "invalid_text": ("evidence_package_invalid", "evaluation evidence package contains invalid text", "failed"),
    "output_unavailable": (
        "output_unavailable",
        "safe evaluation evidence package writing is unavailable",
        "blocked_environment",
    ),
    "write_failed": (
        "evidence_package_write_failed",
        "evaluation evidence package could not be written safely",
        "blocked_environment",
    ),
}


def package_write_error(error: EvaluationContractError) -> _CliError:
    """Map typed writer failures without inspecting caller-controlled text."""

    if isinstance(error, EvaluationEvidencePackageError):
        mapped = _PACKAGE_ERRORS.get(error.code)
        if mapped is not None:
            code, message, status = mapped
            return _CliError(code, message, status=status)
    return _CliError("evidence_package_invalid", "evaluation evidence package is invalid", status="failed")
