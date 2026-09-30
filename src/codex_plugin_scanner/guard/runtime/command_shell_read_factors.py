"""Mandatory policy floors for direct secret reads and incomplete local-code inspection."""

from __future__ import annotations

from pathlib import Path

from .effect_contract import DecisionBasis
from .effect_decision import DecisionFactor, DecisionFactorSource
from .shell_secret_reads import assess_shell_reads


def shell_read_floor_factors(
    command_text: str,
    security_identity: str,
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> tuple[DecisionFactor, ...]:
    """Produce review floors only, never execution authorization or positive proof."""

    assessment = assess_shell_reads(command_text, cwd=cwd, home_dir=home_dir)
    if not assessment.requires_review:
        return ()
    reason_code = "critical.local-secret-read" if assessment.sensitive_paths else "critical.local-script-execution"
    return (
        DecisionFactor(
            source=DecisionFactorSource.POLICY,
            reason_code=reason_code,
            basis=DecisionBasis("require-reapproval", None),
            operation_ref=f"operation:{security_identity.rsplit(':', 1)[-1]}",
            producer_ref="runtime:shell-read-floors-v1",
        ),
    )
