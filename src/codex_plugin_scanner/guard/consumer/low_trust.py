"""Review floor for skills, MCP servers and plugins with a low HOL Registry trust score."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..config import GuardConfig, resolve_risk_action
from ..models import GuardArtifact
from ..registry_trust import (
    LOW_TRUST_RISK_KEY,
    LOW_TRUST_THRESHOLD,
    is_low_trust,
    registry_kind,
    registry_trust_score,
)
from ..runtime.signals import RiskSignalV2

# ``allow`` adds no floor, so the lookup is skipped entirely.
_FLOOR_ACTIONS = frozenset({"warn", "review", "require-reapproval", "sandbox-required", "block"})


@dataclass(frozen=True, slots=True)
class LowTrustFloor:
    action: str
    score: int
    signal: RiskSignalV2


def low_trust_floor(
    guard_home: Path | None,
    config: GuardConfig,
    *,
    harness: str,
    artifact: GuardArtifact,
    configured_action: str | None,
    fresh_decision: bool,
) -> LowTrustFloor | None:
    """Return the review floor for a low-trust artifact, or ``None``.

    Only an unconfigured artifact that is first seen or changed is scored: a
    configured override or an unchanged, already decided artifact keeps its
    decision, and a saved Always allow still applies after the floor raises the
    action.
    """

    if configured_action is not None or not fresh_decision or registry_kind(artifact.artifact_type) is None:
        return None
    action = resolve_risk_action(config, LOW_TRUST_RISK_KEY, harness=harness)
    if action is None or action not in _FLOOR_ACTIONS:
        return None
    score = registry_trust_score(guard_home, artifact_type=artifact.artifact_type, name=artifact.name)
    if score is None or not is_low_trust(score):
        return None
    return LowTrustFloor(action=action, score=score, signal=_low_trust_signal(artifact, score))


def _low_trust_signal(artifact: GuardArtifact, score: int) -> RiskSignalV2:
    return RiskSignalV2(
        signal_id=f"{LOW_TRUST_RISK_KEY}:{artifact.artifact_id}",
        category="publisher",
        severity="medium",
        confidence="likely",
        detector="hol_registry_trust",
        title="Low HOL Registry trust score",
        plain_reason=(
            f"{artifact.name} has a HOL Registry trust score of {score}, below the {LOW_TRUST_THRESHOLD} "
            "Guard asks you to review."
        ),
        technical_detail=f"registry trust score {score} < {LOW_TRUST_THRESHOLD}",
        evidence_ref=None,
        redaction_level="none",
        false_positive_hint=(
            "Allow it if you trust this publisher; set low_trust_artifact to allow to stop these reviews."
        ),
        advisory_id=None,
    )


__all__ = ["LowTrustFloor", "low_trust_floor"]
