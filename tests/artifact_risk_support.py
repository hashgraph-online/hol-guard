"""Test-side views of the resident's artifact risk profile.

Guard's runtime reads the profile through ``artifact_risk_profile``; these
views keep the signals and their explanations easy to assert on.
"""

from __future__ import annotations

from codex_plugin_scanner.guard import risk
from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.types import GuardSignal


def artifact_risk_signals_typed(artifact: GuardArtifact) -> tuple[GuardSignal, ...]:
    """Return structured risk signals for a Guard artifact."""

    return risk.artifact_risk_profile(artifact).signals


def artifact_risk_signals(artifact: GuardArtifact) -> tuple[str, ...]:
    """String signals derived from structured signals."""

    return tuple(signal.explanation for signal in risk.artifact_risk_profile(artifact).signals)
