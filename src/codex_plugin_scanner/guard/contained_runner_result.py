"""Typed result of a resident-run contained local runner (Node, TypeScript, Bun script)."""

from __future__ import annotations

from dataclasses import dataclass

from .runtime.effect_decision import EffectDecision, PositiveProof


@dataclass(frozen=True, slots=True)
class ContainedRunnerResult:
    exit_code: int
    stdout: str
    stderr: str
    proof: PositiveProof
    decision: EffectDecision
    operation_id: str


__all__ = ("ContainedRunnerResult",)
