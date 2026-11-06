"""Shared immutable types for the reviewed command corpus oracle."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

OracleFloor = Literal["allow", "warn", "review", "require-reapproval", "sandbox-required", "block"]
DecisionStatus = Literal["decidable", "context-required", "uncertain"]


@dataclass(frozen=True, slots=True)
class OracleSeed:
    workflow_family: str
    effects: tuple[str, ...]
    target_scope: str
    uncertainties: tuple[str, ...]
    required_proofs: tuple[str, ...]
    minimum_floor: OracleFloor
    decision_status: DecisionStatus
    owner: str


@dataclass(frozen=True, slots=True)
class OracleRecord:
    case_id: str
    workflow_family: str
    effects: tuple[str, ...]
    target_scope: str
    uncertainties: tuple[str, ...]
    required_proofs: tuple[str, ...]
    provided_proofs: tuple[str, ...]
    minimum_floor: OracleFloor
    decision_status: DecisionStatus
    source_id: str
    owner: str


@dataclass(frozen=True, slots=True)
class PairOracleFacts:
    effects: tuple[str, ...]
    target_scope: str
    reversibility: str
    uncertainties: tuple[str, ...]
    required_proofs: tuple[str, ...]
    minimum_floor: OracleFloor
