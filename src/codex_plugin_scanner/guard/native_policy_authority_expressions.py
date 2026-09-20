"""Immutable row-bound command expressions for authenticated native snapshots."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

from .native_command_expression import native_command_expression_payload
from .native_policy_snapshot_constants import NativePolicySnapshotError
from .policy_document_types import PolicyCompilationError
from .runtime.command_expression import CommandExpressionError, command_expression_from_mapping

NATIVE_COMMAND_EXPRESSIONS_FEATURE = "policy-command-expressions-v1"
_ERROR = "native_policy_authority_command_expression_invalid"


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


@dataclass(frozen=True, slots=True, repr=False)
class NativeScopedCommandExpression:
    decision_id: int
    expression_json: str

    def __post_init__(self) -> None:
        if type(self.decision_id) is not int or not 1 <= self.decision_id <= (1 << 53) - 1:
            raise NativePolicySnapshotError(_ERROR)
        if not isinstance(self.expression_json, str) or len(self.expression_json) > 192 * 1024:
            raise NativePolicySnapshotError(_ERROR)
        try:
            value: object = json.loads(self.expression_json)
            expression = command_expression_from_mapping(value)
            encoded = native_command_expression_payload(expression, rule_id=str(self.decision_id))
            # Reject unknown, omitted, normalized or duplicated fields. The
            # native wire takes an explicit normalized AST, not parser input.
            if encoded != self.expression_json or _canonical(value) != encoded:
                raise NativePolicySnapshotError(_ERROR)
        except (ValueError, TypeError, CommandExpressionError, PolicyCompilationError) as error:
            raise NativePolicySnapshotError(_ERROR) from error

    def to_mapping(self) -> dict[str, object]:
        return {"decision_id": self.decision_id, "expression": json.loads(self.expression_json)}

    @classmethod
    def from_mapping(cls, value: object) -> NativeScopedCommandExpression:
        if not isinstance(value, Mapping) or set(value) != {"decision_id", "expression"}:
            raise NativePolicySnapshotError(_ERROR)
        try:
            return cls(cast(int, value["decision_id"]), _canonical(value["expression"]))
        except (TypeError, ValueError) as error:
            raise NativePolicySnapshotError(_ERROR) from error
