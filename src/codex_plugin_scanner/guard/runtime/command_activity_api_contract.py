"""Strict local API contracts for privacy-safe command activity."""

# pyright: reportAny=false, reportUnnecessaryIsInstance=false

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date
from enum import Enum
from typing import Final, cast

from .command_activity_contract import (
    COMMAND_ACTIVITY_HARNESSES,
    ActivityApprovalReuseStatus,
    CommandExecutionStatus,
    CommandProofLevel,
)

COMMAND_ACTIVITY_API_SCHEMA_VERSION: Final = "guard.command-activity-api.v1"
COMMAND_ACTIVITY_PAGE_DEFAULT: Final = 50
COMMAND_ACTIVITY_PAGE_MAX: Final = 100
COMMAND_ACTIVITY_ANALYTICS_DAYS_MAX: Final = 397
COMMAND_ACTIVITY_ANALYTICS_TOP_MAX: Final = 50
_STABLE_ID: Final[re.Pattern[str]] = re.compile(r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*")


class CommandActivityFeedbackLabel(str, Enum):
    SHOULD_NOT_HAVE_INTERRUPTED = "should_not_have_interrupted"
    EXPECTED_GUARD_TO_STOP_THIS = "expected_guard_to_stop_this"


@dataclass(frozen=True, slots=True)
class CommandActivityListQuery:
    limit: int = COMMAND_ACTIVITY_PAGE_DEFAULT
    harness: str | None = None
    execution_status: str | None = None
    proof_level: str | None = None
    prompted: bool | None = None
    approval_reuse_status: str | None = None
    extension_id: str | None = None
    rule_id: str | None = None
    occurred_from: date | None = None
    occurred_through: date | None = None

    def __post_init__(self) -> None:
        if type(self.limit) is not int or not 1 <= self.limit <= COMMAND_ACTIVITY_PAGE_MAX:
            raise ValueError("limit_out_of_range")
        if self.harness is not None and self.harness not in COMMAND_ACTIVITY_HARNESSES:
            raise ValueError("invalid_harness")
        _require_optional_enum(self.execution_status, CommandExecutionStatus, "invalid_execution_status")
        _require_optional_enum(self.proof_level, CommandProofLevel, "invalid_proof_level")
        if self.prompted is not None and type(self.prompted) is not bool:
            raise ValueError("invalid_prompted")
        _require_optional_enum(
            self.approval_reuse_status,
            ActivityApprovalReuseStatus,
            "invalid_approval_reuse_status",
        )
        _require_optional_stable_id(self.extension_id, "invalid_extension_id")
        _require_optional_stable_id(self.rule_id, "invalid_rule_id")
        if self.occurred_from is not None and type(cast(object, self.occurred_from)) is not date:
            raise ValueError("invalid_occurred_from")
        if self.occurred_through is not None and type(cast(object, self.occurred_through)) is not date:
            raise ValueError("invalid_occurred_through")
        if (
            self.occurred_from is not None
            and self.occurred_through is not None
            and self.occurred_from > self.occurred_through
        ):
            raise ValueError("invalid_date_range")
        if (
            self.occurred_from is not None
            and self.occurred_through is not None
            and (self.occurred_through - self.occurred_from).days >= COMMAND_ACTIVITY_ANALYTICS_DAYS_MAX
        ):
            raise ValueError("date_range_out_of_range")

    def binding(self) -> tuple[object, ...]:
        return (
            self.harness,
            self.execution_status,
            self.proof_level,
            self.prompted,
            self.approval_reuse_status,
            self.extension_id,
            self.rule_id,
            self.occurred_from.isoformat() if self.occurred_from else None,
            self.occurred_through.isoformat() if self.occurred_through else None,
        )


@dataclass(frozen=True, slots=True)
class CommandActivityAnalyticsQuery:
    days: int = 90
    top_limit: int = 10
    dimension: str | None = None
    dimension_value: str | None = None

    def __post_init__(self) -> None:
        if type(self.days) is not int or not 1 <= self.days <= COMMAND_ACTIVITY_ANALYTICS_DAYS_MAX:
            raise ValueError("days_out_of_range")
        if type(self.top_limit) is not int or not 1 <= self.top_limit <= COMMAND_ACTIVITY_ANALYTICS_TOP_MAX:
            raise ValueError("top_limit_out_of_range")
        if (self.dimension is None) != (self.dimension_value is None):
            raise ValueError("incomplete_dimension_filter")
        if self.dimension is not None and self.dimension not in {"harness", "extension", "rule"}:
            raise ValueError("invalid_dimension")
        _require_optional_stable_id(self.dimension_value, "invalid_dimension_value")
        if self.dimension == "harness" and self.dimension_value not in COMMAND_ACTIVITY_HARNESSES:
            raise ValueError("invalid_harness")


def _require_optional_enum(value: str | None, enum_type: type[Enum], error: str) -> None:
    if value is None:
        return
    if not isinstance(value, str) or value not in {str(item.value) for item in enum_type}:
        raise ValueError(error)


def _require_optional_stable_id(value: str | None, error: str) -> None:
    if value is not None and (not isinstance(value, str) or len(value) > 256 or _STABLE_ID.fullmatch(value) is None):
        raise ValueError(error)


__all__ = (
    "COMMAND_ACTIVITY_ANALYTICS_DAYS_MAX",
    "COMMAND_ACTIVITY_ANALYTICS_TOP_MAX",
    "COMMAND_ACTIVITY_API_SCHEMA_VERSION",
    "COMMAND_ACTIVITY_PAGE_DEFAULT",
    "COMMAND_ACTIVITY_PAGE_MAX",
    "CommandActivityAnalyticsQuery",
    "CommandActivityFeedbackLabel",
    "CommandActivityListQuery",
)
