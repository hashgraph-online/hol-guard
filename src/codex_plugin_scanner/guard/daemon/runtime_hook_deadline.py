"""One monotonic budget shared by every runtime-hook stage."""

from __future__ import annotations

import math
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

_MIN_BUDGET_SECONDS: Final = 0.1
_MAX_BUDGET_SECONDS: Final = 4.0
_MAX_EXPLICIT_BUDGET_SECONDS: Final = 10.0
_DEFAULT_BUDGET_SECONDS: Final = 4.0
# The first prompt in a new workspace waits for its policy overlay to publish,
# which can outlast the tool-hook budget. Prompts arrive once per turn, so every
# harness gets the longer prompt budget.
PROMPT_ADMISSION_SECONDS: Final = 10.0
_TRANSPORT_RESERVE_SECONDS: Final = 0.25
_SERIALIZATION_RESERVE_SECONDS: Final = 0.05


@dataclass(frozen=True, slots=True)
class RuntimeHookDeadline:
    """Immutable absolute deadline derived once from a bounded duration hint."""

    expires_at: float
    transport_reserve_seconds: float = _TRANSPORT_RESERVE_SECONDS
    serialization_reserve_seconds: float = _SERIALIZATION_RESERVE_SECONDS

    @classmethod
    def from_remaining_hint(
        cls,
        remaining_seconds: object,
        *,
        monotonic: Callable[[], float] = time.monotonic,
        maximum_budget_seconds: float = _MAX_BUDGET_SECONDS,
    ) -> RuntimeHookDeadline:
        budget = max(
            _MIN_BUDGET_SECONDS,
            cls.clamp_budget(remaining_seconds, maximum_budget_seconds=maximum_budget_seconds)
            - _TRANSPORT_RESERVE_SECONDS,
        )
        return cls(expires_at=monotonic() + budget)

    @classmethod
    def for_admission(
        cls,
        remaining_hint: float,
        *,
        hint_missing: bool,
        prompt_event: bool,
        admission_seconds: float,
        transport_deadline: float,
    ) -> RuntimeHookDeadline:
        """Bound the client's hint by the admitted request's transport deadline."""
        if prompt_event:
            hinted = cls.from_remaining_hint(
                admission_seconds if hint_missing else remaining_hint,
                monotonic=lambda: transport_deadline - admission_seconds,
                maximum_budget_seconds=PROMPT_ADMISSION_SECONDS,
            )
        else:
            hinted = cls.from_remaining_hint(remaining_hint)
        return cls(expires_at=min(hinted.expires_at, transport_deadline))

    @staticmethod
    def clamp_budget(remaining_seconds: object, *, maximum_budget_seconds: float = _MAX_BUDGET_SECONDS) -> float:
        if (
            isinstance(maximum_budget_seconds, bool)
            or not math.isfinite(maximum_budget_seconds)
            or not _MIN_BUDGET_SECONDS <= maximum_budget_seconds <= _MAX_EXPLICIT_BUDGET_SECONDS
        ):
            raise ValueError("maximum hook budget must be between 0.1 and 10 seconds")
        if isinstance(remaining_seconds, bool) or not isinstance(remaining_seconds, (int, float)):
            return min(_DEFAULT_BUDGET_SECONDS, maximum_budget_seconds)
        value = float(remaining_seconds)
        if not math.isfinite(value):
            return min(_DEFAULT_BUDGET_SECONDS, maximum_budget_seconds)
        return min(maximum_budget_seconds, max(_MIN_BUDGET_SECONDS, value))

    def remaining(self, *, monotonic: Callable[[], float] = time.monotonic) -> float:
        return max(0.0, self.expires_at - monotonic())

    def remaining_for_work(self, *, monotonic: Callable[[], float] = time.monotonic) -> float:
        return max(0.0, self.remaining(monotonic=monotonic) - self.serialization_reserve_seconds)

    def can_dispatch(
        self,
        predicted_seconds: float,
        *,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> bool:
        return predicted_seconds <= self.remaining_for_work(monotonic=monotonic)


__all__ = ["PROMPT_ADMISSION_SECONDS", "RuntimeHookDeadline"]
