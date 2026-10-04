"""One monotonic budget shared by every runtime-hook stage."""

from __future__ import annotations

import math
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

_MIN_BUDGET_SECONDS: Final = 0.1
_MAX_BUDGET_SECONDS: Final = 4.0
_DEFAULT_BUDGET_SECONDS: Final = 4.0
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
    ) -> RuntimeHookDeadline:
        budget = max(
            _MIN_BUDGET_SECONDS,
            cls.clamp_budget(remaining_seconds) - _TRANSPORT_RESERVE_SECONDS,
        )
        return cls(expires_at=monotonic() + budget)

    @staticmethod
    def clamp_budget(remaining_seconds: object) -> float:
        if isinstance(remaining_seconds, bool) or not isinstance(remaining_seconds, (int, float)):
            return _DEFAULT_BUDGET_SECONDS
        value = float(remaining_seconds)
        if not math.isfinite(value):
            return _DEFAULT_BUDGET_SECONDS
        return min(_MAX_BUDGET_SECONDS, max(_MIN_BUDGET_SECONDS, value))

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


__all__ = ["RuntimeHookDeadline"]
