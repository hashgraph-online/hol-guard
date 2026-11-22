"""Native store snapshot of what the command queue workers read from each lane."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol


class _NativeStore(Protocol):
    def _native_store_call(
        self, method: str, args: Mapping[str, object], *, busy_timeout_seconds: float | None = None
    ) -> Any: ...


@dataclass(frozen=True)
class CommandQueueLaneRow:
    """One queue lane's state row, as the workers judge it.

    ``readable`` is false when the stored text is not JSON. A missing row, or
    one that is not an object, holds no pending result and records no limit.
    ``exact_lease_batch_limit`` is the stored whole number when it is at least
    one, else one.
    """

    state_key: str
    readable: bool
    pending_result: bool
    has_lease_batch_limit: bool
    exact_lease_batch_limit: int

    @classmethod
    def from_native(cls, answer: object, state_key: str) -> CommandQueueLaneRow:
        if not isinstance(answer, dict) or answer.get("state_key") != state_key:
            raise RuntimeError("native command_queue_lane_rows returned no answer")
        # The native store already settles the limit; an answer without a
        # whole number is a broken runtime, not a stored value to repair.
        limit = answer.get("exact_lease_batch_limit")
        if type(limit) is not int:
            raise RuntimeError("native command_queue_lane_rows returned no lease limit")
        return cls(
            state_key=state_key,
            readable=answer.get("readable") is True,
            pending_result=answer.get("pending_result") is True,
            has_lease_batch_limit=answer.get("has_lease_batch_limit") is True,
            exact_lease_batch_limit=limit,
        )


class StoreCommandQueueLanesMixin:
    """The command queue lanes' state rows, read by the native store in one snapshot."""

    def command_queue_lane_rows(self: _NativeStore, state_keys: Sequence[str]) -> tuple[CommandQueueLaneRow, ...]:
        """Each named lane's row, in the order named.

        Raises ``ValueError`` for a key that is not a command queue lane.
        """

        keys = list(state_keys)
        answer = self._native_store_call("command_queue_lane_rows", {"state_keys": keys})
        lanes = answer.get("lanes") if isinstance(answer, dict) else None
        if not isinstance(lanes, list) or len(lanes) != len(keys):
            raise RuntimeError("native command_queue_lane_rows returned no answer")
        return tuple(CommandQueueLaneRow.from_native(lane, key) for lane, key in zip(lanes, keys, strict=True))


__all__ = ["CommandQueueLaneRow", "StoreCommandQueueLanesMixin"]
