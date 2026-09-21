"""Immutable scheduler-owned runtime-hook payload."""

from __future__ import annotations

import threading
from concurrent.futures import Future
from dataclasses import dataclass, field

from .runtime_hook_deadline import RuntimeHookDeadline
from .runtime_hook_scheduler_types import RuntimeHookLane


@dataclass(frozen=True, slots=True)
class RuntimeHookWorkItem:
    """A fully hydrated payload with no mutable external-file dependency."""

    normalized_payload: bytes
    harness: str
    event: str
    workspace_fingerprint: str
    client_fingerprint: str
    lane: RuntimeHookLane
    payload_bytes: int
    arrival_sequence: int
    accepted_at: float
    queued_at: float
    deadline: RuntimeHookDeadline
    completion: Future[object] = field(default_factory=Future, compare=False, repr=False)
    cancellation: threading.Event = field(default_factory=threading.Event, compare=False, repr=False)

    def __post_init__(self) -> None:
        if self.payload_bytes != len(self.normalized_payload):
            raise ValueError("payload_bytes must equal the immutable normalized payload length")


__all__ = ["RuntimeHookWorkItem"]
