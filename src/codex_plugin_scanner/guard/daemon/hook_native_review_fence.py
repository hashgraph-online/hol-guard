"""Retain the command mutation lease through native review and local reuse."""

from __future__ import annotations

import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path

from ..native_command_control_authority_io import hold_command_control_authority_lock


@contextmanager
def native_review_fence(
    *,
    policy_snapshot: Mapping[str, object] | None,
    event_name: str,
    recording_only: bool,
    guard_home: Path,
    deadline: float | None,
) -> Iterator[bool]:
    bound = policy_snapshot is not None and (
        policy_snapshot.get("command_extensions_bound") is True
        or isinstance(policy_snapshot.get("command_extensions"), Mapping)
    )
    if not bound or event_name != "PreToolUse" or recording_only:
        yield False
        return
    # A missing deadline grants no additional lock wait. Normal HTTP callers
    # supply their original absolute deadline; it is never reset here.
    timeout = 0.0 if deadline is None else max(0.0, deadline - time.monotonic())
    with hold_command_control_authority_lock(guard_home, timeout_seconds=timeout, shared=True):
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError("native_review_fence_deadline")
        yield True
