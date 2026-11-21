"""Transport for the resident's policy-source fence wait and accounting."""

from __future__ import annotations

import math
import time
import uuid
from pathlib import Path
from typing import cast, final

from .native_execution import _resident_request

_WRITE_FEATURE = "hook-policy-fence-window-write-v1"
_WAIT_FEATURE = "hook-policy-fence-window-wait-v1"
_REQUEST_SCHEMA = "guard-hook-policy-fence-window-request.v1"
_RESULT_SCHEMA = "guard-hook-policy-fence-window-result.v1"
_TIMEOUT_SECONDS = 0.1

POLICY_SOURCE_FENCE_ERROR = "native_business_source_mutation_in_progress"
POLICY_UPDATE_PENDING_REASON_CODE = "native_policy_update_in_progress"
POLICY_UPDATE_PENDING_REASON = "Guard is finishing a policy update; this action was not run. Retry after 8 seconds."


class PolicySourceFenceBusyError(RuntimeError):
    """Native admission was refused because the fence is held."""


def _fence_request(
    guard_home: Path,
    *,
    action: str,
    request_id: str,
    deadline: float | None,
    **fields: object,
) -> dict[str, object] | None:
    try:
        canonical_home = guard_home.resolve(strict=False)
    except (OSError, RuntimeError):
        canonical_home = guard_home
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": request_id,
        "guard_home": str(canonical_home),
        "action": action,
        "persist_events": True,
        **fields,
    }
    try:
        # Leave is cleanup for a successful enter. Keep its short transport
        # budget even when the hook's decision deadline has elapsed so the
        # resident registration cannot be stranded.
        timeout_seconds = _TIMEOUT_SECONDS
        if action != "leave" and deadline is not None:
            timeout_seconds = min(timeout_seconds, deadline - time.monotonic())
        if timeout_seconds <= 0:
            return None
        reply = _resident_request(
            operation="hook_policy_fence_window",
            request=request,
            guard_home=canonical_home,
            timeout_seconds=timeout_seconds,
            required_feature=_WAIT_FEATURE if action == "wait" else _WRITE_FEATURE,
            response_schema=_RESULT_SCHEMA,
            record_resilience=False,
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        return None
    result = reply.get("result") if reply is not None else None
    if isinstance(result, dict):
        body = cast(dict[str, object], result)
        if body.get("request_id") == request_id:
            return body
    return None


def _remaining_ms(deadline: float | None, now: float) -> int:
    return max(0, int((deadline - now) * 1000)) if deadline is not None else 0


@final
class PolicySourceFenceWait:
    """Carry the resident's retry plan through the daemon review callback."""

    def __init__(self, deadline: float | None, *, guard_home: Path) -> None:
        self._deadline = deadline
        self._guard_home = guard_home
        self._started: float | None = None
        self._attempt_deadline = deadline
        self._exhausted = False
        self._request_id = f"policy-fence-wait-{uuid.uuid4().hex}"

    def _call(self, action: str, **fields: object) -> dict[str, object] | None:
        return _fence_request(
            self._guard_home, action=action, request_id=self._request_id, deadline=self._deadline, **fields
        )

    def pause(self) -> bool:
        if self._started is None:
            self._started = time.monotonic()
            _ = self._call("enter")
        now = time.monotonic()
        remaining_ms = _remaining_ms(self._deadline, now)
        result = self._call("wait", elapsed_ms=math.ceil((now - self._started) * 1000), remaining_ms=remaining_ms)
        poll = result.get("poll") if result is not None else None
        if isinstance(poll, dict):
            plan = cast(dict[str, object], poll)
            delay_ms = plan.get("sleep_ms")
            retry_ms = plan.get("retry_by_ms")
            attempt_ms = plan.get("attempt_budget_ms")
            if (
                type(delay_ms) is int
                and type(retry_ms) is int
                and type(attempt_ms) is int
                and 0 < delay_ms <= retry_ms <= attempt_ms <= remaining_ms
            ):
                delay = delay_ms / 1000
                retry_by = now + retry_ms / 1000
                # Apply the relative plan from the time it was requested. A
                # late reply or oversleep cannot extend the native budget.
                if time.monotonic() + delay <= retry_by:
                    time.sleep(delay)
                    if time.monotonic() <= retry_by:
                        self._attempt_deadline = now + attempt_ms / 1000
                        return True
        self._exhausted = True
        return False

    @property
    def attempt_deadline(self) -> float | None:
        return self._attempt_deadline

    def finish(self) -> None:
        if self._started is not None:
            self._started = None
            _ = self._call("leave", admitted=not self._exhausted)
