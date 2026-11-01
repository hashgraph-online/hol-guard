"""Private native session transport. No SDK, scope or eligibility decisions."""

from __future__ import annotations

import contextlib
from pathlib import Path
from threading import BoundedSemaphore, RLock
from typing import Any

from .native_context import _resolve_digest_home
from .native_context_assistance import ContextAssistanceError
from .native_daemon_route import _decide
from .native_resident_decision import ResidentOperation, shape_fields

_OPERATION = ResidentOperation(
    operation="context_agent",
    feature="context-assistance-agents-v1",
    prefix="native_context_assistance",
    request_schema="guard-context-agent-request.v1",
    result_schema="guard-context-agent-result.v1",
    request_id_prefix="context-agent",
    timeout_seconds=8.0,
    error=ContextAssistanceError,
    shared_resident_health=False,
)
_SLOTS = BoundedSemaphore(2)
CONTEXT_TOOLS = (
    "get_context_status",
    "get_guard_context",
    "explain_guard_context",
    "explain_guard_action",
    "propose_guard_context_note",
    "get_guard_context_proposal_status",
    "forget_guard_context_proposal",
)


class NativeContextAgent:
    """One MCP process's private credential, never a tool argument or result.

    Unknown begin outcomes are not retried. A lost/restarted authority needs a
    fresh MCP process and human pairing; no saved grant is restored here.
    """

    def __init__(self, guard_home: Path) -> None:
        self._home = guard_home
        self._credential: str | None = None
        self._attempted = False
        self._lock = RLock()

    def _ask(self, message: dict[str, object]) -> dict[str, Any]:
        home = _resolve_digest_home(self._home)

        def validate(answer: dict[str, Any]) -> None:
            data = shape_fields(
                answer["data"],
                {"schema": str, "data_role": bool, "result": dict},
                lambda: ContextAssistanceError(_OPERATION.invalid),
            )
            if data["schema"] != "guard-cigar-agent-data.v1" or data["data_role"] is not True:
                raise ContextAssistanceError(_OPERATION.invalid)

        answer = _decide(
            {"kind": "agent", "guard_home": str(home), "input": message},
            home,
            {"data": dict},
            validate,
            operation=_OPERATION,
            slots=_SLOTS,
            max_request_bytes=64 * 1024,
        )
        return answer["data"]["result"]

    def _ensure(self) -> None:
        discovery = self._ask({"action": "discover"})
        if discovery.get("available") is not True:
            self._credential = None
            return
        if self._credential is None and not self._attempted:
            self._attempted = True
            private = self._ask({"action": "begin"})
            credential = private.get("credential")
            if not isinstance(credential, str) or len(credential) != 64:
                raise ContextAssistanceError(_OPERATION.invalid)
            self._credential = credential

    def tool_names(self) -> tuple[str, ...]:
        with self._lock:
            try:
                self._ensure()
                if self._credential is None:
                    return ()
                state = self._ask({"action": "status", "credential": self._credential, "arguments": {}})
                names = state.get("tools")
                if not isinstance(names, list) or any(name not in CONTEXT_TOOLS for name in names):
                    raise ContextAssistanceError(_OPERATION.invalid)
                return tuple(names)
            except (ContextAssistanceError, OSError, RuntimeError, ValueError):
                return ()

    def call(self, name: str, arguments: dict[str, object]) -> dict[str, Any]:
        actions: dict[str, str] = dict(
            zip(
                CONTEXT_TOOLS,
                (
                    "status",
                    "compile",
                    "explain",
                    "review_action",
                    "propose_note",
                    "proposal_status",
                    "forget_proposal",
                ),
                strict=True,
            )
        )
        with self._lock:
            self._ensure()
            # Rust validates the entire nested argument object. Caller fields
            # cannot overwrite framing, the credential or an authority scope.
            return self._ask({"action": actions[name], "credential": self._credential or "", "arguments": arguments})

    def close(self) -> None:
        with self._lock:
            credential, self._credential = self._credential, None
            if credential is not None:
                # Finite native leases still expire after process loss.
                with contextlib.suppress(ContextAssistanceError, OSError, RuntimeError, ValueError):
                    self._ask({"action": "close", "credential": credential})
