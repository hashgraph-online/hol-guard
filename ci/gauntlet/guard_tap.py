"""Record each hook request a real harness sends to the in-process Guard daemon.

Oh My Pi cases observe Guard from inside the agent with ``observer.ts``. Other
harnesses call Guard through their own installed hook commands, so the runner
records the daemon side instead: the request it received, the response it
returned and the validated native receipt for that decision. Wrapping never
changes a decision or its timing: reviews still run concurrently, and each
thread keeps the receipt its own review accepted.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

_PAYLOAD_KEYS = (
    "hook_event_name",
    "tool_name",
    "tool_input",
    "tool_use_id",
    "tool_call_id",
    "command",
    "file_path",
    "generation_id",
    # The workspace and session a contained-run snapshot names; see codex_contained.
    "cwd",
    "session_id",
)
# How long leaving the tap waits for reviews that are still running to finish.
_DRAIN_SECONDS = 15.0
_RECEIPT_KEYS = (
    "harness",
    "event_name",
    "decision",
    "reason_code",
    "policy_action",
    "observed_policy_action",
    "observe_mode",
    "decision_id",
)


class GuardTap:
    """Append one JSON row per reviewed hook request to ``log``."""

    def __init__(self, worker: Any, log: Path):
        self._worker = worker
        self._log = log
        self._lock = threading.Lock()
        self._receipts = threading.local()
        self._in_flight = 0
        self._exited = False
        self._drained = threading.Condition()
        self._capture: Any = None
        self._original = worker.review_http_payload
        self._record_receipt = worker._record_native_decision_receipt

    def __enter__(self) -> GuardTap:
        original = self._original
        record_receipt = self._record_receipt

        def capture_receipt(receipt: object) -> Any:
            accepted = record_receipt(receipt)
            self._receipts.accepted = accepted
            return accepted

        def review(**kwargs: Any) -> dict[str, object]:
            # Holding a lock across the review would queue a parallel tool batch behind
            # its slowest call and push the rest past their hook deadlines.
            self._receipts.accepted = None
            with self._drained:
                self._in_flight += 1
            try:
                started = time.monotonic()
                response = original(**kwargs)
                seconds = time.monotonic() - started
                self._record(kwargs, response, self._receipts.accepted, seconds)
                return response
            finally:
                with self._drained:
                    self._in_flight -= 1
                    self._drained.notify_all()
                    if self._exited and self._in_flight == 0:
                        self._remove_recorder()

        self._capture = capture_receipt
        self._worker._record_native_decision_receipt = capture_receipt
        self._worker.review_http_payload = review
        return self

    def __exit__(self, *_exc: object) -> None:
        self._worker.__dict__.pop("review_http_payload", None)
        # A review that started before exit still needs the receipt recorder, and
        # its row belongs in the log the case reads next.
        # A review still running after the wait removes the recorder when it ends.
        with self._drained:
            self._exited = True
            if self._drained.wait_for(lambda: self._in_flight == 0, timeout=_DRAIN_SECONDS):
                self._remove_recorder()

    def _remove_recorder(self) -> None:
        # Leave a recorder that a later tap installed on the same worker.
        if self._worker.__dict__.get("_record_native_decision_receipt") is self._capture:
            del self._worker.__dict__["_record_native_decision_receipt"]

    def _record(self, kwargs: dict[str, Any], response: Any, receipt: Any, seconds: float) -> None:
        payload = kwargs.get("payload") if isinstance(kwargs.get("payload"), dict) else {}
        row = {
            "route_harness": kwargs.get("default_harness"),
            "payload": {key: payload[key] for key in _PAYLOAD_KEYS if key in payload},
            "response": response if isinstance(response, dict) else None,
            "receipt": {key: receipt.get(key) for key in _RECEIPT_KEYS} if isinstance(receipt, dict) else None,
            "seconds": round(seconds, 4),
        }
        line = json.dumps(row, ensure_ascii=False, default=str) + "\n"
        with self._lock, self._log.open("a", encoding="utf-8") as stream:
            stream.write(line)


def read_tap(path: Path) -> list[dict[str, Any]]:
    """Read tap rows; a missing log means no hook reached Guard."""
    if not path.exists():
        return []
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if any(not isinstance(row, dict) for row in rows):
        raise ValueError("malformed Guard tap row")
    return rows
