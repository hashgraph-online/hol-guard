"""Record each hook request a real harness sends to the in-process Guard daemon.

Oh My Pi cases observe Guard from inside the agent with ``observer.ts``. Other
harnesses call Guard through their own installed hook commands, so the runner
records the daemon side instead: the request it received, the response it
returned and the validated native receipt for that decision. Wrapping never
changes a decision; it only serializes reviews so each receipt maps to its call.
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
)
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
        self._original = worker.review_http_payload

    def __enter__(self) -> GuardTap:
        original = self._original

        def review(**kwargs: Any) -> dict[str, object]:
            with self._lock:
                started = time.monotonic()
                response = original(**kwargs)
                receipt = getattr(self._worker, "_last_native_decision_receipt", None)
                self._record(kwargs, response, receipt, time.monotonic() - started)
                return response

        self._worker.review_http_payload = review
        return self

    def __exit__(self, *_exc: object) -> None:
        self._worker.__dict__.pop("review_http_payload", None)

    def _record(self, kwargs: dict[str, Any], response: Any, receipt: Any, seconds: float) -> None:
        payload = kwargs.get("payload") if isinstance(kwargs.get("payload"), dict) else {}
        row = {
            "route_harness": kwargs.get("default_harness"),
            "payload": {key: payload[key] for key in _PAYLOAD_KEYS if key in payload},
            "response": response if isinstance(response, dict) else None,
            "receipt": {key: receipt.get(key) for key in _RECEIPT_KEYS} if isinstance(receipt, dict) else None,
            "seconds": round(seconds, 4),
        }
        with self._log.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")


def read_tap(path: Path) -> list[dict[str, Any]]:
    """Read tap rows; a missing log means no hook reached Guard."""
    if not path.exists():
        return []
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if any(not isinstance(row, dict) for row in rows):
        raise ValueError("malformed Guard tap row")
    return rows
