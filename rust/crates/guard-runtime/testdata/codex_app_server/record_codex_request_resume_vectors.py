"""Record codex request-resume parity vectors from the Python state machine.

Run from a checkout whose ``codex_resume.py`` still holds the Python
implementation. Each vector seeds approval, operation and resume rows, runs one
call through the real ``store_resume`` SQL, stubs the app-server dispatch and
records the returned value or error, every dispatch call and the final row.
"""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

from codex_plugin_scanner.guard import codex_resume, store_resume

_RESUME_COLUMNS = (
    "request_id",
    "operation_id",
    "harness",
    "resolution_action",
    "strategy",
    "supported",
    "status",
    "thread_id",
    "reason",
    "message",
    "last_error",
    "attempt_count",
    "created_at",
    "updated_at",
    "last_attempt_at",
    "sent_at",
)


class _Store:
    def __init__(self, vector: dict[str, Any]) -> None:
        self.connection = sqlite3.connect(":memory:")
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(store_resume.resume_schema_statement())
        store_resume.ensure_resume_schema(self.connection)
        self.approval = vector.get("approval_request")
        self.operation = vector.get("operation")
        existing = vector.get("existing_resume")
        if existing is not None:
            columns = ", ".join(existing)
            marks = ", ".join("?" for _ in existing)
            self.connection.execute(
                f"insert into guard_request_resumes ({columns}) values ({marks})",
                tuple(existing.values()),
            )

    def get_approval_request(self, request_id: str) -> dict[str, object] | None:
        return None if self.approval is None else {"request_id": request_id, **self.approval}

    def get_guard_operation_for_approval_request(self, request_id: str) -> dict[str, object] | None:
        return self.operation

    def seed_request_resume(self, **kwargs: Any) -> None:
        store_resume.seed_request_resume(self.connection, **kwargs)

    def get_request_resume(self, request_id: str) -> dict[str, object] | None:
        return store_resume.get_request_resume(self.connection, request_id)

    def update_request_resume(self, **kwargs: Any) -> None:
        store_resume.update_request_resume(self.connection, **kwargs)

    def final_row(self, request_id: str) -> dict[str, object] | None:
        row = self.connection.execute(
            f"select {', '.join(_RESUME_COLUMNS)} from guard_request_resumes where request_id = ?",
            (request_id,),
        ).fetchone()
        return None if row is None else {key: row[key] for key in _RESUME_COLUMNS}


def _record(vector: dict[str, Any]) -> dict[str, Any]:
    store = _Store(vector)
    call = vector["call"]
    calls: list[dict[str, object]] = []

    def _dispatch(*, store: object, request_id: str, action: str, **kwargs: object) -> dict[str, object] | None:
        calls.append({"request_id": request_id, "action": action, "timeout_seconds": kwargs.get("timeout_seconds")})
        return vector.get("dispatch_result")

    codex_resume.resume_codex_thread_for_request = _dispatch  # type: ignore[assignment]
    codex_resume._live_hook_wait_is_active = lambda **_: True  # type: ignore[assignment]
    request_id = call["request_id"]
    expected: dict[str, Any]
    try:
        if call["kind"] == "seed":
            result = codex_resume.seed_request_resume_record(store, request_id=request_id, now=call["now"])  # type: ignore[arg-type]
        elif call["kind"] == "status":
            result = codex_resume.get_request_resume_status(store, request_id=request_id, now=call["now"])  # type: ignore[arg-type]
        elif call["kind"] == "retry":
            result = codex_resume.retry_request_resume(
                store,  # type: ignore[arg-type]
                request_id=request_id,
                now=call["now"],
                force=call.get("force", False),
                timeout_seconds=call.get("timeout_seconds"),
            )
        else:
            store.operation = {
                "harness": "codex",
                "status": "waiting_on_approval",
                "metadata": {"hook_event_name": "Stop"},
                **(store.operation or {}),
            }
            result = codex_resume.defer_request_resume_to_live_hook(
                store,  # type: ignore[arg-type]
                request_id=request_id,
                action=call["action"],
                now=call["now"],
            )
        expected = {"result": result}
    except ValueError as error:
        expected = {"error": str(error)}
    expected["dispatch_calls"] = calls
    expected["final_row"] = store.final_row(request_id)
    return {**vector, "expected": expected}


def main() -> None:
    source = Path(sys.argv[1])
    vectors = json.loads(source.read_text())["vectors"]
    recorded = [_record(vector) for vector in vectors]
    print(json.dumps({"schema": "codex-request-resume-vectors.v1", "vectors": recorded}, indent=2))


if __name__ == "__main__":
    main()
