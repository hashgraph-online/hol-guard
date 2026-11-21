"""Transport for the Rust process that holds the policy generation lock."""

from __future__ import annotations

import json
import subprocess
import threading
import time
from collections.abc import Mapping
from contextlib import suppress
from queue import Empty, Queue
from typing import TYPE_CHECKING

from .native_hook_authority_state import hook_authority_state
from .native_hook_decision import _tilde_home
from .native_runtime import _isolated_environment, native_runtime_status

if TYPE_CHECKING:
    from .store import GuardStore

_FEATURE = "claude-question-save-locked-v2"
_ACK = b"locked\n"
_MAX_REPLY = 4096


def _read_reply(child: subprocess.Popen[bytes], limit: int, deadline: float, request: bytes | None = None) -> bytes:
    stdin, stdout = child.stdin, child.stdout
    assert stdin is not None and stdout is not None
    reply: Queue[bytes] = Queue(maxsize=1)

    def exchange() -> None:
        try:
            if request is not None:
                stdin.write(request + b"\n")
                stdin.flush()
            reply.put(stdout.readline(limit))
        except (OSError, ValueError):
            reply.put(b"")

    threading.Thread(target=exchange, daemon=True).start()
    return reply.get(timeout=max(0.0, deadline - time.monotonic()))


def _write_question(store: GuardStore, request: dict[str, object], deadline: float) -> bool:
    from .library_calls import LibraryCallError
    from .routes.policy_write_calls import integrity_begin, integrity_finalize

    status = native_runtime_status(deadline_monotonic=deadline)
    remaining_ms = int((deadline - time.monotonic()) * 1000)
    if (
        remaining_ms <= 0
        or not status.available
        or not status.compatible
        or status.capabilities is None
        or _FEATURE not in status.capabilities.features
        or status.identity is None
    ):
        return False
    argv = (str(status.identity.path), "claude-question-save", str(store.guard_home), str(remaining_ms))
    try:
        with subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=_isolated_environment(),
        ) as child:
            try:
                if _read_reply(child, len(_ACK), deadline) != _ACK:
                    return False
                if child.poll() is not None or time.monotonic() >= deadline:
                    return False
                generation = integrity_begin(store, {"now": request["now"], "sign": True})
                for field in ("current_generation", "integrity_key_b64", "integrity_key_id"):
                    if field not in generation:
                        return False
                    request[field] = generation[field]
                request["prepared_control_state"] = store._read_policy_integrity_control_state_uncached(strict=True)
                data = json.dumps(request, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode()
                if time.monotonic() >= deadline:
                    return False
                output = _read_reply(child, _MAX_REPLY, deadline, data)
                if not output.endswith(b"\n") or child.poll() is not None or time.monotonic() >= deadline:
                    return False
                result = json.loads(output)
                if not isinstance(result, dict) or result.get("saved") is not True:
                    return False
                # The writer keeps the generation lock until stdin closes.
                # Rust validated this state before committing the policy rows.
                integrity_finalize(store, result)
                assert child.stdin is not None
                child.stdin.close()
                return child.wait(timeout=max(0.0, deadline - time.monotonic())) == 0
            finally:
                if child.poll() is None:
                    with suppress(ProcessLookupError):
                        child.kill()
                    child.wait()
    except (Empty, LibraryCallError, OSError, RuntimeError, ValueError, subprocess.TimeoutExpired):
        return False


def save_claude_guard_question(
    store: GuardStore,
    *,
    session_id: str,
    question: str,
    settlement: Mapping[str, object],
    now: str,
    deadline: float | None,
) -> bool:
    expires = time.monotonic() + 5.0 if deadline is None else deadline
    pending = {
        "artifact_id": settlement.get("artifact_id"),
        "pending_artifact_hash": settlement.get("pending_artifact_hash"),
        "pending_id": settlement.get("pending_id"),
    }
    if not all(isinstance(pending[key], str) and pending[key] for key in ("artifact_id", "pending_artifact_hash")):
        return False
    saved = _write_question(
        store,
        {"session_id": session_id, "question": question, "now": now, "tilde_home": _tilde_home(), **pending},
        expires,
    )
    if not saved or time.monotonic() >= expires:
        return False
    consumed = hook_authority_state(store, "claude_question_consume", now=now, session_id=session_id, payload=pending)
    return consumed is not None and consumed.get("consumed") is True
