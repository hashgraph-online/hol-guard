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

_FEATURE = "claude-question-save-locked-v1"
_ACK = b"locked\n"


def _write_question(store: GuardStore, request: dict[str, object], deadline: float) -> dict[str, object] | None:
    from .routes.policy_write_calls import integrity_begin

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
        return None
    argv = (str(status.identity.path), "claude-question-save", str(store.guard_home), str(remaining_ms))
    try:
        with subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=_isolated_environment(),
        ) as child:
            assert child.stdout is not None
            stdout = child.stdout
            ack: Queue[bytes] = Queue(maxsize=1)

            def read_ack() -> None:
                try:
                    ack.put(stdout.readline(len(_ACK)))
                except OSError:
                    ack.put(b"")

            threading.Thread(target=read_ack, daemon=True).start()
            try:
                if ack.get(timeout=max(0.0, deadline - time.monotonic())) != _ACK:
                    return None
                if child.poll() is not None or time.monotonic() >= deadline:
                    return None
                generation = integrity_begin(store, {"now": request["now"], "sign": True})
                for field in ("current_generation", "integrity_key_b64", "integrity_key_id"):
                    if field not in generation:
                        return None
                    request[field] = generation[field]
                data = json.dumps(request, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                output, _ = child.communicate(input=data, timeout=remaining)
                if child.returncode != 0:
                    return None
                result = json.loads(output)
                return result if isinstance(result, dict) else None
            finally:
                if child.poll() is None:
                    with suppress(ProcessLookupError):
                        child.kill()
                    child.wait()
    except (Empty, OSError, RuntimeError, ValueError, subprocess.TimeoutExpired):
        return None


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
    result = _write_question(
        store,
        {"session_id": session_id, "question": question, "now": now, "tilde_home": _tilde_home(), **pending},
        expires,
    )
    if result is None or result.get("saved") is not True or time.monotonic() >= expires:
        return False
    state = result.get("next_control_state")
    try:
        finalized = isinstance(state, dict) and store._finalize_policy_integrity_control_state(state, deadline=expires)
    except (OSError, RuntimeError, ValueError):
        return False
    if not finalized:
        return False
    if time.monotonic() >= expires:
        return False
    consumed = hook_authority_state(store, "claude_question_consume", now=now, session_id=session_id, payload=pending)
    return consumed is not None and consumed.get("consumed") is True
