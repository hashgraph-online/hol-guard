"""Record the original registered Codex waiter without inventing a resume target."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime, timedelta
from pathlib import Path

from ..config import MAX_APPROVAL_WAIT_TIMEOUT_SECONDS, load_guard_config
from ..live_process_identity import (
    CODEX_BROWSER_WAIT_PROCESS_KEY,
    bound_wait_timeout_seconds,
    process_identity_matches,
)
from ..store import GuardStore


def native_codex_wait_operation(
    store: object,
    *,
    harness: str,
    payload: Mapping[str, object],
    workspace: Path | None,
    home_dir: Path | None,
    now: str,
    config_reader: Callable[[Path], dict[str, object]] | None = None,
) -> dict[str, object] | None:
    """Accept only an independently live bridge identity and bounded wait budget."""
    if harness != "codex" or not isinstance(store, GuardStore) or home_dir is None or not home_dir.is_absolute():
        return None
    identity = payload.get(CODEX_BROWSER_WAIT_PROCESS_KEY)
    timeout = bound_wait_timeout_seconds(payload, maximum=MAX_APPROVAL_WAIT_TIMEOUT_SECONDS)
    if not isinstance(identity, Mapping) or not process_identity_matches(identity) or timeout is None:
        return None
    configured = load_guard_config(
        store.guard_home, workspace, config_reader=config_reader
    ).approval_wait_timeout_seconds
    timeout = min(timeout, max(0, configured), MAX_APPROVAL_WAIT_TIMEOUT_SECONDS)
    if timeout <= 0:
        return None
    started = datetime.fromisoformat(now)
    return {
        "created_at": now,
        "updated_at": now,
        "harness": harness,
        "status": "waiting_on_approval",
        "metadata": {
            "hook_event_name": "PreToolUse",
            "workspace": str(workspace) if workspace is not None else None,
            # This came from the validated original ingress, not a resume
            # request. The fresh Rust request digest authenticates its reuse.
            "native_hook_home_dir": str(home_dir),
            "codex_hook_waits_for_browser_approval": True,
            "codex_browser_wait_started_at": now,
            "codex_browser_wait_deadline_at": (started + timedelta(seconds=timeout)).isoformat(),
            "codex_browser_wait_timeout_seconds": timeout,
            "codex_browser_wait_process": dict(identity),
        },
    }


def attach_native_codex_wait(
    store: GuardStore, *, request_id: str, operation: Mapping[str, object], workspace: Path | None, now: str
) -> None:
    """Link the newly persisted exact request to an actual local waiting operation."""
    # Runtime imports avoid the surface runtime -> approvals -> native queue cycle.
    from ..codex_resume import seed_request_resume_record
    from ..runtime.surface_server import GuardSurfaceRuntime

    if store.get_guard_operation_for_approval_request(request_id) is not None:
        raise ValueError("native_codex_wait_already_attached")
    metadata = operation.get("metadata")
    if not isinstance(metadata, Mapping) or not process_identity_matches(metadata.get("codex_browser_wait_process")):
        raise ValueError("native_codex_wait_process_unavailable")
    runtime = GuardSurfaceRuntime(store)
    session = runtime.start_session(
        harness="codex",
        surface="harness-adapter",
        workspace=str(workspace) if workspace is not None else None,
        client_name="codex-native-hook",
        capabilities=("approval-resolution",),
    )
    started = runtime.start_operation(
        session_id=str(session["session_id"]), operation_type="tool_call", harness="codex", metadata=dict(metadata)
    )
    runtime.mark_waiting_on_approval(str(started["operation_id"]), [request_id])
    if seed_request_resume_record(store, request_id=request_id, now=now) is None:
        raise ValueError("native_codex_wait_resume_missing")
