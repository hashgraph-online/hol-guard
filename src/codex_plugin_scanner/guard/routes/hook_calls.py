"""Library steps the native daemon's hook route calls in the resident library process.

The daemon owns ``POST /v1/hooks/<harness>`` and its readiness route: the
caller check, the deadline, directory trust, the admission scheduler and
every reply. What still lives in the Python library -- the hook worker, its
policy publisher and the audit log -- runs here, in the resident process so
the worker and its caches outlive one hook.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

from ..store import GuardStore

_SERVERS: dict[str, Any] = {}
_SERVERS_LOCK = threading.Lock()


def _server(store: GuardStore, args: Mapping[str, Any]) -> Any:
    """The resident's daemon state for this Guard home, built on first use."""

    from ..daemon.auth_token import load_guard_daemon_auth_token
    from .request_host import _replay_server_class

    key = str(store.guard_home)
    with _SERVERS_LOCK:
        server = _SERVERS.get(key)
        if server is None:
            port = args.get("port")
            home_dir = args.get("home_dir")
            daemon_pid = args.get("daemon_pid")
            server = _replay_server_class()(
                store,
                port if isinstance(port, int) else 0,
                "127.0.0.1",
                Path(home_dir) if isinstance(home_dir, str) and home_dir else Path.home(),
                load_guard_daemon_auth_token(store.guard_home) or "",
                daemon_pid if isinstance(daemon_pid, int) else None,
                False,
            )
            _SERVERS[key] = server
        return server


def _text(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _deadline(args: Mapping[str, Any]) -> float:
    remaining = args.get("remaining_seconds")
    seconds = float(remaining) if isinstance(remaining, (int, float)) and not isinstance(remaining, bool) else 0.0
    return time.monotonic() + max(0.0, seconds)


def _payload(args: Mapping[str, Any]) -> dict[str, object]:
    payload = args.get("payload")
    return dict(payload) if isinstance(payload, dict) else {}


def _params(args: Mapping[str, Any]) -> dict[str, list[str]]:
    query = args.get("query")
    return parse_qs(query) if isinstance(query, str) else {}


def _record_path_rejection(server: Any, args: Mapping[str, Any]) -> None:
    rejection = args.get("rejection")
    if not isinstance(rejection, dict):
        return
    from ..daemon.server_common import _now

    with server.denial_audit_lock:
        _ = server.audit_persistence.persist(
            "daemon.hook.path_rejected",
            {
                "method": "POST",
                "path": _text(args.get("path")) or "",
                "parameter": _text(rejection.get("parameter")) or "",
                "reason": _text(rejection.get("reason")) or "",
            },
            _now(),
        )


def hook_begin(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Counts the hook and, for Oh My Pi, asks the resident's direct lane first."""

    from ..adapters import get_adapter
    from ..daemon.hook_direct_counters import note_hook_received
    from ..daemon.hook_direct_pi_transport import pi_direct_answer

    server = _server(store, args)
    worker = getattr(server, "hook_worker", None)
    harness = _text(args.get("harness")) or ""
    note_hook_received(worker, _text(args.get("count_harness")) or harness, _text(args.get("direct_miss")))
    answer = None
    if args.get("try_direct") is True:
        params = _params(args)
        home = params.get("home", [None])[-1]
        answer = pi_direct_answer(
            worker,
            default_harness=harness,
            params=params,
            payload=_payload(args),
            home_dir=home.strip() if isinstance(home, str) and home.strip() else None,
            deadline=_deadline(args),
        )
    try:
        capacity_harness = get_adapter(_text(args.get("capacity_harness")) or harness).harness
    except ValueError:
        capacity_harness = "other"
    return {"answer": answer, "capacity_harness": capacity_harness}


def hook_prepare(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Applies the native-policy barrier and sizes a referenced payload."""

    from ..daemon.hook_fail_closed import unmanaged_passthrough
    from ..daemon.hook_managed_install_state import _canonical_managed_harness, _hook_harness_is_unmanaged
    from ..daemon.hook_policy_admission import _native_policy_not_ready_reason
    from ..daemon.hook_request_parsing import HookPayloadReferenceError, hook_payload_reference_size

    server = _server(store, args)
    _record_path_rejection(server, args)
    harness = _canonical_managed_harness(_text(args.get("harness")) or "")
    if _hook_harness_is_unmanaged(server, harness):
        return {"answer": unmanaged_passthrough(harness)}
    workspace = _text(args.get("workspace"))
    deadline = _deadline(args)
    worker = server.hook_worker
    prepared = worker.prepare_workspace_policy(Path(workspace) if workspace else None, deadline=deadline)
    if prepared is None:
        worker.metrics.record_route("native_fail_safe")
        return {
            "fail_safe": {
                "reason": _native_policy_not_ready_reason(server),
                "reason_code": "native_policy_not_ready",
            }
        }
    try:
        size = hook_payload_reference_size(_payload(args), guard_home=store.guard_home, deadline_monotonic=deadline)
    except HookPayloadReferenceError as error:
        worker.metrics.record_failure(stage="server", exception_type=type(error).__name__)
        return {
            "fail_safe": {
                "reason": "HOL Guard could not authenticate the local hook payload.",
                "reason_code": "invalid_hook_payload_reference",
            }
        }
    return {"reference_bytes": size}


def hook_ready(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Readiness: whether the harness is managed and the workspace's policy is published.

    A `rejection` is a refused Guard home: it is audited and nothing else is
    asked. A `late_rejection` is a refused workspace, which an unmanaged
    harness never reaches, so it is audited only for a managed one.
    """

    from ..daemon.hook_managed_install_state import _hook_harness_is_unmanaged
    from ..daemon.hook_worker import WORKSPACE_POLICY_READINESS_TIMEOUT_SECONDS

    server = _server(store, args)
    _record_path_rejection(server, args)
    if args.get("rejection") is not None:
        return {}
    if _hook_harness_is_unmanaged(server, _text(args.get("harness")) or ""):
        return {"unmanaged": True}
    _record_path_rejection(server, {**args, "rejection": args.get("late_rejection")})
    workspace = _text(args.get("workspace"))
    if workspace is None or args.get("late_rejection") is not None:
        return {"unmanaged": False}
    try:
        prepared = server.hook_worker.prepare_workspace_policy(
            Path(workspace), deadline=time.monotonic() + WORKSPACE_POLICY_READINESS_TIMEOUT_SECONDS
        )
    except Exception:
        server.diagnostics.record_exception("native_workspace_readiness_failed")
        prepared = None
    return {"unmanaged": False, "prepared": isinstance(prepared, dict)}


def hook_review(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """The hook worker's answer, or the fail-safe reason when it raised."""

    from contextlib import nullcontext

    from ..sqlite_tuning import sqlite_operation_deadline

    server = _server(store, args)
    deadline = _deadline(args)
    home_dir = _text(args.get("home_dir_effective"))
    guard_home = _text(args.get("guard_home_effective"))
    workspace = _text(args.get("workspace"))
    with sqlite_operation_deadline(deadline) if deadline is not None else nullcontext():
        try:
            answer = server.hook_worker.review_http_payload(
                payload=_payload(args),
                params=_params(args),
                default_harness=_text(args.get("harness")) or "",
                home_dir=Path(home_dir) if home_dir else server.home_dir,
                guard_home=Path(guard_home) if guard_home else store.guard_home,
                workspace=Path(workspace) if workspace else None,
                deadline=deadline,
            )
        except Exception as error:
            # Fail safe: deny; there is no Python semantic fallback.
            server.hook_worker.metrics.record_failure(stage="server", exception_type=type(error).__name__)
            return {
                "fail_safe": {
                    "reason": "HOL Guard could not complete local hook review safely.",
                    "reason_code": "daemon_worker_exception",
                }
            }
    return {"answer": answer if isinstance(answer, dict) else None}


HOOK_CALLS = {
    "hook.begin": hook_begin,
    "hook.prepare": hook_prepare,
    "hook.ready": hook_ready,
    "hook.review": hook_review,
}
