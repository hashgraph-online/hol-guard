"""Entrypoint and request execution for isolated daemon hook workers."""

from __future__ import annotations

import argparse
import importlib
import json
import multiprocessing
import os
import signal
import time
from contextlib import suppress
from dataclasses import dataclass
from multiprocessing.connection import Connection
from pathlib import Path
from typing import TYPE_CHECKING, NoReturn, cast

from ..codex_hook_windows_job import assign_current_process_to_windows_hook_job
from ..native_route_receipt import native_hook_route, record_native_hook_route, reset_native_hook_route
from ..sqlite_profile import sqlite_error_is_busy_locked
from .hook_process_protocol import (
    applied_hook_environment,
    as_string_object_dict,
    capture_hook_command,
    is_pair,
)

if TYPE_CHECKING:
    from ..store import GuardStore
    from .hook_worker import HookWorker

_HOOK_SQLITE_TIMEOUT_ENV = "HOL_GUARD_INTERNAL_HOOK_SQLITE_TIMEOUT_MS"
_HOOK_EVALUATOR_READY_TIMEOUT_SECONDS = 12.0


@dataclass(frozen=True)
class _ResidentHookRequest:
    payload: dict[str, object]
    harness: str
    home_dir: Path
    guard_home: Path
    workspace: Path | None
    claim_saved_approval: bool
    claimed_saved_allow_hash: str | None
    claimed_trusted_request_override: bool
    claimed_approval_request_id: str | None


def hook_worker_main(connection: Connection, configured_guard_home: str | None) -> None:
    windows_job = None
    if os.name == "nt":
        windows_job = assign_current_process_to_windows_hook_job()
        if windows_job is None:
            connection.send(("isolation_failed", None))
            return
    else:
        try:
            os.setsid()
        except OSError:
            connection.send(("isolation_failed", None))
            return
    connection.send(
        (
            "isolated",
            {
                "process_group_id": os.getpid() if os.name != "nt" else None,
                "windows_job_contained": windows_job is not None,
            },
        )
    )
    context = multiprocessing.get_context("spawn")
    guardian_connection, evaluator_connection = context.Pipe(duplex=True)
    evaluator = context.Process(
        target=_hook_evaluator_main,
        args=(evaluator_connection, configured_guard_home),
        name="hol-guard-hook-evaluator",
        daemon=True,
    )
    try:
        evaluator.start()
    except BaseException:
        guardian_connection.close()
        evaluator_connection.close()
        connection.send(("worker_failed", None))
        _hold_containment_anchor()
    evaluator_connection.close()
    try:
        if not guardian_connection.poll(_HOOK_EVALUATOR_READY_TIMEOUT_SECONDS) or guardian_connection.recv() != (
            "ready",
            None,
        ):
            connection.send(("worker_failed", None))
            _hold_containment_anchor()
        connection.send(("ready", None))
        while True:
            try:
                raw_message = cast(object, connection.recv())
            except EOFError:
                _terminate_guardian_group()
                return
            if is_pair(raw_message) and raw_message[0] == "stop":
                with suppress(BrokenPipeError, OSError):
                    guardian_connection.send(("stop", None))
                evaluator.join(timeout=0.2)
                _hold_containment_anchor()
            try:
                guardian_connection.send(raw_message)
                response = guardian_connection.recv()
            except (BrokenPipeError, EOFError, OSError):
                connection.send(("worker_failed", None))
                _hold_containment_anchor()
            connection.send(response)
    finally:
        guardian_connection.close()
        _ = windows_job


def _hold_containment_anchor() -> NoReturn:
    while True:
        time.sleep(60)


def _terminate_guardian_group() -> None:
    if os.name != "nt":
        with suppress(OSError):
            os.killpg(os.getpid(), getattr(signal, "SIGKILL", 9))


def _hook_evaluator_main(connection: Connection, configured_guard_home: str | None) -> None:
    os.environ[_HOOK_SQLITE_TIMEOUT_ENV] = "250"
    for module_name in (
        "codex_plugin_scanner.guard.adapters.base",
        "codex_plugin_scanner.guard.cli.commands_hook",
        "codex_plugin_scanner.guard.cli.commands_support_connect",
        "codex_plugin_scanner.guard.config",
        "codex_plugin_scanner.guard.daemon.hook_worker",
        "codex_plugin_scanner.guard.store",
    ):
        _ = importlib.import_module(module_name)
    stores: dict[str, GuardStore] = {}
    hook_workers: dict[str, HookWorker] = {}
    if configured_guard_home is not None:
        from ..store import GuardStore

        guard_home = Path(configured_guard_home).resolve(strict=False)
        # The worker can become ready while a concurrent daemon migration
        # finishes; the first request retries store construction lazily.
        with suppress(Exception):
            stores[str(guard_home)] = GuardStore(
                guard_home,
                prime_policy_integrity=False,
                daemon_managed_schema=True,
            )
    try:
        connection.send(("ready", None))
    except (BrokenPipeError, EOFError, OSError):
        return
    while True:
        try:
            raw_message = cast(object, connection.recv())
        except EOFError:
            return
        if not is_pair(raw_message):
            try:
                connection.send(("result", {"payload": None, "reason_code": "daemon_hook_process_invalid_request"}))
            except (BrokenPipeError, EOFError, OSError):
                return
            continue
        message_type, raw_request = raw_message
        if message_type == "stop":
            return
        typed_request = as_string_object_dict(raw_request)
        if message_type != "review" or typed_request is None:
            try:
                connection.send(("result", {"payload": None, "reason_code": "daemon_hook_process_invalid_request"}))
            except (BrokenPipeError, EOFError, OSError):
                return
            continue
        try:
            response = _run_resident_hook_request(
                typed_request,
                stores=stores,
                hook_workers=hook_workers,
                configured_guard_home=configured_guard_home,
            )
        except BaseException as error:
            reason_code = (
                "daemon_hook_process_not_ready" if sqlite_error_is_busy_locked(error) else "daemon_hook_process_failed"
            )
            response = {"payload": None, "reason_code": reason_code}
        try:
            connection.send(("result", response))
        except (BrokenPipeError, EOFError, OSError):
            return


def _run_resident_hook_request(
    request: dict[str, object],
    *,
    stores: dict[str, GuardStore],
    hook_workers: dict[str, HookWorker],
    configured_guard_home: str | None,
) -> dict[str, object]:
    from ..adapters.base import HarnessContext
    from ..cli.commands_hook import _run_guard_hook_command
    from ..cli.commands_support_connect import _synced_policy_payload
    from ..config import load_guard_config, overlay_synced_guard_policy
    from ..store import GuardStore
    from .hook_worker import HookWorker, HookWorkerUnsupported, post_tool_fail_safe_response, runtime_hook_event_name

    parsed = _coerce_resident_hook_request(request)
    if parsed is None:
        return {"payload": None, "reason_code": "daemon_hook_process_invalid_request"}
    reset_native_hook_route()
    if configured_guard_home is not None and parsed.guard_home != Path(configured_guard_home):
        return {"payload": None, "reason_code": "daemon_hook_process_guard_home_mismatch"}
    store_key = str(parsed.guard_home)
    store = stores.get(store_key)
    if store is None:
        store = GuardStore(
            parsed.guard_home,
            prime_policy_integrity=False,
            daemon_managed_schema=True,
        )
        stores[store_key] = store
    context = HarnessContext(
        home_dir=parsed.home_dir,
        workspace_dir=parsed.workspace,
        guard_home=parsed.guard_home,
        home_override_explicit=True,
        workspace_override_explicit=parsed.workspace is not None,
    )
    event_name = runtime_hook_event_name(parsed.payload)
    if _native_mode_requires_rust() or event_name in {"PreToolUse", "PostToolUse"}:
        worker = hook_workers.get(store_key)
        if worker is None:
            worker = HookWorker(store=store)
            hook_workers[store_key] = worker
        try:
            worker_payload = worker.review_http_payload(
                payload=parsed.payload,
                params={"runtime-harness": [parsed.harness]},
                default_harness=parsed.harness,
                home_dir=parsed.home_dir,
                guard_home=parsed.guard_home,
                workspace=parsed.workspace,
            )
        except HookWorkerUnsupported:
            if _native_mode_requires_rust():
                record_native_hook_route("native_fail_safe")
                return {
                    "payload": post_tool_fail_safe_response(
                        parsed.harness,
                        reason="HOL Guard could not complete the native hook decision safely.",
                        reason_code="native_hook_worker_unsupported",
                    ),
                    "reason_code": "native_hook_worker_unsupported",
                    "route": "native_fail_safe",
                }
        except Exception:
            if _native_mode_requires_rust():
                record_native_hook_route("native_fail_safe")
                return {
                    "payload": post_tool_fail_safe_response(
                        parsed.harness,
                        reason="HOL Guard could not complete the native hook decision safely.",
                        reason_code="native_hook_worker_exception",
                    ),
                    "reason_code": "native_hook_worker_exception",
                    "route": "native_fail_safe",
                }
            raise
        else:
            return {
                "payload": worker_payload,
                "reason_code": None,
                "route": _current_decision_route(),
            }
    with applied_hook_environment(request):
        config = overlay_synced_guard_policy(
            load_guard_config(parsed.guard_home, workspace=parsed.workspace),
            _synced_policy_payload(store),
        )
        args = argparse.Namespace(
            guard_command="hook",
            home=str(parsed.home_dir),
            guard_home=str(parsed.guard_home),
            workspace=str(parsed.workspace) if parsed.workspace is not None else None,
            runtime_harness=parsed.harness,
            harness=parsed.harness,
            artifact_id=None,
            artifact_name=None,
            policy_action=None,
            event_file=None,
            json=True,
        )
        response = capture_hook_command(
            lambda output: _run_guard_hook_command(
                args,
                guard_home=parsed.guard_home,
                workspace=parsed.workspace,
                context=context,
                store=store,
                config=config,
                input_text=json.dumps(parsed.payload, separators=(",", ":")),
                output_stream=output,
                _claim_saved_approval=parsed.claim_saved_approval,
                _claimed_saved_allow_hash=parsed.claimed_saved_allow_hash,
                _claimed_trusted_request_override=parsed.claimed_trusted_request_override,
                _claimed_approval_request_id=parsed.claimed_approval_request_id,
            )
        )
        response["route"] = _current_decision_route()
        return response


def _native_mode_requires_rust() -> bool:
    from ..native_runtime import native_mode

    return native_mode() in {"auto", "force"}


def _current_decision_route() -> str:
    if not _native_mode_requires_rust():
        return "python_semantic"
    return native_hook_route() or "python_semantic"


def _coerce_resident_hook_request(request: dict[str, object]) -> _ResidentHookRequest | None:
    payload = request.get("payload")
    harness = request.get("harness")
    home_value = request.get("home_dir")
    guard_home_value = request.get("guard_home")
    workspace_value = request.get("workspace")
    claim_saved_approval = request.get("claim_saved_approval", True)
    claimed_saved_allow_hash = request.get("claimed_saved_allow_hash")
    claimed_trusted_request_override = request.get("claimed_trusted_request_override", False)
    claimed_approval_request_id = request.get("claimed_approval_request_id")
    typed_payload = as_string_object_dict(payload)
    if typed_payload is None or not isinstance(harness, str):
        return None
    if not isinstance(home_value, str) or not isinstance(guard_home_value, str):
        return None
    if workspace_value is not None and not isinstance(workspace_value, str):
        return None
    if not isinstance(claim_saved_approval, bool) or not isinstance(claimed_trusted_request_override, bool):
        return None
    if claimed_saved_allow_hash is not None and not isinstance(claimed_saved_allow_hash, str):
        return None
    if claimed_approval_request_id is not None and not isinstance(claimed_approval_request_id, str):
        return None
    return _ResidentHookRequest(
        payload=typed_payload,
        harness=harness,
        home_dir=Path(home_value),
        guard_home=Path(guard_home_value).resolve(strict=False),
        workspace=Path(workspace_value) if isinstance(workspace_value, str) else None,
        claim_saved_approval=claim_saved_approval,
        claimed_saved_allow_hash=claimed_saved_allow_hash,
        claimed_trusted_request_override=claimed_trusted_request_override,
        claimed_approval_request_id=claimed_approval_request_id,
    )


__all__ = ["hook_worker_main"]
