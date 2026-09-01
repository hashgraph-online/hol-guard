"""Entrypoint and request execution for isolated daemon hook workers."""

from __future__ import annotations

import importlib
import json
import multiprocessing
import os
import signal
import time
from contextlib import suppress
from multiprocessing.connection import Connection
from pathlib import Path
from typing import TYPE_CHECKING, NoReturn, cast

from ..codex_hook_windows_job import assign_current_process_to_windows_hook_job
from ..native_mode import native_mode_requires_rust as _native_mode_requires_rust
from ..native_route_receipt import native_hook_route, record_native_hook_route, reset_native_hook_route
from ..sqlite_profile import sqlite_error_is_busy_locked
from .hook_process_protocol import (
    applied_hook_environment,
    as_string_object_dict,
    capture_hook_command,
    is_pair,
)
from .hook_process_request import (
    ResidentHookRequest,
    coerce_resident_hook_request,
    compatibility_hook_args,
    resident_hook_store_and_context,
)

_ResidentHookRequest = ResidentHookRequest
_coerce_resident_hook_request = coerce_resident_hook_request

if TYPE_CHECKING:
    from ..store import GuardStore
    from .hook_worker import HookWorker

_HOOK_SQLITE_TIMEOUT_ENV = "HOL_GUARD_INTERNAL_HOOK_SQLITE_TIMEOUT_MS"
_HOOK_EVALUATOR_READY_TIMEOUT_SECONDS = 12.0


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
        _hook_evaluator_loop(
            connection,
            stores=stores,
            hook_workers=hook_workers,
            configured_guard_home=configured_guard_home,
        )
    finally:
        for worker in tuple(hook_workers.values()):
            with suppress(Exception):
                worker.close()


def _hook_evaluator_loop(
    connection: Connection,
    *,
    stores: dict[str, GuardStore],
    hook_workers: dict[str, HookWorker],
    configured_guard_home: str | None,
) -> None:
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
    from ..cli.commands_hook import _run_guard_hook_command
    from ..cli.commands_support_connect import _synced_policy_payload
    from ..config import load_guard_config, overlay_synced_guard_policy
    from .hook_worker import HookWorker, HookWorkerUnsupported, post_tool_fail_safe_response, runtime_hook_event_name

    parsed = coerce_resident_hook_request(request)
    if parsed is None:
        return {"payload": None, "reason_code": "daemon_hook_process_invalid_request"}
    reset_native_hook_route()
    if configured_guard_home is not None and parsed.guard_home != Path(configured_guard_home):
        return {"payload": None, "reason_code": "daemon_hook_process_guard_home_mismatch"}
    store_key = str(parsed.guard_home)
    store, context = resident_hook_store_and_context(parsed, stores)
    event_name = runtime_hook_event_name(parsed.payload)
    if parsed.native_minimum_action is None and (
        _native_mode_requires_rust() or event_name in {"PreToolUse", "PostToolUse"}
    ):
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
        args = compatibility_hook_args(parsed)
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


def _current_decision_route() -> str:
    if not _native_mode_requires_rust():
        return "python_semantic"
    return native_hook_route() or "python_semantic"


__all__ = ["hook_worker_main"]
