"""Daemon routes backed by Guard services, run behind ``desktop library-call``.

Each call returns the one reply its route writes:
``{"status": int, "body": {...}, "no_store": bool}``. The native daemon owns
the route, the caller check and the body read.
"""

from __future__ import annotations

import threading
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ..store import GuardStore
from .calls import _Recorder


def _payload(args: Mapping[str, Any]) -> dict[str, object]:
    payload = args.get("payload")
    if not isinstance(payload, dict):
        from ..library_calls import LibraryCallError

        raise LibraryCallError("invalid_arguments")
    return payload


def desktop_bootstrap(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """``GET /v1/desktop/bootstrap``: the document Guard Desktop starts from."""

    from ..cli.commands_dispatch_desktop import desktop_bootstrap_document_for_running_daemon
    from ..library_calls import LibraryCallError
    from ..native_daemon_manage import load_guard_daemon_auth_token

    daemon_url = args.get("daemon_url")
    home_dir = args.get("home_dir")
    if not isinstance(daemon_url, str) or not (home_dir is None or isinstance(home_dir, str)):
        raise LibraryCallError("invalid_arguments")
    try:
        document = desktop_bootstrap_document_for_running_daemon(
            store=store,
            home_dir=Path(home_dir) if home_dir else Path.home(),
            daemon_url=daemon_url,
            auth_token=load_guard_daemon_auth_token(store.guard_home) or "",
        )
    except Exception:
        # A 503 sends the CLI to the full bootstrap command.
        return {"status": 503, "body": {"error": "desktop_bootstrap_unavailable"}, "no_store": False}
    return {"status": 200, "body": dict(document), "no_store": False}


def cloud_review_update(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """``POST /v1/cloud-review``: change Cloud Review and refresh the workers."""

    from ..cloud_control.cloud_review_settings_route import handle_cloud_review_settings
    from ..workers.host import DurableWorkerRefresh

    recorder = _Recorder(store)
    handle_cloud_review_settings(
        store,
        _payload(args),
        refresh_workers=DurableWorkerRefresh(store).refresh_command_queue_worker,
        write_json=recorder._write_json,
        write_approval_gate_error=recorder._write_approval_gate_error,
    )
    return recorder.reply()


def command_queue_refresh(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """``POST /v1/command-queue/worker/refresh``: apply changed Cloud connectivity."""

    del args
    from ..workers.host import DurableWorkerRefresh

    return {"status": 200, "body": DurableWorkerRefresh(store).refresh_command_queue_worker(), "no_store": True}


def cloud_actions_check(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """``POST /v1/cloud-actions/status``: ask Guard Cloud and save the answer."""

    from ..cloud_control.cloud_actions_status_http import handle_cloud_actions_check

    recorder = _RetryAfterRecorder(store)
    handle_cloud_actions_check(recorder, _payload(args))
    return recorder.reply()


_LOCAL_CLI_APIS: dict[str, Any] = {}
_LOCAL_CLI_APIS_LOCK = threading.Lock()


def _local_cli_api(store: GuardStore) -> Any:
    """The custom-extension service for ``store``, kept for the resident's life.

    Discovery jobs it starts run on in this process; their state is also
    recorded in the Guard home so a restarted resident reports them.
    """

    from ..local_clis.local_cli_api import LocalCliApiService
    from ..runtime_health.background_diagnostics import record_background_event
    from .request_state import _ReplayDiscoveryJobs, _ReplayState

    key = str(store.guard_home)
    with _LOCAL_CLI_APIS_LOCK:
        service = _LOCAL_CLI_APIS.get(key)
        if service is None:

            def record_exception(code: str, *, detail: str | None = None, **_: object) -> None:
                record_background_event(code, detail or "")

            service = LocalCliApiService(store=store, record_exception=record_exception)
            service._discovery_jobs = _ReplayDiscoveryJobs(_ReplayState(store.guard_home))
            _LOCAL_CLI_APIS[key] = service
        return service


_LOCAL_CLI_OPS = frozenset(
    {
        "apply",
        "discover_items",
        "forget",
        "mcp_skills",
        "preview",
        "provider_actions",
        "provider_workflows",
        "recognize",
        "refresh_job",
        "registry_search",
        "registry_setup",
        "skills",
    }
)
_LOCAL_CLI_UNAVAILABLE = {
    "status": 500,
    "body": {"error": "local_cli_unavailable", "message": "Guard could not load custom extensions."},
    "no_store": True,
}


def local_cli_post(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """``POST /v1/local-clis/*``: run the service method the daemon picked for the path."""

    from ..library_calls import LibraryCallError
    from ..local_clis.local_cli_api_contract import LocalCliApiError
    from ..runtime_health.background_diagnostics import failure_detail, record_background_event

    op = args.get("op")
    if op not in _LOCAL_CLI_OPS:
        raise LibraryCallError("invalid_arguments")
    payload = _payload(args)
    method = getattr(_local_cli_api(store), op)
    try:
        response = method() if op == "discover_items" else method(payload)
    except LocalCliApiError as error:
        return {"status": error.status, "body": error.to_payload(), "no_store": False}
    except Exception as error:
        # Name the method and the exception class, so daemon.log says which
        # request failed, then answer a reply the page can explain.
        record_background_event("local_cli_post_failed", f"route={op} {failure_detail(error)}")
        return dict(_LOCAL_CLI_UNAVAILABLE)
    if not isinstance(response, dict):
        return dict(_LOCAL_CLI_UNAVAILABLE)
    return {"status": 200, "body": response, "no_store": True}


class _RetryAfterRecorder(_Recorder):
    """Keeps a reply whose ``Retry-After`` repeats the body's ``retry_after_seconds``."""

    def _write_json(
        self,
        payload: dict[str, Any],
        *,
        status: int = 200,
        extra_headers: Mapping[str, str] | None = None,
    ) -> None:
        headers = {name: value for name, value in (extra_headers or {}).items() if name != "Retry-After"}
        super()._write_json(payload, status=status, extra_headers=headers)


SERVICE_CALLS = {
    "route.desktop_bootstrap": desktop_bootstrap,
    "route.cloud_review_update": cloud_review_update,
    "route.command_queue_refresh": command_queue_refresh,
    "route.cloud_actions_check": cloud_actions_check,
    "route.local_cli_post": local_cli_post,
}
