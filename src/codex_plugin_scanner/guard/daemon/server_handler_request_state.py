"""Request listing and scoped approval errors."""

from __future__ import annotations

from . import server as _server


def _handle_requests_list(self: _server._GuardDaemonHandler, query_string: str) -> None:
    limit = self._query_limit(query_string, default=200, maximum=200)
    if limit is None:
        self._write_json({"error": "invalid_limit"}, status=400)
        return
    status = self._query_string(query_string, "status") or "pending"
    if status == "all":
        status_filter = None
    elif status in {"pending", "resolved"}:
        status_filter = status
    else:
        self._write_json({"error": "invalid_status"}, status=400)
        return
    include_totals = self._query_bool(query_string, "include_totals", default=True)
    try:
        page = self.server.store.list_approval_request_page(  # type: ignore[attr-defined]
            status=status_filter,
            limit=limit,
            cursor=self._query_string(query_string, "cursor"),
            harness=self._query_string(query_string, "harness"),
            search=self._query_string(query_string, "search"),
            include_totals=include_totals,
        )
    except _server.InvalidApprovalCursorError:
        self._write_json(
            {
                "error": "invalid_cursor",
                "recovery": {
                    "code": "refresh_queue",
                    "title": "Refresh the blocked action list.",
                    "body": "The queue position expired. Refresh the Review Queue to continue.",
                },
            },
            status=400,
        )
        return
    self._write_json(page)


def _optional_bool(value: object, *, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes", "on"}:
            return True
        if normalized in {"false", "0", "no", "off", ""}:
            return False
    raise ValueError("invalid boolean value")


def _approval_persist_policy(self: _server._GuardDaemonHandler, payload: dict[str, object]) -> bool | None:
    if "persist_policy" in payload:
        return True if self._optional_bool(payload.get("persist_policy"), default=False) else None
    if "remember" in payload:
        return True if self._optional_bool(payload.get("remember"), default=False) else None
    return None


def _write_stale_approval_scope_error(
    self: _server._GuardDaemonHandler, error: _server.StaleApprovalScopeContractError
) -> None:
    self._write_json(
        {"resolved": False, "error": str(error), **error.contract.to_dict()},
        status=409,
    )


def _write_ineligible_approval_scope_error(
    self: _server._GuardDaemonHandler, error: _server.IneligibleApprovalScopeError
) -> None:
    self._write_json(
        {
            "resolved": False,
            "error": str(error),
            "action": error.action,
            "requested_scope": error.requested_scope,
            **error.contract.to_dict(),
        },
        status=422,
    )


def _write_approval_gate_error(
    self: _server._GuardDaemonHandler, error: _server.ApprovalGateError, *, resolved: bool | None = None
) -> None:
    payload = error.to_payload()
    if resolved is not None:
        payload["resolved"] = resolved
    self._write_json(payload, status=error.status)


def _handle_insights_share_publish(self: _server._GuardDaemonHandler, payload: dict[str, object]) -> None:
    include_top_artifacts = self._optional_bool(payload.get("includeTopArtifacts"), default=False)
    show_display_name = self._optional_bool(payload.get("showDisplayName"), default=False)
    display_name_value = payload.get("displayName")
    display_name = display_name_value.strip()[:120] if isinstance(display_name_value, str) else None
    store = self.server.store  # type: ignore[attr-defined]
    try:
        result = _server.publish_insights_share(
            store,
            include_top_artifacts=include_top_artifacts,
            show_display_name=show_display_name,
            display_name=display_name,
        )
    except Exception as error:
        message = str(error).strip() or "Unable to publish Guard insights share."
        self._write_json({"error": "insights_share_failed", "message": message}, status=502)
        return
    self._write_json(result)


def _handle_cloud_exception_request_list(self: _server._GuardDaemonHandler) -> None:
    store = self.server.store  # type: ignore[attr-defined]
    try:
        result = _server.fetch_cloud_exception_requests(store)
    except _server.CloudExceptionRequestError as error:
        message = str(error).strip() or "Unable to load Guard Cloud exception requests."
        self._write_json({"error": "cloud_exception_request_list_failed", "message": message}, status=error.status)
        return
    except Exception as error:
        message = str(error).strip() or "Unable to load Guard Cloud exception requests."
        self._write_json({"error": "cloud_exception_request_list_failed", "message": message}, status=502)
        return
    self._write_json(result)


def _handle_cloud_exception_request_create(self: _server._GuardDaemonHandler, payload: dict[str, object]) -> None:
    store = self.server.store  # type: ignore[attr-defined]
    try:
        result = _server.submit_cloud_exception_request(store, payload)
    except ValueError as error:
        message = str(error).strip() or "Invalid Guard exception request payload."
        self._write_json({"error": "invalid_payload", "message": message}, status=400)
        return
    except _server.CloudExceptionRequestError as error:
        message = str(error).strip() or "Unable to create Guard Cloud exception request."
        self._write_json({"error": "cloud_exception_request_failed", "message": message}, status=error.status)
        return
    except Exception as error:
        message = str(error).strip() or "Unable to create Guard Cloud exception request."
        self._write_json({"error": "cloud_exception_request_failed", "message": message}, status=502)
        return
    self._write_json(result)


def _handle_read_state_update(self: _server._GuardDaemonHandler, payload: dict[str, object]) -> None:
    store = self.server.store  # type: ignore[attr-defined]
    action = str(payload.get("action") or "mark_read")
    if action == "mark_all_read":
        request_ids = payload.get("request_ids")
        if not isinstance(request_ids, list):
            self._write_json({"error": "invalid_request_ids"}, status=400)
            return
        store.mark_requests_read([str(rid) for rid in request_ids if isinstance(rid, str)])
        self._write_json({"ok": True, "ids": store.get_read_state()})
        return
    if action == "mark_unread":
        request_id = payload.get("request_id")
        if not isinstance(request_id, str):
            self._write_json({"error": "invalid_request_id"}, status=400)
            return
        store.mark_request_unread(request_id)
        self._write_json({"ok": True, "ids": store.get_read_state()})
        return
    request_id = payload.get("request_id")
    if isinstance(request_id, str):
        store.mark_requests_read([request_id])
        self._write_json({"ok": True, "ids": store.get_read_state()})
        return
    self._write_json({"error": "invalid_action"}, status=400)


def _read_delete_body(self: _server._GuardDaemonHandler) -> dict[str, object] | None:
    try:
        length = int(self.headers.get("Content-Length", "0"))
    except ValueError:
        return None
    if length <= 0 or length > self._MAX_BODY_BYTES:
        return None
    raw = self.rfile.read(length)
    try:
        parsed = _server.json.loads(raw.decode("utf-8"))
    except (_server.json.JSONDecodeError, UnicodeDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None
