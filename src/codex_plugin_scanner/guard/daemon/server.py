"""Local Guard daemon helpers."""

from __future__ import annotations

import argparse
import io
import json
import mimetypes
import os
import secrets
import threading
import time
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, parse_qsl, unquote, urlencode, urlparse, urlunparse

from ...version import __version__
from ..adapters import get_adapter
from ..adapters.base import HarnessContext
from ..approvals import (
    ApprovalRequestAlreadyResolvedError,
    ApprovalRequestNotFoundError,
    apply_approval_resolution,
    build_runtime_snapshot,
)
from ..cli.install_commands import (
    apply_managed_install,
    build_harness_setup_plan,
    build_harness_verification,
    list_harness_setup_items,
    uninstall_confirmation_token,
)
from ..config import editable_guard_settings, load_guard_config, update_guard_settings
from ..models import DECISION_SCOPE_VALUES, GUARD_ACTION_VALUES
from ..runtime.surface_server import GuardSurfaceRuntime
from ..store import GuardStore
from ..store_approvals import InvalidApprovalCursorError
from ..store_evidence import (
    clear_evidence,
    count_evidence,
    export_evidence_json,
    list_evidence,
)
from .manager import (
    GUARD_DAEMON_COMPATIBILITY_VERSION,
    clear_guard_daemon_state,
    load_guard_daemon_auth_token,
    repair_approval_center_locator,
    write_guard_daemon_state,
)


class _GuardDaemonHttpServer(ThreadingHTTPServer):
    store: GuardStore
    runtime: GuardSurfaceRuntime
    auth_token: str
    idle_timeout_seconds: float | None
    last_activity_monotonic: float
    active_stream_clients: int
    active_stream_clients_lock: threading.Lock


_STATIC_DIR = Path(__file__).with_name("static")
_INDEX_PATH = _STATIC_DIR / "index.html"
_ENTRY_PATH = _STATIC_DIR / "assets" / "guard-dashboard.js"
_ROOT_STATIC_FILES = {
    "/favicon.svg",
    "/favicon.ico",
    "/favicon-16x16.png",
    "/favicon-32x32.png",
}
_CLAUDE_HOOK_EXECUTION_LOCK = threading.Lock()
_DEFAULT_GUARD_DAEMON_IDLE_TIMEOUT_SECONDS = 30 * 60
_EPHEMERAL_GUARD_DAEMON_IDLE_TIMEOUT_SECONDS = 5
_GUARD_DAEMON_IDLE_POLL_INTERVAL_SECONDS = 0.5
_HOSTED_GUARD_DASHBOARD_ORIGINS = frozenset({"https://hol.org", "https://www.hol.org"})


class _GuardDaemonHandler(BaseHTTPRequestHandler):
    _MAX_BODY_BYTES = 1_000_000

    def do_OPTIONS(self) -> None:
        origin = self._normalize_origin(self.headers.get("Origin"))
        if origin is None:
            self._write_empty(status=400)
            return
        headers = self._cors_headers_for_request(
            allow_methods="GET, POST, DELETE, OPTIONS",
            allow_headers="Content-Type, X-Guard-Token",
        )
        if headers is None:
            self._write_empty(status=403)
            return
        self._write_empty(status=200, extra_headers=headers)

    def do_GET(self) -> None:
        store = self.server.store  # type: ignore[attr-defined]
        parsed = urlparse(self.path)
        self._touch_runtime_heartbeat(parsed.path)
        path_parts = [part for part in parsed.path.split("/") if part]
        if not self._origin_is_allowed_for_request(parsed.path, path_parts):
            self._write_json({"error": "forbidden_origin"}, status=403)
            return
        if (
            self._is_hosted_dashboard_origin()
            and self._is_hosted_dashboard_api_path(parsed.path, path_parts)
            and parsed.path != "/v1/connect/state"
            and not self._header_token_is_valid()
        ):
            self._write_json({"error": "unauthorized"}, status=401)
            return
        if parsed.path == "/healthz":
            self._write_json(
                {
                    "ok": True,
                    "receipts": len(store.list_receipts(limit=500)),
                    "approvals": store.count_approval_requests(),
                    "tables": store.list_table_names(),
                    "compatibility_version": GUARD_DAEMON_COMPATIBILITY_VERSION,
                    "package_version": __version__,
                }
            )
            return
        if parsed.path == "/v1/sessions":
            self._write_json({"items": store.list_guard_sessions(limit=200)})
            return
        if parsed.path == "/v1/runtime":
            config = load_guard_config(store.guard_home)
            snapshot = build_runtime_snapshot(
                store=store,
                approval_center_url=f"http://{self.server.server_address[0]}:{self.server.server_address[1]}",
                active_request_id=self._query_string(parsed.query, "active_request_id"),
            )
            self._write_json({**snapshot, "security_level": config.security_level})
            return
        if parsed.path == "/v1/harnesses":
            context = self._harness_context({})
            self._write_json({"items": list_harness_setup_items(context, self.server.store)})  # type: ignore[attr-defined]
            return
        if parsed.path == "/v1/inventory":
            from ..adapters.contracts import HARNESS_CONTRACTS

            inventory_items = store.list_inventory()
            installed_harnesses = {str(item.get("harness", "")) for item in inventory_items}
            contracts_index = {
                c.harness: {
                    "install_aliases": list(c.install_aliases),
                    "event_surfaces": list(c.event_surfaces),
                    "native_approval": c.native_approval,
                    "browser_fallback": c.browser_fallback,
                    "resume_support": c.resume_support,
                    "known_blind_spots": c.known_blind_spots,
                }
                for c in HARNESS_CONTRACTS
            }
            enriched: list[dict[str, object]] = []
            for item in inventory_items:
                harness_name = str(item.get("harness", ""))
                contract = contracts_index.get(harness_name, {})
                enriched.append({**item, "contract": contract})
            uninstalled = [
                {
                    "harness": c.harness,
                    "status": "unknown",
                    "contract": contracts_index[c.harness],
                }
                for c in HARNESS_CONTRACTS
                if c.harness not in installed_harnesses
            ]
            self._write_json({"items": enriched, "available": uninstalled})
            return
        if parsed.path == "/v1/settings":
            config = load_guard_config(store.guard_home)
            self._write_json(
                {
                    "guard_home": str(store.guard_home),
                    "config_path": str(store.guard_home / "config.toml"),
                    "settings": editable_guard_settings(config),
                }
            )
            return
        if len(path_parts) == 4 and path_parts[:2] == ["v1", "sessions"] and path_parts[3] == "resume":
            self._handle_session_resume(path_parts[2])
            return
        if len(path_parts) == 3 and path_parts[:2] == ["v1", "operations"]:
            operation = store.get_guard_operation(path_parts[2])
            if operation is None:
                self._write_json({"error": "not_found"}, status=404)
                return
            self._write_json(operation)
            return
        if parsed.path == "/v1/events":
            self._write_json({"items": store.list_events_after(_int_query_value(parsed.query, "cursor"), limit=200)})
            return
        if parsed.path == "/v1/requests":
            self._handle_requests_list(parsed.query)
            return
        if parsed.path == "/v1/connect/state":
            self._handle_connect_state_read(parsed.query)
            return
        if len(path_parts) == 3 and path_parts[:2] == ["v1", "requests"]:
            approval = store.get_approval_request(path_parts[2])
            if approval is None:
                self._write_json(
                    {
                        "error": "not_found",
                        "recovery": {
                            "code": "request_unknown",
                            "title": "This request is no longer waiting.",
                            "body": "The request was either already resolved or expired. You can close this tab.",
                        },
                    },
                    status=404,
                )
                return
            self._write_json(approval)
            return
        if parsed.path == "/v1/receipts":
            self._write_json({"items": store.list_receipts(limit=200)})
            return
        if parsed.path == "/v1/receipts/latest":
            query = parse_qs(parsed.query)
            harness = query.get("harness", [None])[-1]
            artifact_id = query.get("artifact_id", [None])[-1]
            if not isinstance(harness, str) or not harness or not isinstance(artifact_id, str) or not artifact_id:
                self._write_json({"error": "missing_receipt_query"}, status=400)
                return
            receipt = store.get_latest_receipt(harness, artifact_id)
            if receipt is None:
                self._write_json({"error": "not_found"}, status=404)
                return
            self._write_json(receipt)
            return
        if len(path_parts) == 3 and path_parts[:2] == ["v1", "receipts"]:
            receipt = store.get_receipt(path_parts[2])
            if receipt is None:
                self._write_json({"error": "not_found"}, status=404)
                return
            self._write_json(receipt)
            return
        if parsed.path == "/v1/policy":
            query = parse_qs(parsed.query)
            harness = query.get("harness", [None])[-1]
            self._write_json(
                {"items": store.list_policy_decisions(harness=harness if isinstance(harness, str) else None)}
            )
            return
        if parsed.path == "/v1/evidence":
            query = parse_qs(parsed.query)
            harness_q = query.get("harness", [None])[-1]
            category_q = query.get("category", [None])[-1]
            severity_q = query.get("severity", [None])[-1]
            before_q = query.get("before", [None])[-1]
            limit_q = query.get("limit", ["100"])[-1]
            try:
                limit_v = min(int(limit_q), 500)
            except (ValueError, TypeError):
                limit_v = 100
            with store._connect() as conn:
                records = list_evidence(
                    conn,
                    harness=harness_q if isinstance(harness_q, str) else None,
                    category=category_q if isinstance(category_q, str) else None,
                    severity=severity_q if isinstance(severity_q, str) else None,
                    before_cursor=before_q if isinstance(before_q, str) else None,
                    limit=limit_v,
                )
                total = count_evidence(conn)
            self._write_json(
                {
                    "items": [vars(r) for r in records],
                    "total": total,
                }
            )
            return
        if parsed.path == "/v1/evidence/export":
            with store._connect() as conn:
                payload = export_evidence_json(conn, limit=10_000)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(payload.encode("utf-8"))
            return
        if len(path_parts) == 4 and path_parts[:3] == ["v1", "artifacts", path_parts[2]] and path_parts[3] == "diff":
            query = parse_qs(parsed.query)
            harness = query.get("harness", [None])[-1]
            if not isinstance(harness, str) or not harness:
                self._write_json({"error": "missing_harness"}, status=400)
                return
            diff = store.get_latest_diff(harness, unquote(path_parts[2]))
            if diff is None:
                self._write_json({"error": "not_found"}, status=404)
                return
            self._write_json(diff)
            return
        if parsed.path in _ROOT_STATIC_FILES:
            self._write_static_asset(parsed.path.removeprefix("/"))
            return
        if parsed.path.startswith("/assets/") or parsed.path.startswith("/brand/"):
            self._write_static_asset(parsed.path.removeprefix("/"))
            return
        if parsed.path == "/v1/events/stream":
            if not self._token_is_valid(parsed.query):
                self._write_json({"error": "unauthorized"}, status=401)
                return
            self._stream_events(_int_query_value(parsed.query, "cursor"))
            return
        if self._is_dashboard_route(parsed.path):
            self._write_dashboard_shell()
            return
        self.send_response(404)
        self.end_headers()

    def do_DELETE(self) -> None:
        parsed = urlparse(self.path)
        self._touch_runtime_heartbeat(parsed.path)
        path_parts = [part for part in parsed.path.split("/") if part]
        if not self._origin_is_allowed_for_request(parsed.path, path_parts):
            self._write_json({"error": "forbidden_origin"}, status=403)
            return
        if not self._header_token_is_valid():
            self._write_json(
                {"error": "unauthorized"},
                status=401,
                extra_headers=self._cors_headers_for_request(),
            )
            return
        store = self.server.store  # type: ignore[attr-defined]
        if parsed.path == "/v1/evidence":
            with store._connect() as conn:
                deleted = clear_evidence(conn)
            self._write_json({"deleted": deleted})
            return
        self._write_json({"error": "not_found"}, status=404)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        self._touch_runtime_heartbeat(parsed.path)
        path_parts = [part for part in parsed.path.split("/") if part]
        if parsed.path != "/v1/connect/complete" and not self._origin_is_allowed_for_request(parsed.path, path_parts):
            self._write_json({"error": "forbidden_origin"}, status=403)
            return
        if self._requires_header_token(parsed.path, path_parts) and not self._header_token_is_valid():
            if len(path_parts) == 4 and path_parts[:2] == ["v1", "requests"] and path_parts[3] in {"approve", "block"}:
                host = self.server.server_address[0]  # type: ignore[attr-defined]
                port = self.server.server_address[1]  # type: ignore[attr-defined]
                reconnect_url = _build_local_url(host, port, "/#/reconnect")
                self._write_json(
                    {
                        "error": "unauthorized",
                        "recovery": {
                            "code": "session_stale",
                            "title": "Your session with the local Guard daemon has expired.",
                            "body": "Click the link below to reconnect, then retry your approval.",
                            "reconnect_url": reconnect_url,
                        },
                    },
                    status=401,
                    extra_headers=self._cors_headers_for_request(),
                )
            else:
                self._write_json(
                    {"error": "unauthorized"},
                    status=401,
                    extra_headers=self._cors_headers_for_request(),
                )
            return
        payload, body_error = self._load_request_body()
        if body_error is not None:
            self._write_json({"error": body_error}, status=400)
            return
        if parsed.path == "/v1/initialize":
            self._handle_initialize(payload)
            return
        if parsed.path == "/v1/hooks/claude-code":
            self._handle_claude_hook(payload, parsed.query)
            return
        if parsed.path == "/v1/clients/attach":
            self._handle_client_attach(payload)
            return
        if parsed.path == "/v1/clients/heartbeat":
            self._handle_client_heartbeat(payload)
            return
        if parsed.path == "/v1/sessions/start":
            self._handle_session_start(payload)
            return
        if parsed.path == "/v1/operations/start":
            self._handle_operation_start(payload)
            return
        if parsed.path == "/v1/connect/requests":
            self._handle_connect_request_create(payload)
            return
        if parsed.path == "/v1/connect/complete":
            self._handle_connect_complete(payload)
            return
        if parsed.path == "/v1/connect/result":
            self._handle_connect_result_update(payload)
            return
        if parsed.path == "/v1/operations/block":
            self._handle_operation_block(payload)
            return
        if len(path_parts) == 4 and path_parts[:2] == ["v1", "operations"] and path_parts[3] == "items":
            self._handle_operation_item(path_parts[2], payload)
            return
        if len(path_parts) == 4 and path_parts[:2] == ["v1", "operations"] and path_parts[3] == "status":
            self._handle_operation_status(path_parts[2], payload)
            return
        if parsed.path == "/v1/policy/decisions":
            self._handle_policy_upsert(payload)
            return
        if parsed.path == "/v1/policy/clear":
            self._handle_policy_clear(payload)
            return
        if parsed.path == "/v1/settings":
            self._handle_settings_update(payload)
            return
        if parsed.path == "/v1/daemon/repair":
            result = repair_approval_center_locator(self.server.store.guard_home)  # type: ignore[attr-defined]
            self._write_json(result)
            return
        if len(path_parts) == 4 and path_parts[:2] == ["v1", "harnesses"]:
            self._handle_harness_action(path_parts[2], path_parts[3], payload)
            return
        request_id, action, matched = self._resolve_request_action(path_parts, payload)
        if not matched:
            self.send_response(404)
            self.end_headers()
            return
        if action is None:
            self._write_json({"resolved": False, "error": "missing_required_fields"}, status=400)
            return
        scope = payload.get("scope")
        if not isinstance(scope, str) or not scope.strip():
            self._write_json({"resolved": False, "error": "missing_required_fields"}, status=400)
            return
        try:
            updated = apply_approval_resolution(
                store=self.server.store,  # type: ignore[attr-defined]
                request_id=request_id,
                action=action,
                scope=scope.strip(),
                workspace=self._optional_string(payload.get("workspace")),
                reason=self._optional_string(payload.get("reason")),
                return_queue_result=True,
                resolve_scope_matches=True,
            )
        except ApprovalRequestNotFoundError:
            self._write_json(
                {
                    "resolved": False,
                    "error": "not_found",
                    "recovery": {
                        "code": "request_unknown",
                        "title": "This request is no longer waiting.",
                        "body": "The request was either already resolved or expired. You can close this tab.",
                    },
                },
                status=404,
            )
            return
        except ApprovalRequestAlreadyResolvedError:
            self._write_json(
                {
                    "resolved": False,
                    "error": "already_resolved",
                    "recovery": {
                        "code": "request_resolved",
                        "title": "This request has already been resolved.",
                        "body": (
                            "If the action is blocked and you believe it should be allowed, "
                            "you can re-submit from your AI assistant."
                        ),
                    },
                },
                status=409,
            )
            return
        except ValueError as error:
            self._write_json({"resolved": False, "error": str(error)}, status=400)
            return
        normalized_scope = scope.strip()
        item = updated.get("item")
        harness_str = str(item.get("harness", "")) if isinstance(item, dict) else ""
        self.server.store.add_event(  # type: ignore[attr-defined]
            "approval_resolved",
            {"request_id": request_id, "action": action, "scope": normalized_scope, "harness": harness_str},
            _now(),
        )
        harness = str(updated.get("harness", ""))
        updated["copy"] = _build_resolution_copy(action, harness_str or harness)
        self._write_json(updated)

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _load_request_body(self) -> tuple[dict[str, object], str | None]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > self._MAX_BODY_BYTES:
            return {}, None
        try:
            raw_body = self.rfile.read(length).decode("utf-8")
        except UnicodeDecodeError:
            return {}, "invalid_request_body"
        content_type = self.headers.get("Content-Type", "")
        if "application/json" in content_type:
            try:
                payload = json.loads(raw_body)
            except json.JSONDecodeError:
                return {}, "invalid_request_body"
            return (payload if isinstance(payload, dict) else {}), None
        form_payload = parse_qs(raw_body)
        return {key: values[-1] for key, values in form_payload.items() if values}, None

    def _handle_policy_clear(self, payload: dict[str, object]) -> None:
        harness = self._optional_string(payload.get("harness"))
        source = self._optional_string(payload.get("source"))
        try:
            clear_all = self._optional_bool(payload.get("all"), default=False)
        except ValueError:
            self._write_json({"error": "invalid_all", "cleared": 0}, status=400)
            return
        if clear_all and harness is not None:
            self._write_json(
                {
                    "error": "choose_all_or_harness",
                    "cleared": 0,
                    "harness": harness,
                    "source": source,
                },
                status=400,
            )
            return
        if not clear_all and harness is None:
            self._write_json({"error": "missing_harness_or_all", "cleared": 0}, status=400)
            return
        cleared = self.server.store.clear_policy_decisions(  # type: ignore[attr-defined]
            None if clear_all else harness,
            source,
        )
        self._write_json(
            {
                "cleared": cleared,
                "harness": None if clear_all else harness,
                "source": source,
            }
        )

    def _harness_context(self, payload: dict[str, object]) -> HarnessContext:
        home = self._optional_string(payload.get("home"))
        workspace = self._optional_string(payload.get("workspace"))
        return HarnessContext(
            home_dir=Path(home).expanduser().resolve() if home is not None else Path.home().resolve(),
            workspace_dir=Path(workspace).expanduser().resolve() if workspace is not None else None,
            guard_home=self.server.store.guard_home,  # type: ignore[attr-defined]
        )

    def _handle_harness_action(self, harness: str, action: str, payload: dict[str, object]) -> None:
        if action not in {"install", "verify", "repair", "uninstall"}:
            self._write_json({"error": "not_found"}, status=404)
            return
        context = self._harness_context(payload)
        if action == "verify":
            try:
                self._write_json(build_harness_verification(harness, context, self.server.store))  # type: ignore[attr-defined]
            except ValueError as error:
                self._write_json({"error": str(error)}, status=404)
            return
        try:
            dry_run = self._optional_bool(payload.get("dry_run"), default=True)
        except ValueError:
            self._write_json({"error": "invalid_dry_run"}, status=400)
            return
        try:
            adapter = get_adapter(harness)
        except ValueError as error:
            self._write_json({"error": str(error)}, status=404)
            return
        if action == "uninstall":
            expected_confirmation = uninstall_confirmation_token(adapter.harness)
            confirmation = self._optional_string(payload.get("confirmation_phrase")) or self._optional_string(
                payload.get("confirmation_token")
            )
            if confirmation != expected_confirmation:
                self._write_json(
                    {
                        "error": "confirmation_required",
                        "harness": adapter.harness,
                        "confirmation_phrase": expected_confirmation,
                        "confirm_command": (
                            f"hol-guard apps disconnect {adapter.harness} --confirm {expected_confirmation}"
                        ),
                    },
                    status=400,
                )
                return
        if dry_run:
            self._write_json(build_harness_setup_plan(action, adapter.harness, context, dry_run=True))
            return
        install_command = "uninstall" if action == "uninstall" else "install"
        try:
            result = apply_managed_install(
                install_command,
                adapter.harness,
                False,
                context,
                self.server.store,  # type: ignore[attr-defined]
                str(context.workspace_dir) if context.workspace_dir is not None else None,
                _now(),
            )
        except ValueError as error:
            self._write_json({"error": str(error)}, status=400)
            return
        self._write_json({"harness": adapter.harness, "action": action, "dry_run": False, **result})

    def _handle_requests_list(self, query_string: str) -> None:
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
        try:
            page = self.server.store.list_approval_request_page(  # type: ignore[attr-defined]
                status=status_filter,
                limit=limit,
                cursor=self._query_string(query_string, "cursor"),
                harness=self._query_string(query_string, "harness"),
                search=self._query_string(query_string, "search"),
            )
        except InvalidApprovalCursorError:
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

    @staticmethod
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

    def _handle_settings_update(self, payload: dict[str, object]) -> None:
        settings = payload.get("settings")
        if not isinstance(settings, dict):
            self._write_json({"error": "invalid_settings"}, status=400)
            return
        try:
            config = update_guard_settings(self.server.store.guard_home, settings)  # type: ignore[attr-defined]
        except ValueError as error:
            self._write_json({"error": "invalid_settings", "message": str(error)}, status=400)
            return
        self._write_json(
            {
                "guard_home": str(self.server.store.guard_home),  # type: ignore[attr-defined]
                "config_path": str(self.server.store.guard_home / "config.toml"),  # type: ignore[attr-defined]
                "settings": editable_guard_settings(config),
            }
        )

    def _handle_initialize(self, payload: dict[str, object]) -> None:
        client_name = self._optional_string(payload.get("client_name")) or "guard-client"
        surface = self._optional_string(payload.get("surface")) or "cli"
        capabilities = payload.get("capabilities")
        capability_items = (
            tuple(str(item) for item in capabilities if isinstance(item, str)) if isinstance(capabilities, list) else ()
        )
        supported_versions = payload.get("supported_protocol_versions")
        try:
            response = self.server.runtime.initialize_client(  # type: ignore[attr-defined]
                client_name=client_name,
                client_title=self._optional_string(payload.get("client_title")),
                version=self._optional_string(payload.get("version")),
                surface=surface,
                capabilities=capability_items,
                supported_protocol_versions=tuple(str(item) for item in supported_versions if isinstance(item, str))
                if isinstance(supported_versions, list)
                else (),
            )
        except ValueError as error:
            self._write_json({"error": str(error)}, status=400)
            return
        response["auth_token"] = self.server.auth_token  # type: ignore[attr-defined]
        self._write_json(response)

    def _handle_client_attach(self, payload: dict[str, object]) -> None:
        client_id = self._optional_string(payload.get("client_id"))
        surface = self._optional_string(payload.get("surface"))
        if client_id is None or surface is None:
            self._write_json({"attached": False, "error": "missing_required_fields"}, status=400)
            return
        try:
            attachment = self.server.runtime.attach_client(  # type: ignore[attr-defined]
                client_id=client_id,
                surface=surface,
                session_id=self._optional_string(payload.get("session_id")),
                metadata={"title": self._optional_string(payload.get("client_title")) or surface},
                lease_seconds=self._optional_int(payload.get("lease_seconds")) or 60,
            )
        except ValueError as error:
            self._write_json({"attached": False, "error": str(error)}, status=400)
            return
        self._write_json({"attached": True, "item": attachment})

    def _handle_client_heartbeat(self, payload: dict[str, object]) -> None:
        client_id = self._optional_string(payload.get("client_id"))
        lease_id = self._optional_string(payload.get("lease_id"))
        if client_id is None or lease_id is None:
            self._write_json({"renewed": False, "error": "missing_required_fields"}, status=400)
            return
        try:
            attachment = self.server.runtime.renew_client(  # type: ignore[attr-defined]
                client_id=client_id,
                lease_id=lease_id,
                lease_seconds=self._optional_int(payload.get("lease_seconds")) or 60,
            )
        except ValueError as error:
            self._write_json({"renewed": False, "error": str(error)}, status=404)
            return
        self._write_json({"renewed": True, "item": attachment})

    def _handle_session_start(self, payload: dict[str, object]) -> None:
        harness = self._optional_string(payload.get("harness"))
        surface = self._optional_string(payload.get("surface"))
        client_name = self._optional_string(payload.get("client_name"))
        if harness is None or surface is None or client_name is None:
            self._write_json({"error": "missing_required_fields"}, status=400)
            return
        capabilities = payload.get("capabilities")
        session = self.server.runtime.start_session(  # type: ignore[attr-defined]
            harness=harness,
            surface=surface,
            workspace=self._optional_string(payload.get("workspace")),
            client_name=client_name,
            client_title=self._optional_string(payload.get("client_title")),
            client_version=self._optional_string(payload.get("client_version")),
            capabilities=tuple(str(item) for item in capabilities if isinstance(item, str))
            if isinstance(capabilities, list)
            else (),
        )
        self._write_json(session)

    def _handle_operation_start(self, payload: dict[str, object]) -> None:
        session_id = self._optional_string(payload.get("session_id"))
        operation_type = self._optional_string(payload.get("operation_type"))
        harness = self._optional_string(payload.get("harness"))
        if session_id is None or operation_type is None or harness is None:
            self._write_json({"error": "missing_required_fields"}, status=400)
            return
        metadata = payload.get("metadata")
        try:
            operation = self.server.runtime.start_operation(  # type: ignore[attr-defined]
                session_id=session_id,
                operation_type=operation_type,
                harness=harness,
                metadata=metadata if isinstance(metadata, dict) else {},
            )
        except ValueError as error:
            self._write_json({"error": str(error)}, status=400)
            return
        self._write_json(operation)

    def _handle_operation_block(self, payload: dict[str, object]) -> None:
        session_id = self._optional_string(payload.get("session_id"))
        operation_type = self._optional_string(payload.get("operation_type"))
        harness = self._optional_string(payload.get("harness"))
        approval_center_url = self._optional_string(payload.get("approval_center_url"))
        approval_surface_policy = self._optional_string(payload.get("approval_surface_policy"))
        detection = payload.get("detection")
        evaluation = payload.get("evaluation")
        if not all(
            (
                session_id is not None,
                operation_type is not None,
                harness is not None,
                approval_center_url is not None,
                approval_surface_policy is not None,
                isinstance(detection, dict),
                isinstance(evaluation, dict),
            )
        ):
            self._write_json({"error": "missing_required_fields"}, status=400)
            return
        try:
            response = self.server.runtime.queue_blocked_operation(  # type: ignore[attr-defined]
                session_id=session_id,
                operation_type=operation_type,
                harness=harness,
                metadata=dict(payload.get("metadata")) if isinstance(payload.get("metadata"), dict) else {},
                detection=detection,
                evaluation=evaluation,
                approval_center_url=approval_center_url,
                browser_url=_approval_center_browser_url(approval_center_url, self.server.auth_token),  # type: ignore[attr-defined]
                approval_surface_policy=approval_surface_policy,
                open_key=self._optional_string(payload.get("open_key")),
                opener=webbrowser.open,
            )
        except ValueError as error:
            self._write_json({"error": str(error)}, status=400)
            return
        self._write_json(response)

    def _handle_operation_item(self, operation_id: str, payload: dict[str, object]) -> None:
        item_type = self._optional_string(payload.get("item_type"))
        item_payload = payload.get("payload")
        if item_type is None or not isinstance(item_payload, dict):
            self._write_json({"error": "missing_required_fields"}, status=400)
            return
        try:
            item = self.server.runtime.add_item(  # type: ignore[attr-defined]
                operation_id=operation_id,
                item_type=item_type,
                payload=item_payload,
            )
        except ValueError as error:
            self._write_json({"error": str(error)}, status=400)
            return
        self._write_json({"item": item})

    def _handle_operation_status(self, operation_id: str, payload: dict[str, object]) -> None:
        status = self._optional_string(payload.get("status"))
        if status is None:
            self._write_json({"error": "missing_required_fields"}, status=400)
            return
        request_ids = payload.get("approval_request_ids")
        try:
            operation = self.server.runtime.update_operation_status(  # type: ignore[attr-defined]
                operation_id=operation_id,
                status=status,
                approval_request_ids=[str(item) for item in request_ids if isinstance(item, str)]
                if isinstance(request_ids, list)
                else [],
            )
        except ValueError as error:
            self._write_json({"error": str(error)}, status=400)
            return
        self._write_json({"operation": operation})

    def _handle_session_resume(self, session_id: str) -> None:
        try:
            payload = self.server.runtime.resume_session(session_id)  # type: ignore[attr-defined]
        except ValueError:
            self._write_json({"error": "not_found"}, status=404)
            return
        self._write_json(payload)

    def _handle_connect_request_create(self, payload: dict[str, object]) -> None:
        sync_url = self._optional_string(payload.get("sync_url"))
        allowed_origin = self._normalize_origin(self._optional_string(payload.get("allowed_origin")))
        lifetime_seconds = self._optional_int(payload.get("lifetime_seconds")) or 300
        if sync_url is None or allowed_origin is None:
            self._write_json({"error": "missing_required_fields"}, status=400)
            return
        request = self.server.store.create_guard_connect_request(  # type: ignore[attr-defined]
            sync_url=sync_url,
            allowed_origin=allowed_origin,
            now=_now(),
            lifetime_seconds=lifetime_seconds,
        )
        self._write_json(request)

    def _handle_connect_complete(self, payload: dict[str, object]) -> None:
        origin = self._normalize_origin(self.headers.get("Origin"))
        request_id = self._optional_string(payload.get("request_id"))
        pairing_secret = self._optional_string(payload.get("pairing_secret"))
        token = self._optional_string(payload.get("token"))
        if origin is None or request_id is None or pairing_secret is None or token is None:
            self._write_json(
                {"error": "missing_required_fields"},
                status=400,
                extra_headers=self._cors_headers(origin) if origin else None,
            )
            return
        request = self.server.store.get_guard_connect_request(request_id)  # type: ignore[attr-defined]
        if request is None:
            self._write_json({"error": "not_found"}, status=404, extra_headers=self._cors_headers(origin))
            return
        if origin != str(request["allowed_origin"]):
            self._write_json(
                {"error": "forbidden_origin"},
                status=403,
                extra_headers=self._cors_headers(origin),
            )
            return
        try:
            completed_request = self.server.store.complete_guard_connect_request(  # type: ignore[attr-defined]
                request_id=request_id,
                pairing_secret=pairing_secret,
                token=token,
                now=_now(),
            )
        except ValueError as error:
            error_code = str(error)
            status = 400
            if error_code == "connect_request_not_found":
                status = 404
            self._write_json(
                {"error": error_code},
                status=status,
                extra_headers=self._cors_headers(origin),
            )
            return
        self._write_json(
            {"completed": True, "request": completed_request},
            extra_headers=self._cors_headers(origin),
        )

    def _handle_connect_state_read(self, query: str) -> None:
        params = parse_qs(query)
        request_id = self._optional_string(params.get("request_id", [None])[-1])
        pairing_secret = self._optional_string(params.get("pairing_secret", [None])[-1])
        origin = self._normalize_origin(self.headers.get("Origin"))
        if request_id is None:
            self._write_json({"error": "missing_required_fields"}, status=400)
            return
        if self._header_token_is_valid():
            state = self.server.store.get_guard_connect_state(request_id, now=_now())  # type: ignore[attr-defined]
            if state is None:
                self._write_json({"error": "not_found"}, status=404)
                return
            self._write_json({"state": state})
            return
        if origin is None or pairing_secret is None:
            self._write_json({"error": "unauthorized"}, status=401)
            return
        access = self.server.store.verify_guard_connect_access(  # type: ignore[attr-defined]
            request_id=request_id,
            pairing_secret=pairing_secret,
        )
        if access is None:
            self._write_json({"error": "forbidden"}, status=403, extra_headers=self._cors_headers(origin))
            return
        if origin != str(access["allowed_origin"]):
            self._write_json(
                {"error": "forbidden_origin"},
                status=403,
                extra_headers=self._cors_headers(origin),
            )
            return
        state = self.server.store.get_guard_connect_state(request_id, now=_now())  # type: ignore[attr-defined]
        if state is None:
            self._write_json({"error": "not_found"}, status=404, extra_headers=self._cors_headers(origin))
            return
        self._write_json({"state": state}, extra_headers=self._cors_headers(origin))

    def _handle_connect_result_update(self, payload: dict[str, object]) -> None:
        request_id = self._optional_string(payload.get("request_id"))
        status = self._optional_string(payload.get("status"))
        milestone = self._optional_string(payload.get("milestone"))
        reason = self._optional_string(payload.get("reason"))
        sync_payload = payload.get("sync")
        if request_id is None or status is None or milestone is None:
            self._write_json({"error": "missing_required_fields"}, status=400)
            return
        normalized_sync_payload = dict(sync_payload) if isinstance(sync_payload, dict) else None
        try:
            state = self.server.store.record_guard_connect_result(  # type: ignore[attr-defined]
                request_id=request_id,
                status=status,
                milestone=milestone,
                now=_now(),
                reason=reason,
                sync_payload=normalized_sync_payload,
            )
        except ValueError as error:
            error_code = str(error)
            status_code = 400
            if error_code == "connect_state_not_found":
                status_code = 404
            self._write_json({"error": error_code}, status=status_code)
            return
        self._write_json({"state": state})

    def _handle_claude_hook(self, payload: dict[str, object], query: str) -> None:
        params = parse_qs(query)
        home_dir = self._optional_string(params.get("home", [None])[-1])
        guard_home = self._optional_string(params.get("guard-home", [None])[-1])
        workspace = self._optional_string(params.get("workspace", [None])[-1])
        args = argparse.Namespace(
            guard_command="hook",
            home=home_dir,
            guard_home=guard_home,
            workspace=workspace,
            harness="claude-code",
            artifact_id=None,
            artifact_name=None,
            policy_action=None,
            event_file=None,
            json=True,
        )
        buffer = io.StringIO()
        with _CLAUDE_HOOK_EXECUTION_LOCK:
            from ..cli.commands import run_guard_command

            exit_code = run_guard_command(args, input_text=json.dumps(payload), output_stream=buffer)
        raw_response = buffer.getvalue().strip()
        if not raw_response:
            if exit_code == 0:
                self._write_json({})
                return
            self._write_json({"error": "empty_hook_response", "exit_code": exit_code}, status=502)
            return
        try:
            hook_payload = json.loads(raw_response)
        except json.JSONDecodeError:
            self._write_json(
                {"error": "invalid_hook_response", "raw": raw_response, "exit_code": exit_code},
                status=502,
            )
            return
        self._write_json(hook_payload)

    def _token_is_valid(self, query: str) -> bool:
        params = parse_qs(query)
        token = params.get("token", [None])[-1]
        return self._tokens_match(token)

    def _header_token_is_valid(self) -> bool:
        token = self.headers.get("X-Guard-Token")
        return self._tokens_match(token)

    def _tokens_match(self, token: object) -> bool:
        if not isinstance(token, str):
            return False
        try:
            provided = token.encode("ascii")
            expected = self.server.auth_token.encode("ascii")  # type: ignore[attr-defined]
        except UnicodeEncodeError:
            return False
        return secrets.compare_digest(provided, expected)

    def _touch_runtime_heartbeat(self, path: str) -> None:
        if path != "/healthz" and not path.startswith("/v1/"):
            return
        self.server.last_activity_monotonic = time.monotonic()  # type: ignore[attr-defined]
        self.server.store.touch_runtime_state(  # type: ignore[attr-defined]
            session_id=self.server.runtime_session_id,  # type: ignore[attr-defined]
            last_heartbeat_at=_now(),
        )

    def _increment_active_stream_clients(self) -> None:
        with self.server.active_stream_clients_lock:  # type: ignore[attr-defined]
            self.server.active_stream_clients += 1  # type: ignore[attr-defined]

    def _decrement_active_stream_clients(self) -> None:
        with self.server.active_stream_clients_lock:  # type: ignore[attr-defined]
            self.server.active_stream_clients = max(0, self.server.active_stream_clients - 1)  # type: ignore[attr-defined]

    @staticmethod
    def _optional_int(value: object) -> int | None:
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.strip():
            try:
                return int(value.strip())
            except ValueError:
                return None
        return None

    def _stream_events(self, cursor: int) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        next_cursor = cursor
        self._increment_active_stream_clients()
        try:
            while True:
                self._touch_runtime_heartbeat("/v1/events/stream")
                items = self.server.store.list_events_after(next_cursor, limit=100)  # type: ignore[attr-defined]
                for item in items:
                    next_cursor = int(item["event_id"])
                    body = json.dumps(item)
                    try:
                        self.wfile.write(f"data: {body}\n\n".encode())
                        self.wfile.flush()
                    except BrokenPipeError:
                        return
                time.sleep(0.5)
        finally:
            self._decrement_active_stream_clients()

    def _origin_is_allowed_for_request(self, path: str, path_parts: list[str]) -> bool:
        origin = self.headers.get("Origin")
        if origin is None:
            return True
        normalized_origin = self._normalize_origin(origin)
        if normalized_origin is None:
            return False
        parsed = urlparse(normalized_origin)
        local_origin = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
        if local_origin:
            return True
        return normalized_origin in _HOSTED_GUARD_DASHBOARD_ORIGINS and self._is_hosted_dashboard_api_path(
            path, path_parts
        )

    @staticmethod
    def _is_hosted_dashboard_api_path(path: str, path_parts: list[str]) -> bool:
        if path in {
            "/v1/inventory",
            "/v1/connect/state",
            "/v1/daemon/repair",
            "/v1/evidence",
            "/v1/evidence/export",
            "/v1/harnesses",
            "/v1/policy",
            "/v1/policy/clear",
            "/v1/receipts",
            "/v1/receipts/latest",
            "/v1/requests",
            "/v1/runtime",
            "/v1/settings",
        }:
            return True
        if len(path_parts) == 3 and path_parts[:2] in (["v1", "requests"], ["v1", "receipts"]):
            return True
        if len(path_parts) == 4 and path_parts[:2] == ["v1", "requests"] and path_parts[3] in {"approve", "block"}:
            return True
        if len(path_parts) == 4 and path_parts[:2] == ["v1", "harnesses"] and path_parts[3] in {
            "install",
            "verify",
            "repair",
            "uninstall",
        }:
            return True
        return len(path_parts) == 4 and path_parts[:2] == ["v1", "artifacts"] and path_parts[3] == "diff"

    def _is_hosted_dashboard_origin(self) -> bool:
        origin = self._normalize_origin(self.headers.get("Origin"))
        return origin in _HOSTED_GUARD_DASHBOARD_ORIGINS

    @staticmethod
    def _normalize_origin(origin: str | None) -> str | None:
        if not isinstance(origin, str) or not origin.strip():
            return None
        parsed = urlparse(origin.strip())
        if (
            parsed.scheme not in {"http", "https"}
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.params
            or parsed.query
            or parsed.fragment
        ):
            return None
        host = parsed.hostname
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        default_port = 80 if parsed.scheme == "http" else 443
        try:
            port = parsed.port
        except ValueError:
            return None
        port_suffix = f":{port}" if port not in {None, default_port} else ""
        return f"{parsed.scheme}://{host}{port_suffix}"

    @staticmethod
    def _cors_headers(
        origin: str,
        *,
        allow_methods: str = "POST, OPTIONS",
        allow_headers: str = "Content-Type, X-Guard-Token",
    ) -> dict[str, str]:
        return {
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Methods": allow_methods,
            "Access-Control-Allow-Headers": allow_headers,
            "Vary": "Origin",
        }

    def _cors_headers_for_request(
        self,
        *,
        allow_methods: str = "POST, OPTIONS",
        allow_headers: str = "Content-Type, X-Guard-Token",
    ) -> dict[str, str] | None:
        parsed = urlparse(self.path)
        path_parts = [part for part in parsed.path.split("/") if part]
        origin = self._normalize_origin(self.headers.get("Origin"))
        if origin is None or not self._origin_is_allowed_for_request(parsed.path, path_parts):
            return None
        return self._cors_headers(origin, allow_methods=allow_methods, allow_headers=allow_headers)

    def _handle_policy_upsert(self, payload: dict[str, object]) -> None:
        harness = payload.get("harness")
        scope = payload.get("scope")
        action = payload.get("action")
        if not all(isinstance(value, str) and value.strip() for value in (harness, scope, action)):
            self._write_json({"saved": False, "error": "missing_required_fields"}, status=400)
            return
        normalized_scope = str(scope).strip()
        normalized_action = str(action).strip()
        if normalized_scope not in DECISION_SCOPE_VALUES or normalized_action not in GUARD_ACTION_VALUES:
            self._write_json({"saved": False, "error": "unsupported_policy_value"}, status=400)
            return
        record = {
            "harness": str(harness).strip(),
            "scope": normalized_scope,
            "action": normalized_action,
            "artifact_id": self._optional_string(payload.get("artifact_id")),
            "workspace": self._optional_string(payload.get("workspace")),
            "publisher": self._optional_string(payload.get("publisher")),
            "reason": self._optional_string(payload.get("reason")),
        }
        if not self._scope_target_is_valid(
            normalized_scope,
            artifact_id=record["artifact_id"],
            workspace=record["workspace"],
            publisher=record["publisher"],
        ):
            self._write_json({"saved": False, "error": "missing_scope_target"}, status=400)
            return
        store = self.server.store  # type: ignore[attr-defined]
        from ..models import PolicyDecision

        store.upsert_policy(
            PolicyDecision(
                harness=record["harness"],
                scope=record["scope"],  # type: ignore[arg-type]
                action=record["action"],  # type: ignore[arg-type]
                artifact_id=record["artifact_id"],
                workspace=record["workspace"],
                publisher=record["publisher"],
                reason=record["reason"],
            ),
            _now(),
        )
        self._write_json({"saved": True, "decision": record})

    @staticmethod
    def _optional_string(value: object) -> str | None:
        if isinstance(value, str) and value.strip():
            return value.strip()
        return None

    @staticmethod
    def _query_string(query_string: str, key: str) -> str | None:
        value = parse_qs(query_string).get(key, [None])[-1]
        if isinstance(value, str) and value.strip():
            return value.strip()
        return None

    @staticmethod
    def _query_limit(query_string: str, *, default: int, maximum: int) -> int | None:
        raw_value = parse_qs(query_string).get("limit", [None])[-1]
        if raw_value is None:
            return default
        try:
            value = int(raw_value)
        except (TypeError, ValueError):
            return None
        if value < 1:
            return None
        return min(value, maximum)

    @staticmethod
    def _scope_target_is_valid(
        scope: str,
        *,
        artifact_id: str | None,
        workspace: str | None,
        publisher: str | None,
    ) -> bool:
        if scope in {"global", "harness"}:
            return True
        if scope == "artifact":
            return artifact_id is not None
        if scope == "workspace":
            return workspace is not None
        if scope == "publisher":
            return publisher is not None
        return False

    @staticmethod
    def _resolve_request_action(
        path_parts: list[str], payload: dict[str, object]
    ) -> tuple[str | None, str | None, bool]:
        if len(path_parts) == 4 and path_parts[:2] == ["v1", "requests"] and path_parts[3] in {"approve", "block"}:
            return path_parts[2], "allow" if path_parts[3] == "approve" else "block", True
        if len(path_parts) == 3 and path_parts[0] == "approvals" and path_parts[2] == "decision":
            action = payload.get("action")
            if not isinstance(action, str) or not action.strip():
                return path_parts[1], None, True
            return path_parts[1], action.strip(), True
        return None, None, False

    @staticmethod
    def _requires_header_token(path: str, path_parts: list[str]) -> bool:
        if path in {
            "/v1/clients/attach",
            "/v1/clients/heartbeat",
            "/v1/sessions/start",
            "/v1/operations/start",
            "/v1/connect/requests",
            "/v1/connect/result",
            "/v1/operations/block",
            "/v1/policy/decisions",
            "/v1/policy/clear",
            "/v1/settings",
            "/v1/daemon/repair",
        }:
            return True
        if len(path_parts) == 4 and path_parts[:2] == ["v1", "operations"] and path_parts[3] in {"items", "status"}:
            return True
        if len(path_parts) == 4 and path_parts[:2] == ["v1", "requests"] and path_parts[3] in {"approve", "block"}:
            return True
        if len(path_parts) == 4 and path_parts[:2] == ["v1", "harnesses"] and path_parts[3] in {
            "install",
            "verify",
            "repair",
            "uninstall",
        }:
            return True
        return len(path_parts) == 3 and path_parts[0] == "approvals" and path_parts[2] == "decision"

    def _write_json(
        self,
        payload: dict[str, Any],
        *,
        status: int = 200,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        body = json.dumps(payload).encode("utf-8")
        headers = dict(extra_headers or {})
        cors_headers = self._cors_headers_for_request(allow_methods="GET, POST, OPTIONS")
        if cors_headers is not None:
            headers = {**cors_headers, **headers}
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for key, value in self._validated_headers(headers).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _write_empty(
        self,
        *,
        status: int,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        for key, value in self._validated_headers(extra_headers).items():
            self.send_header(key, value)
        self.end_headers()

    @staticmethod
    def _validated_headers(extra_headers: dict[str, str] | None) -> dict[str, str]:
        allowed_headers = {
            "Access-Control-Allow-Origin",
            "Access-Control-Allow-Methods",
            "Access-Control-Allow-Headers",
            "Vary",
        }
        validated: dict[str, str] = {}
        for key, value in (extra_headers or {}).items():
            if key not in allowed_headers or not isinstance(value, str):
                continue
            if "\r" in value or "\n" in value:
                continue
            validated[key] = value
        return validated

    def _write_static_asset(self, relative_path: str) -> None:
        target = (_STATIC_DIR / relative_path).resolve()
        if not target.is_file() or _STATIC_DIR.resolve() not in target.parents:
            self.send_response(404)
            self.end_headers()
            return
        body = target.read_bytes()
        content_type, _ = mimetypes.guess_type(str(target))
        self.send_response(200)
        self.send_header("Content-Type", content_type or "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.end_headers()
        self.wfile.write(body)

    def _write_dashboard_shell(self) -> None:
        if _INDEX_PATH.is_file() and _ENTRY_PATH.is_file():
            encoded = _INDEX_PATH.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Cache-Control", "no-store, max-age=0")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.end_headers()
            self.wfile.write(encoded)
            return
        self._write_json({"error": "dashboard_bundle_missing"}, status=503)

    @staticmethod
    def _is_dashboard_route(path: str) -> bool:
        if path in {
            "/",
            "/home",
            "/dashboard",
            "/inbox",
            "/fleet",
            "/evidence",
            "/settings",
            "/requests",
            "/approvals",
        }:
            return True
        if path.startswith("/requests/"):
            return True
        return path.startswith("/approvals/") and not path.endswith("/decision")


class GuardDaemonServer:
    """Small local daemon for health, receipts, and approval-center introspection."""

    def __init__(
        self,
        store: GuardStore,
        host: str = "127.0.0.1",
        port: int = 0,
        *,
        idle_timeout_seconds: float | None = None,
    ) -> None:
        _validate_dashboard_bundle()
        self._server = _GuardDaemonHttpServer((host, port), _GuardDaemonHandler)
        self._server.store = store
        self._server.runtime = GuardSurfaceRuntime(store)
        self._server.auth_token = load_guard_daemon_auth_token(store.guard_home) or uuid.uuid4().hex
        self._server.runtime_host = host
        self._server.runtime_session_id = uuid.uuid4().hex
        self._server.runtime_started_at = _now()
        self._server.idle_timeout_seconds = _guard_daemon_idle_timeout_seconds(
            store.guard_home,
            idle_timeout_seconds=idle_timeout_seconds,
        )
        self._server.last_activity_monotonic = time.monotonic()
        self._server.active_stream_clients = 0
        self._server.active_stream_clients_lock = threading.Lock()
        self.port = int(self._server.server_address[1])
        self._thread: threading.Thread | None = None
        self._watchdog_thread: threading.Thread | None = None
        self._shutdown_started = threading.Event()

    def start(self) -> None:
        if self._thread is not None:
            return
        self._begin_service()
        self._thread = threading.Thread(target=self._serve_forever, daemon=True)
        self._thread.start()

    def serve(self) -> None:
        self._begin_service()
        self._serve_forever()

    def stop(self) -> None:
        self._shutdown_started.set()
        self._server.shutdown()
        self._server.server_close()
        self._finish_service()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        if self._watchdog_thread is not None:
            self._watchdog_thread.join(timeout=5)
            self._watchdog_thread = None

    def _begin_service(self) -> None:
        self._shutdown_started.clear()
        self._server.last_activity_monotonic = time.monotonic()
        write_guard_daemon_state(self._server.store.guard_home, self.port, self._server.auth_token)
        self._server.store.upsert_runtime_state(
            session_id=self._server.runtime_session_id,
            daemon_host=self._server.runtime_host,
            daemon_port=self.port,
            started_at=self._server.runtime_started_at,
            last_heartbeat_at=_now(),
        )
        self._start_watchdog()

    def _serve_forever(self) -> None:
        try:
            self._server.serve_forever()
        finally:
            self._server.server_close()
            self._finish_service()

    def _finish_service(self) -> None:
        if self._shutdown_started.is_set():
            clear_guard_daemon_state(self._server.store.guard_home)
            self._server.store.clear_runtime_state(session_id=self._server.runtime_session_id)
            return
        self._shutdown_started.set()
        clear_guard_daemon_state(self._server.store.guard_home)
        self._server.store.clear_runtime_state(session_id=self._server.runtime_session_id)

    def _start_watchdog(self) -> None:
        if self._watchdog_thread is not None and self._watchdog_thread.is_alive():
            return
        idle_timeout_seconds = self._server.idle_timeout_seconds
        if idle_timeout_seconds is None or idle_timeout_seconds <= 0:
            return
        self._watchdog_thread = threading.Thread(target=self._watch_for_idle_shutdown, daemon=True)
        self._watchdog_thread.start()

    def _watch_for_idle_shutdown(self) -> None:
        idle_timeout_seconds = self._server.idle_timeout_seconds
        if idle_timeout_seconds is None or idle_timeout_seconds <= 0:
            return
        while not self._shutdown_started.is_set():
            with self._server.active_stream_clients_lock:
                active_stream_clients = self._server.active_stream_clients
            if active_stream_clients > 0:
                time.sleep(_GUARD_DAEMON_IDLE_POLL_INTERVAL_SECONDS)
                continue
            if time.monotonic() - self._server.last_activity_monotonic >= idle_timeout_seconds:
                self._shutdown_started.set()
                self._server.shutdown()
                return
            time.sleep(_GUARD_DAEMON_IDLE_POLL_INTERVAL_SECONDS)


def _approval_center_browser_url(approval_center_url: str, auth_token: str) -> str:
    parsed = urlparse(approval_center_url)
    fragment_pairs = [
        (key, value) for key, value in parse_qsl(parsed.fragment, keep_blank_values=True) if key != "guard-token"
    ]
    fragment_pairs.append(("guard-token", auth_token))
    return urlunparse(parsed._replace(fragment=urlencode(fragment_pairs)))


def _build_local_url(host: str, port: int, path: str) -> str:
    host_part = f"[{host}]" if ":" in host else host
    return f"http://{host_part}:{port}{path}"


_HARNESS_RETRY_COPY: dict[str, str] = {
    "codex": "Return to Codex and retry",
    "claude-code": "Return to Claude and retry",
    "opencode": "Return to OpenCode and retry",
    "copilot": "Return to Copilot and retry",
}
_DEFAULT_RETRY_COPY = "Return to your AI assistant and retry"


def _build_resolution_copy(action: str, harness: str) -> dict[str, str]:
    title = "Approved. Retry in chat." if action == "allow" else "Blocked. Guard will remember this decision."
    return {"title": title, "body": _HARNESS_RETRY_COPY.get(harness, _DEFAULT_RETRY_COPY)}


def _now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def _validate_dashboard_bundle() -> None:
    if not _INDEX_PATH.is_file() or not _ENTRY_PATH.is_file():
        raise RuntimeError(
            "Guard dashboard bundle is missing. Run `pnpm install && pnpm run build` in the dashboard directory."
        )


def _guard_daemon_idle_timeout_seconds(
    guard_home: Path,
    *,
    idle_timeout_seconds: float | None = None,
) -> float | None:
    if idle_timeout_seconds is not None:
        return idle_timeout_seconds if idle_timeout_seconds > 0 else None
    configured_timeout = os.environ.get("GUARD_DAEMON_IDLE_TIMEOUT_SECONDS")
    if isinstance(configured_timeout, str) and configured_timeout.strip():
        try:
            parsed_timeout = float(configured_timeout.strip())
        except ValueError:
            parsed_timeout = None
        if isinstance(parsed_timeout, float) and parsed_timeout > 0:
            return parsed_timeout
        if parsed_timeout == 0:
            return None
    if _guard_home_is_ephemeral(guard_home):
        return _EPHEMERAL_GUARD_DAEMON_IDLE_TIMEOUT_SECONDS
    return _DEFAULT_GUARD_DAEMON_IDLE_TIMEOUT_SECONDS


def _guard_home_is_ephemeral(guard_home: Path) -> bool:
    resolved_parts = guard_home.resolve().parts
    return any(part.startswith("pytest-") or "pytest-of-" in part for part in resolved_parts)


def _int_query_value(query: str, key: str) -> int:
    values = parse_qs(query).get(key, ["0"])
    raw_value = values[-1]
    try:
        return int(str(raw_value))
    except ValueError:
        return 0
