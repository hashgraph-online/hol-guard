"""Dashboard support handlers (queue, capabilities, shell, event stream) for the daemon."""

# pyright: reportAttributeAccessIssue=false, reportUnknownMemberType=false

from __future__ import annotations

import json
import mimetypes
import platform
import time

from ...version import __version__
from ..cli.install_commands import list_harness_setup_items
from ..native_daemon_handler import NativeDaemonHandlerError, native_detection_app_statuses, native_requests_list
from ..native_hook_evidence_writer import unreachable_writer_stats
from ..store_approvals import InvalidApprovalCursorError
from .dashboard_bundle import dashboard_build_id, is_pinned_path, pinned_dashboard_file, stamp_dashboard_build
from .manager import GUARD_DAEMON_COMPATIBILITY_VERSION
from .server_common import _NATIVE_HANDLER_UNAVAILABLE, _is_string_object_dict, _ServerProxy
from .server_control_health import _HEADLESS_OPERATIONS, _headless_safe_failure_reasons
from .server_control_sync import _safe_int

m = _ServerProxy()


class _DashboardSupportRoutes:
    def _handle_requests_list(self, query_string: str) -> None:
        guard_home = self.server.store.guard_home  # type: ignore[attr-defined]
        verdict = self._native_handler_decision(lambda: native_requests_list(query_string, guard_home=guard_home))
        if verdict is None:
            return
        options = verdict.fields
        from ..native_approval_scope import ApprovalScopeUnavailableError
        from .business_review_queue import NativeBusinessReviewQueueReadError, local_request_page

        try:
            read_page = (
                self.server.store.list_approval_request_page
                if self._is_hosted_dashboard_origin()
                else (lambda **options: local_request_page(self.server.store, **options))
            )
            page = read_page(**options)
        except NativeBusinessReviewQueueReadError:
            self._write_json(
                {"error": "native_local_business_queue_read_failed"},
                status=503,
                extra_headers={"Cache-Control": "no-store"},
            )
            return
        except ApprovalScopeUnavailableError:
            self._write_json(
                {"error": "native_approval_scope_unavailable"},
                status=503,
                extra_headers={"Cache-Control": "no-store"},
            )
            return
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
        self._write_json(page, extra_headers={"Cache-Control": "no-store"})

    def _handle_capabilities(self) -> None:
        context = self._harness_context({})
        items = list_harness_setup_items(context, self.server.store)  # type: ignore[attr-defined]
        supported = []
        failure_reasons = _headless_safe_failure_reasons()
        listed = [item for item in items if isinstance(item.get("harness"), str)]
        try:
            app_statuses = native_detection_app_statuses(
                [item.get("status") for item in listed],
                guard_home=self.server.store.guard_home,  # type: ignore[attr-defined]
            )
        except NativeDaemonHandlerError:
            self._write_json(_NATIVE_HANDLER_UNAVAILABLE[1], status=_NATIVE_HANDLER_UNAVAILABLE[0])
            return
        for item, app_status in zip(listed, app_statuses, strict=True):
            harness = item["harness"]
            supported.append(
                {
                    "display_name": item.get("display_name"),
                    "harness": harness,
                    "status": app_status,
                    "command_available": bool(item.get("command_available")),
                    "headless_actions": list(_HEADLESS_OPERATIONS[:-1]),
                    "safe_failure_reasons": failure_reasons,
                }
            )
        self._write_json(
            {
                "auth_state": "dashboard_session" if self._dashboard_session_token_is_valid() else "local_token",
                "command_available": any(bool(item.get("command_available")) for item in items),
                "daemon": {
                    "compatibility_version": GUARD_DAEMON_COMPATIBILITY_VERSION,
                    "package_version": __version__,
                    "platform": platform.system().lower() or "unknown",
                },
                "headless_api": {
                    "execution_mode": "guard_cloud_command_queue",
                    "operations": list(_HEADLESS_OPERATIONS),
                },
                "package_firewall_api": {
                    "execution_mode": "guard_cloud_command_queue",
                    "operations": ["status", "connect", "install", "repair", "test", "audit", "sync", "remove"],
                },
                "safe_failure_reasons": _headless_safe_failure_reasons(),
                "supported_harnesses": sorted(item["harness"] for item in supported),
                "items": supported,
            }
        )

    def _operator_health_payload(self) -> dict[str, object]:
        daemon_server = self._daemon_server()
        scheduler = daemon_server.runtime_hook_scheduler.stats()
        try:
            evidence_writer = daemon_server.runtime_hook_evidence_writer.stats()
        except Exception:
            evidence_writer = unreachable_writer_stats()
        activity_health = daemon_server.store.get_command_activity_persistence_health()
        # A writer the resident has not built yet is idle, not broken: a daemon
        # that has admitted no hook since it started has nothing to repair.
        evidence_fault = bool(evidence_writer.get("started", True)) and not evidence_writer["running"]
        store_busy = (
            activity_health.persistence_error_count > 0
            and activity_health.last_error_code is not None
            and activity_health.last_error_code.startswith("sqlite.")
        )
        saturated = scheduler["queued_limit"] > 0 and scheduler["queued"] >= scheduler["queued_limit"]

        if evidence_fault:
            state = "saturated"
            cause = "A local processing component stopped and needs repair."
        elif store_busy:
            state = "store-contended"
            cause = "The local evidence store is busy; queued writes are retrying automatically."
        elif saturated:
            state = "saturated"
            cause = "Local review capacity is full; new work waits or receives a typed retry."
        elif scheduler["queued"] > 0:
            state = "backlogged"
            cause = "A short local backlog is waiting behind active reviews."
        else:
            state = "healthy"
            cause = "Local reviews are processing within available capacity."

        repairable = evidence_fault
        return {
            "state": state,
            "cause": cause,
            "automatic_recovery": (
                "Repair restores the stopped local component."
                if repairable
                else "Guard drains queued work and adjusts ready workers automatically."
            ),
            "repairable": repairable,
            "queue_depth": scheduler["queued"],
            "queue_limit": scheduler["queued_limit"],
            "oldest_wait_ms": scheduler["oldest_queued_ms"],
            "workers_busy": scheduler["active"],
            "workers_ready": max(0, scheduler["active_limit"] - scheduler["active"]),
            "workers_configured": scheduler["active_limit"],
        }

    def _handle_mcp_policy_request_get(self, request_id: str) -> None:
        """Return sanitized MCP policy request details for the dashboard.

        GET /v1/mcp-policy/requests/<id>

        Returns the request status, digests, mode, timestamps, and a
        sanitized semantic diff summary.  Never returns the canonical
        policy YAML or the full plan JSON — the dashboard renders the
        diff summary only.
        """
        import json as _json

        from codex_plugin_scanner.guard.mcp.policy_store import MCPolicyRequestRepository

        store = self.server.store  # type: ignore[attr-defined]
        repo = MCPolicyRequestRepository(store)
        request = repo.get_request(request_id)
        if request is None:
            self._write_json({"error": "not_found"}, status=404)
            return

        result: dict[str, object] = {}
        if request.result_json:
            try:
                parsed_result: object = _json.loads(request.result_json)
                if _is_string_object_dict(parsed_result):
                    result = parsed_result
            except _json.JSONDecodeError:
                pass

        plan_summary: dict[str, object] = {}
        if request.plan_json:
            try:
                parsed_plan: object = _json.loads(request.plan_json)
                if _is_string_object_dict(parsed_plan):
                    plan_summary = parsed_plan
            except _json.JSONDecodeError:
                pass

        inserted_value = result.get("inserted", 0)
        replaced_value = result.get("replaced", 0)
        inserted = inserted_value if isinstance(inserted_value, (bool, int)) else 0
        replaced = replaced_value if isinstance(replaced_value, (bool, int)) else 0
        additions_value = plan_summary.get("additions", [])
        replacements_value = plan_summary.get("replacements", [])
        removals_value = plan_summary.get("removals", [])
        additions = additions_value if isinstance(additions_value, list) else []
        replacements = replacements_value if isinstance(replacements_value, list) else []
        removals = removals_value if isinstance(removals_value, list) else []

        self._write_json(
            {
                "requestId": request.request_id,
                "status": request.status,
                "documentId": request.policy_document_id,
                "candidateDigest": request.policy_document_digest,
                "expectedCurrentDigest": request.expected_current_digest,
                "expectedPolicyGeneration": request.expected_policy_generation,
                "mode": request.mode,
                "createdAt": request.created_at,
                "expiresAt": request.expires_at,
                "resolvedAt": request.resolved_at,
                "failureCode": request.failure_code,
                "isTerminal": request.is_terminal,
                "isExpired": request.is_expired,
                "result": {
                    "inserted": _safe_int(inserted),
                    "replaced": _safe_int(replaced),
                },
                "writePlan": {
                    "additions": list(additions),
                    "replacements": list(replacements),
                    "removals": list(removals),
                },
                "semanticDiff": {
                    "additionCount": len(additions),
                    "replacementCount": len(replacements),
                    "removalCount": len(removals),
                },
                "activeEnforcementWarning": request.status == "pending" and not request.is_expired,
            }
        )

    def _write_static_asset(self, relative_path: str) -> None:
        if is_pinned_path(relative_path):
            body = pinned_dashboard_file(m._STATIC_DIR, relative_path)
        else:
            target = (m._STATIC_DIR / relative_path).resolve()
            in_static_dir = target.is_file() and m._STATIC_DIR.resolve() in target.parents
            body = target.read_bytes() if in_static_dir else None
        if body is None:
            self.send_response(404)
            self.end_headers()
            return
        content_type, _ = mimetypes.guess_type(relative_path)
        self.send_response(200)
        self.send_header("Content-Type", content_type or "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _write_dashboard_shell(self) -> None:
        encoded = pinned_dashboard_file(m._STATIC_DIR, "index.html")
        if encoded is not None and pinned_dashboard_file(m._STATIC_DIR, "assets/guard-dashboard.js") is not None:
            encoded = stamp_dashboard_build(encoded, dashboard_build_id(m._STATIC_DIR))
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Cache-Control", "no-store, max-age=0")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.send_header("Content-Security-Policy", m._DASHBOARD_CSP)
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Content-Type-Options", "nosniff")
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
            "/protect",
            "/evidence",
            "/extensions",
            "/supply-chain",
            "/audit",
            "/policy",
            "/feed-health",
            "/workspaces",
            "/releases",
            "/settings",
            "/about",
            "/protection/repair",
            "/requests",
            "/approvals",
        }:
            return True
        if path.startswith("/requests/"):
            return True
        if path.startswith("/apps/"):
            return True
        if path.startswith("/extensions/"):
            return True
        return path.startswith("/approvals/") and not path.endswith("/decision")

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
                    event_id = item.get("event_id")
                    if not isinstance(event_id, int):
                        continue
                    next_cursor = event_id
                    body = json.dumps(item)
                    try:
                        self.wfile.write(f"data: {body}\n\n".encode())
                        self.wfile.flush()
                    except BrokenPipeError:
                        return
                time.sleep(0.5)
        finally:
            self._decrement_active_stream_clients()
