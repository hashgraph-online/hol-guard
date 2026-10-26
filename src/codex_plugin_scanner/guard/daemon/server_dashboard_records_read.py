"""Dashboard request, receipt, policy and evidence read routes for the daemon."""

# pyright: reportAttributeAccessIssue=false, reportUnknownMemberType=false

from __future__ import annotations

from urllib.parse import ParseResult, parse_qs, unquote

from ..store import GuardStore
from ..store_evidence import (
    count_evidence,
    evidence_record_to_dict,
    export_evidence_csv,
    export_evidence_json,
    list_evidence,
)
from .command_activity_api import (
    handle_command_activity_analytics,
    handle_command_activity_diagnostics,
    handle_command_activity_list,
    handle_command_extensions,
)
from .managed_controls_api import managed_policy_rows
from .server_common import _ServerProxy

m = _ServerProxy()


class _DashboardRecordsReadRoutes:
    def _serve_dashboard_records_read(self, parsed: ParseResult, path_parts: list[str], store: GuardStore) -> bool:
        """Serve a dashboard read route; return True when the route was handled."""
        if parsed.path == "/v1/requests":
            self._handle_requests_list(parsed.query)
            return True
        if parsed.path == "/v1/command-activity":
            handle_command_activity_list(self, parsed.query)
            return True
        if parsed.path == "/v1/command-activity/analytics":
            handle_command_activity_analytics(self, parsed.query)
            return True
        if parsed.path == "/v1/command-activity/diagnostics":
            handle_command_activity_diagnostics(self)
            return True
        if parsed.path == "/v1/command-extensions":
            handle_command_extensions(self, parsed.query)
            return True
        if parsed.path == "/v1/connect/state":
            self._write_legacy_pairing_disabled()
            return True
        if len(path_parts) == 4 and path_parts[:2] == ["v1", "requests"] and path_parts[3] == "business-summary":
            from .business_review_summary import handle_business_review_summary

            handle_business_review_summary(self, path_parts[2])
            return True
        if len(path_parts) == 3 and path_parts[:2] == ["v1", "requests"]:
            approval = store.get_approval_request(path_parts[2])
            if approval is None and not self._is_hosted_dashboard_origin():
                from .business_review_queue import NativeBusinessReviewQueueReadError, native_request_detail

                try:
                    native_detail = native_request_detail(store, unquote(path_parts[2]))
                except NativeBusinessReviewQueueReadError:
                    self._write_json(
                        {
                            "error": "native_local_business_queue_read_failed",
                            "message": (
                                "Saved request details could not be verified. "
                                "Refresh this request or return to the queue."
                            ),
                            "recovery": {
                                "code": "request_unavailable",
                                "title": "Request details are unavailable.",
                                "body": (
                                    "The saved request could not be checked. "
                                    "Refresh this request or return to the queue."
                                ),
                                "queue_url": self._local_queue_url(),
                            },
                        },
                        status=503,
                        extra_headers={"Cache-Control": "no-store"},
                    )
                    return True
                if native_detail is not None:
                    self._write_json(native_detail, extra_headers={"Cache-Control": "no-store"})
                    return True
            if approval is None:
                self._write_json(
                    {
                        "error": "not_found",
                        "recovery": {
                            "code": "request_unknown",
                            "title": "This request is no longer waiting.",
                            "body": "The request was either already resolved or expired. You can close this tab.",
                            "queue_url": self._local_queue_url(),
                        },
                    },
                    status=404,
                )
                return True
            self._write_json(self._approval_with_extension_recommendation(approval))
            return True
        if parsed.path == "/v1/receipts":
            query = parse_qs(parsed.query)
            harness_q = query.get("harness", [None])[-1]
            limit_q = query.get("limit", ["200"])[-1]
            try:
                limit_v = min(max(int(limit_q), 1), 500)
            except (ValueError, TypeError):
                limit_v = 200
            self._write_json(
                {
                    "items": store.list_receipts(
                        limit=limit_v,
                        harness=harness_q if isinstance(harness_q, str) and harness_q else None,
                    )
                }
            )
            return True
        if parsed.path == "/v1/receipts/analytics":
            query = parse_qs(parsed.query)
            activity_days_q = query.get("activity_days", ["90"])[-1]
            trend_days_q = query.get("trend_days", ["7"])[-1]
            top_limit_q = query.get("top_limit", ["10"])[-1]
            try:
                activity_days = min(max(int(activity_days_q), 1), 366)
            except (ValueError, TypeError):
                activity_days = 90
            try:
                trend_days = min(max(int(trend_days_q), 1), activity_days)
            except (ValueError, TypeError):
                trend_days = 7
            try:
                top_limit = min(max(int(top_limit_q), 1), 50)
            except (ValueError, TypeError):
                top_limit = 10
            self._write_json(
                store.receipt_analytics(
                    activity_days=activity_days,
                    trend_days=trend_days,
                    top_limit=top_limit,
                )
            )
            return True
        if parsed.path == "/v1/receipts/latest":
            query = parse_qs(parsed.query)
            harness = query.get("harness", [None])[-1]
            artifact_id = query.get("artifact_id", [None])[-1]
            if not isinstance(harness, str) or not harness or not isinstance(artifact_id, str) or not artifact_id:
                self._write_json({"error": "missing_receipt_query"}, status=400)
                return True
            receipt = store.get_latest_receipt(harness, artifact_id)
            if receipt is None:
                self._write_json({"error": "not_found"}, status=404)
                return True
            self._write_json(receipt)
            return True
        if len(path_parts) == 3 and path_parts[:2] == ["v1", "receipts"]:
            receipt = store.get_receipt(path_parts[2])
            if receipt is None:
                self._write_json({"error": "not_found"}, status=404)
                return True
            self._write_json(receipt)
            return True
        if parsed.path == "/v1/policy":
            query = parse_qs(parsed.query)
            harness = query.get("harness", [None])[-1]
            harness_filter = harness if isinstance(harness, str) else None
            self._write_json(
                {
                    "items": managed_policy_rows(store, harness_filter),
                    "cloud_exceptions": store.list_cloud_exceptions(harness=harness_filter),
                }
            )
            return True
        if parsed.path == "/v1/policy/cloud-exceptions":
            query = parse_qs(parsed.query)
            harness = query.get("harness", [None])[-1]
            harness_filter = harness if isinstance(harness, str) else None
            self._write_json({"items": store.list_cloud_exceptions(harness=harness_filter)})
            return True
        if parsed.path == "/v1/policy/cloud-exception-requests":
            self._handle_cloud_exception_request_list()
            return True
        if parsed.path == "/v1/evidence":
            query = parse_qs(parsed.query)
            harness_q = query.get("harness", [None])[-1]
            category_q = query.get("category", [None])[-1]
            severity_q = query.get("severity", [None])[-1]
            before_q = query.get("before", [None])[-1]
            limit_q = query.get("limit", ["100"])[-1]
            try:
                limit_v = min(max(int(limit_q), 1), 500)
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
                    include_details=False,
                )
                total = count_evidence(
                    conn,
                    harness=harness_q if isinstance(harness_q, str) else None,
                    category=category_q if isinstance(category_q, str) else None,
                    severity=severity_q if isinstance(severity_q, str) else None,
                )
            self._write_json(
                {
                    "items": [evidence_record_to_dict(record) for record in records],
                    "total": total,
                }
            )
            return True
        if parsed.path == "/v1/evidence/export":
            query = parse_qs(parsed.query)
            format_q = query.get("format", ["json"])[-1]
            with store._connect() as conn:
                if format_q == "json":
                    export_body = export_evidence_json(conn, limit=10_000)
                    content_type = "application/json"
                elif format_q == "csv":
                    export_body = export_evidence_csv(conn, limit=10_000)
                    content_type = "text/csv; charset=utf-8"
                else:
                    self._write_json({"error": "invalid_export_format"}, status=400)
                    return True
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.end_headers()
            self.wfile.write(export_body.encode("utf-8"))
            return True
        if len(path_parts) == 4 and path_parts[:3] == ["v1", "artifacts", path_parts[2]] and path_parts[3] == "diff":
            query = parse_qs(parsed.query)
            harness = query.get("harness", [None])[-1]
            if not isinstance(harness, str) or not harness:
                self._write_json({"error": "missing_harness"}, status=400)
                return True
            diff = store.get_latest_diff(harness, unquote(path_parts[2]))
            if diff is None:
                self._write_json({"error": "not_found"}, status=404)
                return True
            self._write_json(diff)
            return True
        if parsed.path == "/v1/read-state":
            self._write_json({"ids": store.get_read_state()})
            return True
        if parsed.path in m._ROOT_STATIC_FILES:
            self._write_static_asset(parsed.path.removeprefix("/"))
            return True
        if parsed.path.startswith("/assets/") or parsed.path.startswith("/brand/"):
            self._write_static_asset(parsed.path.removeprefix("/"))
            return True
        if self._is_dashboard_route(parsed.path):
            self._write_dashboard_shell()
            return True
        return False
