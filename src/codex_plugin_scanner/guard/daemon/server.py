"""Local Guard daemon helpers."""

from __future__ import annotations

import html
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from ..approvals import apply_approval_resolution
from ..store import GuardStore
from .manager import clear_guard_daemon_state, write_guard_daemon_state


class _GuardDaemonHttpServer(ThreadingHTTPServer):
    store: GuardStore


class _GuardDaemonHandler(BaseHTTPRequestHandler):
    _MAX_BODY_BYTES = 1_000_000

    def do_GET(self) -> None:
        store = self.server.store  # type: ignore[attr-defined]
        parsed = urlparse(self.path)
        path_parts = [part for part in parsed.path.split("/") if part]
        if parsed.path == "/":
            self._write_html(_build_approval_center_html(store.list_approval_requests(limit=200)))
            return
        if parsed.path == "/healthz":
            self._write_json(
                {
                    "ok": True,
                    "receipts": len(store.list_receipts(limit=500)),
                    "approvals": store.count_approval_requests(),
                    "tables": store.list_table_names(),
                }
            )
            return
        if parsed.path == "/v1/requests":
            self._write_json({"items": store.list_approval_requests(limit=200)})
            return
        if len(path_parts) == 3 and path_parts[:2] == ["v1", "requests"]:
            approval = store.get_approval_request(path_parts[2])
            if approval is None:
                self._write_json({"error": "not_found"}, status=404)
                return
            self._write_json(approval)
            return
        if parsed.path == "/requests":
            self._write_html(_build_approval_center_html(store.list_approval_requests(limit=200)))
            return
        if len(path_parts) == 2 and path_parts[0] == "requests":
            self._write_html(_build_request_detail_html(store, path_parts[1]))
            return
        if parsed.path == "/v1/receipts":
            self._write_json({"items": store.list_receipts(limit=200)})
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
        if len(path_parts) == 4 and path_parts[:3] == ["v1", "artifacts", path_parts[2]] and path_parts[3] == "diff":
            query = parse_qs(parsed.query)
            harness = query.get("harness", [None])[-1]
            if not isinstance(harness, str) or not harness:
                self._write_json({"error": "missing_harness"}, status=400)
                return
            diff = store.get_latest_diff(harness, path_parts[2])
            if diff is None:
                self._write_json({"error": "not_found"}, status=404)
                return
            self._write_json(diff)
            return
        if parsed.path == "/receipts":
            self._write_json({"items": store.list_receipts(limit=200)})
            return
        if parsed.path == "/approvals":
            self._write_json({"items": store.list_approval_requests(limit=200)})
            return
        if parsed.path.startswith("/approvals/"):
            request_id = parsed.path.removeprefix("/approvals/")
            approval = store.get_approval_request(request_id)
            if approval is None:
                self._write_json({"error": "not_found"}, status=404)
                return
            self._write_json(approval)
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self) -> None:
        if not self._origin_is_allowed():
            self._write_json({"error": "forbidden_origin"}, status=403)
            return
        parsed = urlparse(self.path)
        payload = self._load_request_body()
        path_parts = [part for part in parsed.path.split("/") if part]
        if parsed.path == "/v1/policy/decisions":
            self._handle_policy_upsert(payload)
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
            )
        except ValueError as error:
            self._write_json({"resolved": False, "error": str(error)}, status=400)
            return
        if "/decision" in parsed.path:
            self._write_html(
                "<!doctype html><html><body style='font-family:ui-sans-serif,system-ui;padding:24px;'>"
                "<h1>Approval resolved</h1><p>Guard has received your decision. "
                "You can close this window and return to your terminal.</p></body></html>"
            )
            return
        self._write_json({"resolved": True, "item": updated})

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _load_request_body(self) -> dict[str, object]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > self._MAX_BODY_BYTES:
            return {}
        raw_body = self.rfile.read(length).decode("utf-8")
        content_type = self.headers.get("Content-Type", "")
        if "application/json" in content_type:
            try:
                payload = json.loads(raw_body)
            except json.JSONDecodeError:
                return {}
            return payload if isinstance(payload, dict) else {}
        form_payload = parse_qs(raw_body)
        return {key: values[-1] for key, values in form_payload.items() if values}

    def _origin_is_allowed(self) -> bool:
        origin = self.headers.get("Origin")
        if origin is None:
            return True
        parsed = urlparse(origin)
        if parsed.scheme not in {"http", "https"}:
            return False
        return parsed.hostname in {"127.0.0.1", "localhost", "::1"}

    def _handle_policy_upsert(self, payload: dict[str, object]) -> None:
        harness = payload.get("harness")
        scope = payload.get("scope")
        action = payload.get("action")
        if not all(isinstance(value, str) and value.strip() for value in (harness, scope, action)):
            self._write_json({"saved": False, "error": "missing_required_fields"}, status=400)
            return
        record = {
            "harness": str(harness).strip(),
            "scope": str(scope).strip(),
            "action": str(action).strip(),
            "artifact_id": self._optional_string(payload.get("artifact_id")),
            "workspace": self._optional_string(payload.get("workspace")),
            "publisher": self._optional_string(payload.get("publisher")),
            "reason": self._optional_string(payload.get("reason")),
        }
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

    def _write_json(self, payload: dict[str, Any], *, status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _write_html(self, body: str) -> None:
        encoded = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


class GuardDaemonServer:
    """Small local daemon for health, receipts, and approval-center introspection."""

    def __init__(self, store: GuardStore, host: str = "127.0.0.1", port: int = 0) -> None:
        self._server = _GuardDaemonHttpServer((host, port), _GuardDaemonHandler)
        self._server.store = store
        self.port = int(self._server.server_address[1])
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None:
            return
        write_guard_daemon_state(self._server.store.guard_home, self.port)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def serve(self) -> None:
        write_guard_daemon_state(self._server.store.guard_home, self.port)
        try:
            self._server.serve_forever()
        finally:
            clear_guard_daemon_state(self._server.store.guard_home)

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        clear_guard_daemon_state(self._server.store.guard_home)
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None


def _build_approval_center_html(items: list[dict[str, object]]) -> str:
    rows = []
    for item in items:
        request_id = html.escape(str(item.get("request_id") or "unknown"), quote=True)
        changed_fields = html.escape(
            ", ".join(str(value) for value in item.get("changed_fields", []) if isinstance(value, str)) or "none"
        )
        artifact_label = html.escape(str(item.get("artifact_name") or item.get("artifact_id") or "unknown"))
        harness_label = html.escape(str(item.get("harness") or "unknown"))
        recommendation_label = html.escape(str(item.get("policy_action") or "warn"))
        detail_url = f"/requests/{request_id}"
        rows.append(
            "\n".join(
                [
                    "<article style='border:1px solid #d9d9d9;border-radius:16px;padding:16px;margin:16px 0;'>",
                    f"<h2 style='margin:0 0 8px 0'>{artifact_label}</h2>",
                    f"<p><strong>Harness:</strong> {harness_label}</p>",
                    f"<p><strong>Changed fields:</strong> {changed_fields}</p>",
                    f"<p><strong>Recommendation:</strong> {recommendation_label}</p>",
                    f"<p><a href='{detail_url}'>Open approval details</a></p>",
                    "</article>",
                ]
            )
        )
    body = "\n".join(rows) or "<p>No pending approvals.</p>"
    return (
        "<!doctype html><html><head><meta charset='utf-8'><title>HOL Guard approval center</title></head>"
        "<body style='font-family:ui-sans-serif,system-ui;padding:24px;max-width:900px;margin:0 auto;'>"
        "<h1>HOL Guard approval center</h1>"
        "<p>Approve blocked harness changes without losing the current session.</p>"
        f"{body}"
        "</body></html>"
    )


def _build_request_detail_html(store: GuardStore, request_id: str) -> str:
    item = store.get_approval_request(request_id)
    if item is None:
        return (
            "<!doctype html><html><body style='font-family:ui-sans-serif,system-ui;padding:24px;'>"
            "<h1>Approval not found</h1><p>The requested approval no longer exists.</p></body></html>"
        )
    artifact_id = str(item.get("artifact_id") or "unknown")
    harness = str(item.get("harness") or "unknown")
    diff = store.get_latest_diff(harness, artifact_id)
    latest_receipt = store.get_latest_receipt(harness, artifact_id)
    changed_fields = (
        ", ".join(str(value) for value in item.get("changed_fields", []) if isinstance(value, str)) or "none"
    )
    recommended_scope = str(item.get("recommended_scope") or "artifact")
    scope_options = [
        ("artifact", "Trust this exact artifact"),
        ("workspace", "Trust this workspace"),
        ("publisher", "Trust this publisher in this harness"),
        ("harness", "Trust this harness"),
        ("global", "Trust globally"),
    ]
    scope_options_html = "".join(
        (
            f"<option value='{html.escape(value, quote=True)}'"
            f"{' selected' if recommended_scope == value else ''}>"
            f"{html.escape(label)}</option>"
        )
        for value, label in scope_options
    )
    diff_html = (
        "<p>No previous diff is stored for this artifact yet.</p>"
        if diff is None
        else (
            "<ul>"
            "<li><strong>Changed fields:</strong> "
            f"{html.escape(', '.join(str(value) for value in diff['changed_fields']))}</li>"
            f"<li><strong>Previous hash:</strong> {html.escape(str(diff['previous_hash'] or 'none'))}</li>"
            f"<li><strong>Current hash:</strong> {html.escape(str(diff['current_hash']))}</li>"
            "</ul>"
        )
    )
    receipt_html = (
        "<p>No previous receipt recorded.</p>"
        if latest_receipt is None
        else (
            "<ul>"
            f"<li><strong>Decision:</strong> {html.escape(str(latest_receipt['policy_decision']))}</li>"
            f"<li><strong>Capabilities:</strong> {html.escape(str(latest_receipt['capabilities_summary']))}</li>"
            f"<li><strong>Provenance:</strong> {html.escape(str(latest_receipt['provenance_summary']))}</li>"
            "</ul>"
        )
    )
    return (
        "<!doctype html><html><head><meta charset='utf-8'><title>HOL Guard approval detail</title></head>"
        "<body style='font-family:ui-sans-serif,system-ui;padding:24px;max-width:900px;margin:0 auto;'>"
        f"<p><a href='/'>← Back to pending approvals</a></p>"
        f"<h1>{html.escape(str(item.get('artifact_name') or artifact_id))}</h1>"
        f"<p><strong>Harness:</strong> {html.escape(harness)}</p>"
        f"<p><strong>Artifact ID:</strong> {html.escape(artifact_id)}</p>"
        f"<p><strong>Changed fields:</strong> {html.escape(changed_fields)}</p>"
        f"<p><strong>Recommended scope:</strong> {html.escape(str(item.get('recommended_scope') or 'artifact'))}</p>"
        f"<p><strong>Recommendation:</strong> {html.escape(str(item.get('policy_action') or 'review'))}</p>"
        "<h2>What changed</h2>"
        f"{diff_html}"
        "<h2>Latest recorded evidence</h2>"
        f"{receipt_html}"
        "<h2>Approve or block</h2>"
        "<form method='post' action='/approvals/"
        f"{html.escape(request_id, quote=True)}/decision' style='display:grid;gap:12px;max-width:480px;'>"
        "<label>Decision scope"
        "<select name='scope'>"
        f"{scope_options_html}"
        "</select>"
        "</label>"
        "<label>Workspace path (required for workspace scope)"
        "<input name='workspace' type='text' />"
        "</label>"
        "<label>Reason"
        "<input name='reason' type='text' value='approved in local approval center' />"
        "</label>"
        "<div style='display:flex;gap:8px;flex-wrap:wrap;'>"
        "<button name='action' value='allow'>Allow</button>"
        "<button name='action' value='block'>Block</button>"
        "</div>"
        "</form>"
        "</body></html>"
    )


def _now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()
