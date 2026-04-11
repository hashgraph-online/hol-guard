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
    def do_GET(self) -> None:
        store = self.server.store  # type: ignore[attr-defined]
        parsed = urlparse(self.path)
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
        parsed = urlparse(self.path)
        if not parsed.path.endswith("/decision") or not parsed.path.startswith("/approvals/"):
            self.send_response(404)
            self.end_headers()
            return
        request_id = parsed.path.removeprefix("/approvals/").removesuffix("/decision")
        payload = self._load_request_body()
        action = payload.get("action")
        scope = payload.get("scope")
        if not isinstance(action, str) or not action.strip() or not isinstance(scope, str) or not scope.strip():
            self._write_json({"resolved": False, "error": "missing_required_fields"}, status=400)
            return
        reason = payload.get("reason")
        if not isinstance(reason, str):
            reason = None
        try:
            updated = apply_approval_resolution(
                store=self.server.store,  # type: ignore[attr-defined]
                request_id=request_id,
                action=action.strip(),
                scope=scope.strip(),
                workspace=None,
                reason=reason,
            )
        except ValueError as error:
            self._write_json({"resolved": False, "error": str(error)}, status=400)
            return
        self._write_json({"resolved": True, "item": updated})

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _load_request_body(self) -> dict[str, object]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
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
        rows.append(
            "\n".join(
                [
                    "<article style='border:1px solid #d9d9d9;border-radius:16px;padding:16px;margin:16px 0;'>",
                    f"<h2 style='margin:0 0 8px 0'>{artifact_label}</h2>",
                    f"<p><strong>Harness:</strong> {harness_label}</p>",
                    f"<p><strong>Changed fields:</strong> {changed_fields}</p>",
                    f"<p><strong>Recommendation:</strong> {recommendation_label}</p>",
                    "<form method='post' action='/approvals/"
                    f"{request_id}/decision' style='display:flex;gap:8px;flex-wrap:wrap;'>",
                    "<input type='hidden' name='scope' value='artifact'>",
                    "<input type='hidden' name='reason' value='approved in local approval center'>",
                    "<button name='action' value='allow'>Allow artifact</button>",
                    "<button name='action' value='block'>Keep blocked</button>",
                    "</form>",
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
