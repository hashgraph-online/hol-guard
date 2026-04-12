"""Local Guard daemon helpers."""

from __future__ import annotations

import json
import mimetypes
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from ..approvals import apply_approval_resolution
from ..models import DECISION_SCOPE_VALUES, GUARD_ACTION_VALUES
from ..store import GuardStore
from .manager import clear_guard_daemon_state, write_guard_daemon_state


class _GuardDaemonHttpServer(ThreadingHTTPServer):
    store: GuardStore


_STATIC_DIR = Path(__file__).with_name("static")
_INDEX_PATH = _STATIC_DIR / "index.html"
_ENTRY_PATH = _STATIC_DIR / "assets" / "guard-dashboard.js"
_ROOT_STATIC_FILES = {
    "/favicon.ico",
    "/favicon-16x16.png",
    "/favicon-32x32.png",
}


class _GuardDaemonHandler(BaseHTTPRequestHandler):
    _MAX_BODY_BYTES = 1_000_000

    def do_GET(self) -> None:
        store = self.server.store  # type: ignore[attr-defined]
        parsed = urlparse(self.path)
        path_parts = [part for part in parsed.path.split("/") if part]
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
        if parsed.path == "/receipts":
            self._write_json({"items": store.list_receipts(limit=200)})
            return
        if self._is_dashboard_route(parsed.path):
            self._write_dashboard_shell()
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self) -> None:
        if not self._origin_is_allowed():
            self._write_json({"error": "forbidden_origin"}, status=403)
            return
        parsed = urlparse(self.path)
        payload, body_error = self._load_request_body()
        if body_error is not None:
            self._write_json({"error": body_error}, status=400)
            return
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
        self._write_json({"resolved": True, "item": updated})

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

    def _write_json(self, payload: dict[str, Any], *, status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

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
        self.end_headers()
        self.wfile.write(body)

    def _write_dashboard_shell(self) -> None:
        if _INDEX_PATH.is_file() and _ENTRY_PATH.is_file():
            self._write_static_asset("index.html")
            return
        self._write_json({"error": "dashboard_bundle_missing"}, status=503)

    @staticmethod
    def _is_dashboard_route(path: str) -> bool:
        if path in {"/", "/requests", "/approvals"}:
            return True
        if path.startswith("/requests/"):
            return True
        return path.startswith("/approvals/") and not path.endswith("/decision")


class GuardDaemonServer:
    """Small local daemon for health, receipts, and approval-center introspection."""

    def __init__(self, store: GuardStore, host: str = "127.0.0.1", port: int = 0) -> None:
        _validate_dashboard_bundle()
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


def _now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def _validate_dashboard_bundle() -> None:
    if not _INDEX_PATH.is_file() or not _ENTRY_PATH.is_file():
        raise RuntimeError(
            "Guard dashboard bundle is missing. Run `pnpm install && pnpm run build` in the dashboard directory."
        )
