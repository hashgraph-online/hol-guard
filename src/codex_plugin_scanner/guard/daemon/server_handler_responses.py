"""Response headers, static assets, and route access policy."""

from __future__ import annotations

from . import server as _server


def _requires_header_token(path: str, path_parts: list[str]) -> bool:
    if path in {
        "/v1/cloud-review",
        "/v1/clients/attach",
        "/v1/clients/heartbeat",
        "/v1/sessions/start",
        "/v1/operations/start",
        "/v1/connect/requests",
        "/v1/connect/result",
        "/v1/operations/block",
        "/v1/policy/decisions",
        "/v1/policy/resolve",
        "/v1/policy/claim",
        "/v1/policy/cloud-exceptions",
        "/v1/policy/cloud-exception-requests",
        "/v1/policy/clear",
        "/v1/policy/sync",
        "/v1/requests/clear",
        *_server._REMOTE_REVIEW_POST_ROUTES,
        "/v1/settings",
        "/v1/settings/import",
        "/v1/settings/reset",
        "/v1/approval-gate/cooldown/revoke",
        "/v1/approval-gate/totp/enroll",
        "/v1/approval-gate/totp/verify",
        "/v1/approval-gate/totp/disable",
        "/v1/daemon/repair",
        "/v1/protection/repair",
        "/v1/insights/share",
        "/v1/cloud/connect",
        "/v1/notifications/setup",
        "/v1/update",
        "/v1/update/channel",
        "/v1/update/reconnect/prepare",
        "/v1/command-activity/feedback",
    }:
        return True
    if len(path_parts) >= 3 and path_parts[:2] == ["v1", "hooks"]:
        return True
    if len(path_parts) == 3 and path_parts[:2] == ["v1", "apps"] and path_parts[2] in _server._HEADLESS_APP_ACTIONS:
        return True
    if len(path_parts) >= 2 and path_parts[:2] == ["v1", "supply-chain"]:
        return True
    if len(path_parts) == 4 and path_parts[:3] == ["v1", "audit", "remediations"]:
        return True
    if len(path_parts) == 4 and path_parts[:2] == ["v1", "operations"] and path_parts[3] in {"items", "status"}:
        return True
    if (
        len(path_parts) == 4
        and path_parts[:2] == ["v1", "requests"]
        and path_parts[3] in {"approve", "block", "resume", "live-decision"}
    ):
        return True
    if (
        len(path_parts) == 4
        and path_parts[:2] == ["v1", "harnesses"]
        and path_parts[3]
        in {
            "install",
            "verify",
            "repair",
            "uninstall",
        }
    ):
        return True
    if len(path_parts) == 5 and path_parts[:2] == ["v1", "apps"] and path_parts[3:] == ["cloud", "start"]:
        return True
    if len(path_parts) == 3 and path_parts[0] == "approvals" and path_parts[2] == "decision":
        return True
    if len(path_parts) == 4 and path_parts[:2] == ["v1", "approvals"] and path_parts[3] == "decision":
        return True
    return len(path_parts) == 5 and path_parts[:3] == ["v1", "mcp-policy", "requests"] and path_parts[4] == "decision"


def _write_json(
    self: _server._GuardDaemonHandler,
    payload: dict[str, _server.Any],
    *,
    status: int = 200,
    extra_headers: dict[str, str] | None = None,
) -> None:
    body = _server.escape_json_for_html(_server.json.dumps(payload).encode("utf-8"))
    headers = {**dict(extra_headers or {}), "X-Content-Type-Options": "nosniff"}
    cors_headers = self._cors_headers_for_request(allow_methods="GET, POST, OPTIONS")
    if cors_headers is not None:
        headers = {**cors_headers, **headers}
    try:
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for key, value in self._validated_headers(headers).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)
    except _server._PEER_DISCONNECT_ERRORS:
        self.close_connection = True


def _write_empty(
    self: _server._GuardDaemonHandler,
    *,
    status: int,
    extra_headers: dict[str, str] | None = None,
) -> None:
    try:
        self.send_response(status)
        for key, value in self._validated_headers(extra_headers).items():
            self.send_header(key, value)
        self.end_headers()
    except _server._PEER_DISCONNECT_ERRORS:
        self.close_connection = True


def _validated_headers(extra_headers: dict[str, str] | None) -> dict[str, str]:
    allowed_headers = {
        "Access-Control-Allow-Origin",
        "Access-Control-Allow-Methods",
        "Access-Control-Allow-Headers",
        "Access-Control-Allow-Private-Network",
        "Cache-Control",
        "Expires",
        "Location",
        "Pragma",
        "Vary",
        "X-Content-Type-Options",
    }
    validated: dict[str, str] = {}
    for key, value in (extra_headers or {}).items():
        if key not in allowed_headers or not isinstance(value, str):
            continue
        if "\r" in value or "\n" in value:
            continue
        validated[key] = value
    return validated


def _write_static_asset(self: _server._GuardDaemonHandler, relative_path: str) -> None:
    target = (_server._STATIC_DIR / relative_path).resolve()
    if not target.is_file() or _server._STATIC_DIR.resolve() not in target.parents:
        self.send_response(404)
        self.end_headers()
        return
    body = target.read_bytes()
    content_type, _ = _server.mimetypes.guess_type(str(target))
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


def _write_dashboard_shell(self: _server._GuardDaemonHandler) -> None:
    if _server._INDEX_PATH.is_file() and _server._ENTRY_PATH.is_file():
        encoded = _server._INDEX_PATH.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("Content-Security-Policy", _server._DASHBOARD_CSP)
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(encoded)
        return
    self._write_json({"error": "dashboard_bundle_missing"}, status=503)


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
        "/settings",
        "/about",
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
