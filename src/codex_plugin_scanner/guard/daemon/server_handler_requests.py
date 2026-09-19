"""HTTP request loading and auxiliary routes."""

from __future__ import annotations

from . import server as _server


def do_OPTIONS(self: _server._GuardDaemonHandler) -> None:  # noqa: N802 - HTTP dispatch contract
    origin = self._normalize_origin(self.headers.get("Origin"))
    if origin is None:
        self._write_empty(status=400)
        return
    headers = self._cors_headers_for_request(
        allow_methods="GET, POST, DELETE, OPTIONS",
        allow_headers=("Authorization, Content-Type, Last-Event-ID, X-Guard-Dashboard-Session, X-Guard-Token"),
    )
    if headers is None:
        self._write_empty(status=403)
        return
    self._write_empty(status=200, extra_headers=headers)


def do_DELETE(self: _server._GuardDaemonHandler) -> None:  # noqa: N802 - HTTP dispatch contract
    parsed = _server.urlparse(self.path)
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
    body = self._read_delete_body() if parsed.path == "/v1/command-activity" else None
    store = self.server.store  # type: ignore[attr-defined]
    if parsed.path == "/v1/command-activity":
        if body is None:
            self._write_json({"error": "invalid_request"}, status=400)
            return
        if body.get("confirm") != "clear-command-activity":
            self._write_json(
                {"error": "confirmation_required", "confirm": "clear-command-activity"},
                status=400,
            )
            return
        try:
            _server.require_high_risk(
                store.guard_home,
                purpose="evidence_clear",
                approval_gate_input=_server.approval_gate_input_from_mapping(body),
            )
        except _server.ApprovalGateError as error:
            self._write_approval_gate_error(error)
            return
        self._write_json(store.clear_command_activity_evidence())
        return
    if parsed.path == "/v1/evidence":
        with store._connect() as conn:
            deleted = _server.clear_evidence(conn)
        self._write_json({"deleted": deleted})
        return
    if parsed.path == "/v1/read-state":
        body = self._read_delete_body()
        request_id = body.get("request_id") if body else None
        if isinstance(request_id, str):
            store.mark_request_unread(request_id)
        elif body and body.get("clear_all"):
            store.clear_read_state()
        self._write_json({"ok": True})
        return
    self._write_json({"error": "not_found"}, status=404)


def log_message(self: _server._GuardDaemonHandler, format: str, *args: object) -> None:  # noqa: A002
    return


def _local_queue_url(self: _server._GuardDaemonHandler) -> str:
    host = self._daemon_server().daemon_host()
    port = self._daemon_server().daemon_port()
    return _server._build_local_url(host, port, "/#/inbox")


def _load_request_body(self: _server._GuardDaemonHandler) -> tuple[dict[str, object], str | None]:
    if self.headers.get("Transfer-Encoding") is not None:
        return {}, "unsupported_transfer_encoding"
    content_lengths = self.headers.get_all("Content-Length", [])
    if len(content_lengths) > 1:
        return {}, "invalid_content_length"
    try:
        length = int(content_lengths[0]) if content_lengths else 0
    except ValueError:
        return {}, "invalid_content_length"
    if length < 0:
        return {}, "invalid_content_length"
    if length == 0:
        return {}, None
    if length > self._MAX_BODY_BYTES:
        return {}, "request_body_too_large"
    raw_body, body_error = self._read_request_body(length)
    if body_error is not None:
        return {}, body_error
    try:
        decoded_body = raw_body.decode("utf-8")
    except UnicodeDecodeError:
        return {}, "invalid_request_body"
    content_type = self.headers.get("Content-Type", "")
    if "application/json" in content_type:
        try:
            payload = _server.json.loads(decoded_body)
        except _server.json.JSONDecodeError:
            return {}, "invalid_request_body"
        return (payload if isinstance(payload, dict) else {}), None
    form_payload = _server.parse_qs(decoded_body)
    return {key: values[-1] for key, values in form_payload.items() if values}, None


def _read_request_body(self: _server._GuardDaemonHandler, length: int) -> tuple[bytes, str | None]:
    deadline = _server.time.monotonic() + _server._DAEMON_REQUEST_READ_TIMEOUT_SECONDS
    chunks: list[bytes] = []
    remaining = length
    while remaining > 0:
        timeout = deadline - _server.time.monotonic()
        if timeout <= 0:
            return b"", "request_body_timeout"
        with _server.suppress(OSError):
            self.connection.settimeout(timeout)
        try:
            chunk = self.rfile.read1(min(remaining, 64 * 1024))
        except TimeoutError:
            return b"", "request_body_timeout"
        except OSError:
            return b"", "incomplete_request_body"
        if not chunk:
            return b"", "incomplete_request_body"
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks), None
