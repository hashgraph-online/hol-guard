from __future__ import annotations

import json
from collections.abc import Mapping
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from lab_store import Store
from lab_support import (
    ADMIN_HEADER,
    MAX_BODY_BYTES,
    _safe_identifier,
    decode_json_object,
    json_bytes,
    read_json,
)

from codex_plugin_scanner.guard.mdm.cloud_control import ContractError


class CloudHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "HOLGuardMdmCloudLab/2"

    @property
    def store(self) -> Store:
        return self.server.store  # type: ignore[attr-defined,return-value]

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def reply(
        self,
        status: int,
        payload: object | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        body = b"" if payload is None else json_bytes(payload)
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("content-type", "application/json")
        self.send_header("cache-control", "private, no-store")
        self.send_header("content-length", str(len(body)))
        self.send_header("connection", "close")
        self.end_headers()
        if body:
            self.wfile.write(body)
        self.close_connection = True

    def _handle_admin(
        self,
        path: str,
        query_string: str,
    ) -> None:
        if self.headers.get(ADMIN_HEADER) != self.server.admin:  # type: ignore[attr-defined]
            raise ContractError("admin_denied", 401)
        payload = read_json(self) if self.command == "POST" else {}
        if path == "/admin/policies" and self.command == "POST":
            self.reply(201, self.store.publish(payload))
            return
        if path == "/admin/remediations" and self.command == "POST":
            created, job = self.store.create_job(payload)
            self.reply(201 if created else 200, job)
            return
        if path == "/admin/state" and self.command == "GET":
            query = parse_qs(query_string, strict_parsing=False)
            workspace_values = query.get("workspaceId", [])
            workspace_id = _safe_identifier(workspace_values[0], "workspace") if workspace_values else None
            self.reply(200, self.store.state(workspace_id))
            return
        raise ContractError("not_found", 404)

    def _runtime_context(
        self,
        path: str,
    ) -> tuple[str, str, str, bytes]:
        raw_length = self.headers.get("content-length", "0")
        try:
            content_length = int(raw_length)
        except ValueError as error:
            raise ContractError("invalid_content_length") from error
        if content_length < 0 or content_length > MAX_BODY_BYTES:
            raise ContractError("request_too_large", 413)
        body = b"" if self.command == "GET" else self.rfile.read(content_length)
        workspace, device, generation = self.store.authenticate(
            self.headers,
            self.command,
            path,
            body,
        )
        return workspace, device, generation, body

    def _handle_runtime(self, path: str) -> None:
        if path == "/runtime/v1/enroll" and self.command == "POST":
            self.reply(201, self.store.enroll(read_json(self)))
            return
        workspace, device, generation, body = self._runtime_context(path)
        if path == "/runtime/v1/configuration" and self.command == "GET":
            status, response_headers, payload = self.store.configuration(
                workspace,
                device,
                generation,
                self.headers.get("if-none-match"),
            )
            self.reply(status, payload, response_headers)
            return
        if path == "/runtime/v1/remediations" and self.command == "GET":
            jobs = self.store.jobs(workspace, device, generation)
            self.reply(200, {"jobs": jobs})
            return
        payload = decode_json_object(body)
        if path == "/runtime/v1/acknowledgements" and self.command == "POST":
            result = self.store.save_acknowledgement(
                workspace,
                device,
                generation,
                payload,
            )
            self.reply(202, result)
            return
        if path == "/runtime/v1/health" and self.command == "POST":
            result = self.store.save_health(
                workspace,
                device,
                generation,
                payload,
            )
            self.reply(202, result)
            return
        if path == "/runtime/v1/remediation-results" and self.command == "POST":
            result = self.store.save_remediation_result(
                workspace,
                device,
                generation,
                payload,
            )
            self.reply(202, result)
            return
        raise ContractError("not_found", 404)

    def handle_all(self) -> None:
        parsed_url = urlsplit(self.path)
        path = parsed_url.path
        try:
            if path == "/healthz" and self.command == "GET":
                self.reply(
                    200,
                    {
                        "healthy": True,
                        "schemaVersion": "hol-guard-mdm-cloud-healthz.v1",
                    },
                )
            elif path.startswith("/admin/"):
                self._handle_admin(path, parsed_url.query)
            else:
                self._handle_runtime(path)
        except ContractError as error:
            self.reply(error.status, {"error": error.code})
        except (
            ValueError,
            TypeError,
            OSError,
            json.JSONDecodeError,
        ) as error:
            self.reply(
                400,
                {
                    "error": "invalid_request",
                    "detail": type(error).__name__,
                },
            )

    def do_GET(self) -> None:
        self.handle_all()

    def do_POST(self) -> None:
        self.handle_all()


class CloudServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        address: tuple[str, int],
        store: Store,
        admin: str,
    ) -> None:
        super().__init__(address, CloudHandler)
        self.store = store
        self.admin = admin
