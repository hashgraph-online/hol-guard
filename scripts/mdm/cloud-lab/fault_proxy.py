#!/usr/bin/env python3
"""Deterministic HTTP fault proxy for the HOL Guard MDM Cloud integration lab."""

from __future__ import annotations

import argparse
import contextlib
import http.client
import os
import socket
import threading
import time
from collections import defaultdict, deque
from collections.abc import Mapping
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from lab_common import ADMIN_HEADER, MAX_BODY_BYTES, ContractError, decode_json_object, json_bytes

_MAX_HISTORY = 8


class FaultState:
    """Thread-safe persistent and one-shot network faults keyed by device id."""

    def __init__(self, admin_token: str) -> None:
        self.admin_token = admin_token
        self._lock = threading.RLock()
        self.partitioned: set[str] = set()
        self.delay_ms: dict[str, int] = {}
        self.status: dict[str, int] = {}
        self.status_by_path: dict[tuple[str, str], int] = {}
        self.drop_next: set[str] = set()
        self.drop_response_after_forward: set[str] = set()
        self.corrupt_next_configuration: set[str] = set()
        self.truncate_next: set[str] = set()
        self.malformed_json_next: set[str] = set()
        self.replay_previous_configuration: set[str] = set()
        self.strip_etag: set[str] = set()
        self.configuration_history: dict[
            str,
            deque[tuple[int, dict[str, str], bytes]],
        ] = defaultdict(lambda: deque(maxlen=_MAX_HISTORY))

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            return {
                "schemaVersion": "hol-guard-mdm-fault-state.v2",
                "partitionedDevices": sorted(self.partitioned),
                "delayMsByDevice": dict(sorted(self.delay_ms.items())),
                "statusByDevice": dict(sorted(self.status.items())),
                "statusByDeviceAndPath": {
                    f"{device}|{path}": status for (device, path), status in sorted(self.status_by_path.items())
                },
                "dropNextFor": sorted(self.drop_next),
                "dropResponseAfterForwardFor": sorted(self.drop_response_after_forward),
                "corruptNextConfigurationFor": sorted(self.corrupt_next_configuration),
                "truncateNextFor": sorted(self.truncate_next),
                "malformedJsonNextFor": sorted(self.malformed_json_next),
                "replayPreviousConfigurationFor": sorted(self.replay_previous_configuration),
                "stripEtagFor": sorted(self.strip_etag),
                "configurationHistoryDepth": {
                    key: len(value) for key, value in sorted(self.configuration_history.items())
                },
            }

    @staticmethod
    def _string_set(payload: Mapping[str, object], name: str) -> set[str]:
        value = payload.get(name, [])
        if not isinstance(value, list) or any(
            not isinstance(item, str) or not item or len(item) > 128 for item in value
        ):
            raise ContractError("fault_configuration_invalid")
        return set(value)

    @staticmethod
    def _int_map(
        payload: Mapping[str, object],
        name: str,
        minimum: int,
        maximum: int,
    ) -> dict[str, int]:
        value = payload.get(name, {})
        if not isinstance(value, dict):
            raise ContractError("fault_configuration_invalid")
        result: dict[str, int] = {}
        for key, item in value.items():
            if (
                not isinstance(key, str)
                or not key
                or len(key) > 260
                or not isinstance(item, int)
                or isinstance(item, bool)
                or item < minimum
                or item > maximum
            ):
                raise ContractError("fault_configuration_invalid")
            result[key] = item
        return result

    def configure(self, payload: Mapping[str, object]) -> dict[str, object]:
        expected = {
            "partitionedDevices",
            "delayMsByDevice",
            "statusByDevice",
            "statusByDeviceAndPath",
            "dropNextFor",
            "dropResponseAfterForwardFor",
            "corruptNextConfigurationFor",
            "truncateNextFor",
            "malformedJsonNextFor",
            "replayPreviousConfigurationFor",
            "stripEtagFor",
        }
        if set(payload) - expected:
            raise ContractError("fault_configuration_invalid")
        status_by_path_raw = self._int_map(
            payload,
            "statusByDeviceAndPath",
            400,
            599,
        )
        status_by_path: dict[tuple[str, str], int] = {}
        for key, value in status_by_path_raw.items():
            device, separator, path = key.partition("|")
            if not separator or not device or not path.startswith("/"):
                raise ContractError("fault_configuration_invalid")
            status_by_path[(device, path)] = value
        with self._lock:
            self.partitioned = self._string_set(payload, "partitionedDevices")
            self.delay_ms = self._int_map(payload, "delayMsByDevice", 0, 30_000)
            self.status = self._int_map(payload, "statusByDevice", 400, 599)
            self.status_by_path = status_by_path
            self.drop_next = self._string_set(payload, "dropNextFor")
            self.drop_response_after_forward = self._string_set(
                payload,
                "dropResponseAfterForwardFor",
            )
            self.corrupt_next_configuration = self._string_set(
                payload,
                "corruptNextConfigurationFor",
            )
            self.truncate_next = self._string_set(payload, "truncateNextFor")
            self.malformed_json_next = self._string_set(payload, "malformedJsonNextFor")
            self.replay_previous_configuration = self._string_set(
                payload,
                "replayPreviousConfigurationFor",
            )
            self.strip_etag = self._string_set(payload, "stripEtagFor")
        return self.snapshot()

    def reset(self) -> dict[str, object]:
        return self.configure({})

    def consume(self, collection: set[str], device_id: str) -> bool:
        with self._lock:
            if device_id not in collection:
                return False
            collection.remove(device_id)
            return True

    def remember_configuration(
        self,
        device_id: str,
        status: int,
        headers: dict[str, str],
        body: bytes,
    ) -> None:
        if status != 200:
            return
        with self._lock:
            history = self.configuration_history[device_id]
            identity = headers.get("etag", "") + body.decode("utf-8", "replace")
            if history and history[-1][1].get("x-hol-history-identity") == identity:
                return
            stored_headers = dict(headers)
            stored_headers["x-hol-history-identity"] = identity
            history.append((status, stored_headers, body))

    def previous_configuration(
        self,
        device_id: str,
    ) -> tuple[int, dict[str, str], bytes] | None:
        with self._lock:
            history = self.configuration_history.get(device_id)
            if not history:
                return None
            candidate = history[-2] if len(history) >= 2 else history[-1]
            status, headers, body = candidate
            return (
                status,
                {key: value for key, value in headers.items() if key != "x-hol-history-identity"},
                body,
            )


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "HOLGuardMdmFaultProxy/2"

    @property
    def app(self) -> FaultProxyServer:
        return self.server  # type: ignore[return-value]

    def log_message(self, format_string: str, *args: object) -> None:
        if self.app.verbose:
            super().log_message(format_string, *args)

    def _read_body(self) -> bytes:
        raw_length = self.headers.get("content-length", "0")
        try:
            length = int(raw_length)
        except ValueError as error:
            raise ContractError("invalid_content_length") from error
        if length < 0 or length > MAX_BODY_BYTES:
            raise ContractError("request_too_large", 413)
        return self.rfile.read(length)

    def _reply(
        self,
        status: int,
        body: bytes,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        excluded = {"content-length", "connection", "transfer-encoding"}
        for key, value in (headers or {}).items():
            if key.lower() not in excluded:
                self.send_header(key, value)
        self.send_header("content-length", str(len(body)))
        self.send_header("connection", "close")
        self.end_headers()
        if body:
            self.wfile.write(body)
        self.close_connection = True

    def _json(self, status: int, payload: object) -> None:
        self._reply(
            status,
            json_bytes(payload),
            {"content-type": "application/json", "cache-control": "no-store"},
        )

    def _drop_connection(self) -> None:
        self.close_connection = True
        with contextlib.suppress(OSError):
            self.connection.shutdown(socket.SHUT_RDWR)
        self.connection.close()

    def _control(self) -> bool:
        path = urlsplit(self.path).path
        if path == "/healthz" and self.command == "GET":
            self._json(
                200,
                {
                    "healthy": True,
                    "schemaVersion": "hol-guard-mdm-fault-proxy-healthz.v1",
                },
            )
            return True
        if path != "/__faults":
            return False
        if self.headers.get(ADMIN_HEADER) != self.app.state.admin_token:
            self._json(401, {"error": "fault_admin_denied"})
            return True
        try:
            if self.command == "GET":
                self._json(200, self.app.state.snapshot())
                return True
            if self.command == "DELETE":
                self._json(200, self.app.state.reset())
                return True
            if self.command == "POST":
                self._json(200, self.app.state.configure(decode_json_object(self._read_body())))
                return True
            self._json(405, {"error": "method_not_allowed"})
            return True
        except ContractError as error:
            self._json(error.status, {"error": error.code})
            return True

    def _forward(self) -> None:
        if self._control():
            return
        try:
            body = self._read_body()
        except ContractError as error:
            self._json(error.status, {"error": error.code})
            return
        path = urlsplit(self.path).path
        device_id = self.headers.get("x-hol-device-id", "anonymous")
        state = self.app.state
        if device_id in state.partitioned:
            self._json(503, {"error": "fault_partitioned"})
            return
        if state.consume(state.drop_next, device_id):
            self._drop_connection()
            return
        delay_ms = state.delay_ms.get(device_id, 0)
        if delay_ms:
            time.sleep(delay_ms / 1_000)
        forced_status = state.status_by_path.get((device_id, path), state.status.get(device_id))
        if forced_status is not None:
            headers = {"retry-after": "1"} if forced_status in {429, 503} else None
            self._reply(
                forced_status,
                json_bytes({"error": "fault_forced_status", "status": forced_status}),
                {"content-type": "application/json", **(headers or {})},
            )
            return

        upstream = urlsplit(self.app.upstream)
        connection = http.client.HTTPConnection(upstream.hostname, upstream.port or 80, timeout=20)
        forwarded_headers = {
            key: value
            for key, value in self.headers.items()
            if key.lower() not in {"host", "content-length", "connection", "transfer-encoding"}
        }
        forwarded_headers["host"] = upstream.netloc
        try:
            connection.request(
                self.command,
                self.path,
                body=body if self.command != "GET" else None,
                headers=forwarded_headers,
            )
            response = connection.getresponse()
            response_body = response.read(MAX_BODY_BYTES + 1)
            if len(response_body) > MAX_BODY_BYTES:
                self._json(502, {"error": "fault_upstream_response_too_large"})
                return
            response_headers = {key.lower(): value for key, value in response.getheaders()}
            status = response.status
        except (OSError, http.client.HTTPException) as error:
            self._json(502, {"error": "fault_upstream_unavailable", "detail": type(error).__name__})
            return
        finally:
            connection.close()

        if state.consume(state.drop_response_after_forward, device_id):
            self._drop_connection()
            return

        if path == "/runtime/v1/configuration":
            state.remember_configuration(device_id, status, response_headers, response_body)
            if state.consume(state.replay_previous_configuration, device_id):
                previous = state.previous_configuration(device_id)
                if previous is not None:
                    status, response_headers, response_body = previous
            if state.consume(state.corrupt_next_configuration, device_id) and response_body:
                try:
                    payload = decode_json_object(response_body)
                    payload["policyHash"] = "0" * 64
                    response_body = json_bytes(payload)
                except ContractError:
                    response_body = b'{"schemaVersion":"corrupt"}'
            if device_id in state.strip_etag:
                response_headers.pop("etag", None)

        if state.consume(state.malformed_json_next, device_id):
            response_body = b'{"unterminated":'
            response_headers["content-type"] = "application/json"
        elif state.consume(state.truncate_next, device_id) and response_body:
            response_body = response_body[: max(1, len(response_body) // 2)]
        self._reply(status, response_body, response_headers)

    def do_GET(self) -> None:
        self._forward()

    def do_POST(self) -> None:
        self._forward()

    def do_DELETE(self) -> None:
        self._forward()


class FaultProxyServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        address: tuple[str, int],
        *,
        upstream: str,
        state: FaultState,
        verbose: bool,
    ) -> None:
        super().__init__(address, ProxyHandler)
        self.upstream = upstream.rstrip("/")
        self.state = state
        self.verbose = verbose


def _required_admin_token() -> str:
    token = os.environ.get("HOL_MDM_LAB_ADMIN_TOKEN", "").strip()
    if not token:
        raise RuntimeError("HOL_MDM_LAB_ADMIN_TOKEN is required")
    return token


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument(
        "--upstream",
        default=os.environ.get("HOL_MDM_UPSTREAM_URL", "http://cloud:8090"),
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    state = FaultState(_required_admin_token())
    server = FaultProxyServer(
        (args.host, args.port),
        upstream=args.upstream,
        state=state,
        verbose=args.verbose,
    )
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
