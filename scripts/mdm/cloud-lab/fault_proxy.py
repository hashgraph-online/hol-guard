#!/usr/bin/env python3
"""Deterministic HTTP fault proxy for the HOL Guard MDM Cloud integration lab."""

from __future__ import annotations

import argparse
import http.client
import json
import os
import socket
import threading
import time
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Mapping
from urllib.parse import urlsplit

_ADMIN_HEADER = "x-hol-mdm-lab-admin"
_MAX_BODY = 1024 * 1024
_MAX_HISTORY = 4


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


class FaultState:
    """Thread-safe one-shot and persistent network faults keyed by device id."""

    def __init__(self, admin_token: str) -> None:
        self.admin_token = admin_token
        self._lock = threading.RLock()
        self.partitioned: set[str] = set()
        self.delay_ms: dict[str, int] = {}
        self.status: dict[str, int] = {}
        self.drop_next: set[str] = set()
        self.corrupt_next_configuration: set[str] = set()
        self.truncate_next: set[str] = set()
        self.replay_previous_configuration: set[str] = set()
        self.strip_etag: set[str] = set()
        self.configuration_history: dict[str, deque[tuple[int, dict[str, str], bytes]]] = defaultdict(
            lambda: deque(maxlen=_MAX_HISTORY)
        )

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            return {
                "schemaVersion": "hol-guard-mdm-fault-state.v1",
                "partitionedDevices": sorted(self.partitioned),
                "delayMsByDevice": dict(sorted(self.delay_ms.items())),
                "statusByDevice": dict(sorted(self.status.items())),
                "dropNextFor": sorted(self.drop_next),
                "corruptNextConfigurationFor": sorted(self.corrupt_next_configuration),
                "truncateNextFor": sorted(self.truncate_next),
                "replayPreviousConfigurationFor": sorted(self.replay_previous_configuration),
                "stripEtagFor": sorted(self.strip_etag),
                "configurationHistoryDepth": {
                    key: len(value) for key, value in sorted(self.configuration_history.items())
                },
            }

    def configure(self, payload: Mapping[str, object]) -> dict[str, object]:
        expected = {
            "partitionedDevices",
            "delayMsByDevice",
            "statusByDevice",
            "dropNextFor",
            "corruptNextConfigurationFor",
            "truncateNextFor",
            "replayPreviousConfigurationFor",
            "stripEtagFor",
        }
        if set(payload) - expected:
            raise ValueError("unknown fault field")

        def string_set(name: str) -> set[str]:
            value = payload.get(name, [])
            if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
                raise ValueError(f"invalid {name}")
            return set(value)

        def int_map(name: str, minimum: int, maximum: int) -> dict[str, int]:
            value = payload.get(name, {})
            if not isinstance(value, dict):
                raise ValueError(f"invalid {name}")
            result: dict[str, int] = {}
            for key, item in value.items():
                if not isinstance(key, str) or not key or not isinstance(item, int) or isinstance(item, bool):
                    raise ValueError(f"invalid {name}")
                if item < minimum or item > maximum:
                    raise ValueError(f"invalid {name}")
                result[key] = item
            return result

        with self._lock:
            self.partitioned = string_set("partitionedDevices")
            self.delay_ms = int_map("delayMsByDevice", 0, 30_000)
            self.status = int_map("statusByDevice", 400, 599)
            self.drop_next = string_set("dropNextFor")
            self.corrupt_next_configuration = string_set("corruptNextConfigurationFor")
            self.truncate_next = string_set("truncateNextFor")
            self.replay_previous_configuration = string_set("replayPreviousConfigurationFor")
            self.strip_etag = string_set("stripEtagFor")
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
            stored = dict(headers)
            stored["x-hol-history-identity"] = identity
            history.append((status, stored, body))

    def previous_configuration(self, device_id: str) -> tuple[int, dict[str, str], bytes] | None:
        with self._lock:
            history = self.configuration_history.get(device_id)
            if not history:
                return None
            candidate = history[-2] if len(history) >= 2 else history[-1]
            status, headers, body = candidate
            clean = {key: value for key, value in headers.items() if key != "x-hol-history-identity"}
            return status, clean, body


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "HOLGuardMdmFaultProxy/1"

    @property
    def app(self) -> "FaultProxyServer":
        return self.server  # type: ignore[return-value]

    def log_message(self, format: str, *args: object) -> None:
        if self.app.verbose:
            super().log_message(format, *args)

    def _read_body(self) -> bytes:
        try:
            length = int(self.headers.get("content-length", "0"))
        except ValueError as error:
            raise ValueError("invalid content length") from error
        if length < 0 or length > _MAX_BODY:
            raise ValueError("request too large")
        return self.rfile.read(length)

    def _reply(self, status: int, body: bytes, headers: Mapping[str, str] | None = None) -> None:
        self.send_response(status)
        emitted = {"content-length", "connection", "transfer-encoding"}
        for key, value in (headers or {}).items():
            if key.lower() in emitted:
                continue
            self.send_header(key, value)
        self.send_header("content-length", str(len(body)))
        self.send_header("connection", "close")
        self.end_headers()
        if body:
            self.wfile.write(body)
        self.close_connection = True

    def _json(self, status: int, payload: object) -> None:
        self._reply(status, _json_bytes(payload), {"content-type": "application/json", "cache-control": "no-store"})

    def _control(self) -> bool:
        parsed = urlsplit(self.path)
        if parsed.path == "/healthz" and self.command == "GET":
            self._json(200, {"healthy": True, "schemaVersion": "hol-guard-mdm-fault-proxy-healthz.v1"})
            return True
        if parsed.path != "/__faults":
            return False
        if self.headers.get(_ADMIN_HEADER) != self.app.state.admin_token:
            self._json(401, {"error": "fault_admin_denied"})
            return True
        if self.command == "GET":
            self._json(200, self.app.state.snapshot())
            return True
        if self.command == "DELETE":
            self._json(200, self.app.state.reset())
            return True
        if self.command == "POST":
            try:
                payload = json.loads(self._read_body() or b"{}")
                if not isinstance(payload, dict):
                    raise ValueError("invalid payload")
                self._json(200, self.app.state.configure(payload))
            except (ValueError, json.JSONDecodeError) as error:
                self._json(400, {"error": "fault_configuration_invalid", "detail": str(error)[:160]})
            return True
        self._json(405, {"error": "method_not_allowed"})
        return True

    def _forward(self) -> None:
        if self._control():
            return
        body = self._read_body()
        device_id = self.headers.get("x-hol-device-id", "anonymous")
        state = self.app.state

        if device_id in state.partitioned:
            self._json(503, {"error": "fault_partitioned"})
            return
        if state.consume(state.drop_next, device_id):
            self.close_connection = True
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.connection.close()
            return
        delay_ms = state.delay_ms.get(device_id, 0)
        if delay_ms:
            time.sleep(delay_ms / 1000)
        forced_status = state.status.get(device_id)
        if forced_status is not None:
            self._json(forced_status, {"error": "fault_forced_status", "status": forced_status})
            return

        parsed = urlsplit(self.app.upstream)
        connection = http.client.HTTPConnection(parsed.hostname, parsed.port or 80, timeout=20)
        headers = {
            key: value
            for key, value in self.headers.items()
            if key.lower() not in {"host", "content-length", "connection", "transfer-encoding"}
        }
        headers["host"] = parsed.netloc
        try:
            connection.request(self.command, self.path, body=body if self.command != "GET" else None, headers=headers)
            response = connection.getresponse()
            response_body = response.read(_MAX_BODY + 1)
            if len(response_body) > _MAX_BODY:
                self._json(502, {"error": "fault_upstream_response_too_large"})
                return
            response_headers = {key.lower(): value for key, value in response.getheaders()}
            status = response.status
        except (OSError, http.client.HTTPException) as error:
            self._json(502, {"error": "fault_upstream_unavailable", "detail": type(error).__name__})
            return
        finally:
            connection.close()

        is_configuration = urlsplit(self.path).path == "/runtime/v1/configuration"
        if is_configuration:
            state.remember_configuration(device_id, status, response_headers, response_body)
            if state.consume(state.replay_previous_configuration, device_id):
                previous = state.previous_configuration(device_id)
                if previous is not None:
                    status, response_headers, response_body = previous
            if state.consume(state.corrupt_next_configuration, device_id) and response_body:
                try:
                    payload = json.loads(response_body)
                    if isinstance(payload, dict):
                        payload["policyHash"] = "0" * 64
                        response_body = _json_bytes(payload)
                except json.JSONDecodeError:
                    response_body = b'{"schemaVersion":"corrupt"}'
            if device_id in state.strip_etag:
                response_headers.pop("etag", None)

        if state.consume(state.truncate_next, device_id) and response_body:
            response_body = response_body[: max(1, len(response_body) // 2)]
        self._reply(status, response_body, response_headers)

    def do_GET(self) -> None:  # noqa: N802
        self._forward()

    def do_POST(self) -> None:  # noqa: N802
        self._forward()

    def do_DELETE(self) -> None:  # noqa: N802
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--upstream", default=os.environ.get("HOL_MDM_UPSTREAM_URL", "http://cloud:8090"))
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    state = FaultState(os.environ.get("HOL_MDM_LAB_ADMIN_TOKEN", "hol-guard-mdm-lab-admin"))
    server = FaultProxyServer((args.host, args.port), upstream=args.upstream, state=state, verbose=args.verbose)
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
