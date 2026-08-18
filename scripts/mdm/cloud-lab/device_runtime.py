#!/usr/bin/env python3
"""Independent durable HOL Guard device runtime for the MDM integration lab."""

from __future__ import annotations

import argparse
import hashlib
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from device_agent import Device
from lab_common import json_bytes, read_json

from codex_plugin_scanner.guard.mdm.cloud_control import ContractError, public_pem


class DeviceHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "HOLGuardMdmDeviceLab/2"

    @property
    def device_runtime(self) -> Device:
        return self.server.device  # type: ignore[attr-defined,return-value]

    @property
    def device(self) -> Device:
        return self.device_runtime

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def reply(self, status: int, payload: object) -> None:
        body = json_bytes(payload)
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("cache-control", "private, no-store")
        self.send_header("content-length", str(len(body)))
        self.send_header("connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self.reply(200, {"healthy": True, "schemaVersion": "hol-guard-mdm-device-healthz.v1"})
            return
        if self.path == "/state":
            self.reply(200, self.device_runtime.view())
            return
        if self.path == "/identity":
            public_key = public_pem(self.device_runtime.key.public_key())
            self.reply(
                200,
                {
                    "schemaVersion": "hol-guard-mdm-device-identity.v1",
                    "workspaceId": self.device_runtime.workspace,
                    "deviceId": self.device_runtime.device,
                    "installationGeneration": self.device_runtime.generation,
                    "keyId": hashlib.sha256(public_key.encode("utf-8")).hexdigest()[:32],
                    "publicKeyPem": public_key,
                },
            )
            return
        if self.path == "/sync":
            try:
                self.reply(200, self.device_runtime.sync())
            except Exception as error:
                self.reply(500, {"error": str(error)[:160], **self.device_runtime.view()})
            return
        self.reply(404, {"error": "not_found"})

    def do_POST(self) -> None:
        if self.path != "/fault":
            self.reply(404, {"error": "not_found"})
            return
        try:
            payload = read_json(self)
            self.device_runtime.apply_fault(payload)
            self.reply(200, {"accepted": True, "state": self.device_runtime.view()})
        except ContractError as error:
            self.reply(error.status, {"error": error.code})


class DeviceServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], device: Device) -> None:
        super().__init__(address, DeviceHandler)
        self.device = device


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8070)
    args = parser.parse_args()
    device = Device(
        Path(os.environ["HOL_MDM_STATE_DIR"]),
        os.environ["HOL_MDM_CLOUD_URL"],
        os.environ["HOL_MDM_WORKSPACE_ID"],
        os.environ["HOL_MDM_DEVICE_ID"],
        os.environ["HOL_MDM_INSTALLATION_GENERATION"],
        os.environ["HOL_MDM_ENROLLMENT_TOKEN"],
        Path(os.environ["HOL_MDM_POLICY_PATH"]),
    )
    server = DeviceServer((args.host, args.port), device)
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
