from __future__ import annotations

import hashlib
import json
import threading
from datetime import timedelta
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from device_support import response_error_code
from lab_common import atomic, decode_json_object, http_request, json_bytes

from codex_plugin_scanner.guard.mdm.cloud_control import (
    ENROLL_SCHEMA,
    ContractError,
    iso,
    public_pem,
    sign_proof,
    utcnow,
)


class DeviceBase:
    """Persistent identity, endpoint state, enrollment, and request proof."""

    def __init__(
        self,
        state: Path,
        cloud: str,
        workspace: str,
        device: str,
        generation: str,
        token: str,
        policy_path: Path,
    ) -> None:
        self.state = state
        self.cloud = cloud.rstrip("/")
        self.workspace = workspace
        self.device = device
        self.generation = generation
        self.token = token
        self.policy_path = policy_path
        state.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.faults: dict[str, object] = {
            "crashAfterWrite": False,
            "replayNext": False,
            "workspaceOverride": None,
            "holdOutbox": False,
            "clockOffsetSeconds": 0,
        }
        self.key = self._load_or_create_key()
        self.meta = self._load_json(
            "meta",
            {
                "requestSequence": 0,
                "healthSequence": 0,
                "revision": None,
                "policyHash": None,
                "etag": None,
                "enrolled": False,
                "lastSyncError": None,
                "completedJobs": {},
            },
        )
        self.outbox = self._load_json(
            "outbox",
            {"acks": [], "health": [], "results": [], "deadLetters": []},
        )
        self.proofs: dict[tuple[str, str, bytes], dict[str, str]] = {}
        self._validate_state_shape()

    @property
    def w(self) -> str:
        return self.workspace

    @property
    def d(self) -> str:
        return self.device

    @property
    def g(self) -> str:
        return self.generation

    @property
    def out(self) -> dict[str, Any]:
        return self.outbox

    def _now(self):
        offset = self.faults.get("clockOffsetSeconds", 0)
        seconds = offset if isinstance(offset, int) and not isinstance(offset, bool) else 0
        return utcnow() + timedelta(seconds=seconds)

    def _file(self, name: str) -> Path:
        return self.state / f"{name}.json"

    def _load_json(self, name: str, default: dict[str, object]) -> dict[str, Any]:
        path = self._file(name)
        if path.is_symlink():
            raise ContractError(f"device_{name}_symlink")
        if not path.exists():
            return json.loads(json.dumps(default))
        try:
            value = decode_json_object(path.read_bytes())
        except (OSError, ContractError) as error:
            raise ContractError(f"device_{name}_invalid") from error
        return value

    def _save(self, name: str, value: object) -> None:
        atomic(self._file(name), json_bytes(value))

    def _validate_state_shape(self) -> None:
        for key in ("requestSequence", "healthSequence"):
            value = self.meta.get(key)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ContractError("device_meta_invalid")
        for key in ("acks", "health", "results", "deadLetters"):
            if not isinstance(self.outbox.get(key), list):
                raise ContractError("device_outbox_invalid")
        if not isinstance(self.meta.get("completedJobs"), dict):
            raise ContractError("device_meta_invalid")

    def _load_or_create_key(self) -> ec.EllipticCurvePrivateKey:
        path = self.state / "device-key.pem"
        if path.is_symlink():
            raise ContractError("device_key_symlink")
        if path.exists():
            key = serialization.load_pem_private_key(path.read_bytes(), password=None)
            if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
                raise ContractError("device_key_invalid")
            return key
        key = ec.generate_private_key(ec.SECP256R1())
        atomic(
            path,
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )
        return key

    def enroll(self) -> None:
        if self.meta["enrolled"]:
            return
        public_key = public_pem(self.key.public_key())
        payload = {
            "schemaVersion": ENROLL_SCHEMA,
            "workspaceId": self.workspace,
            "deviceId": self.device,
            "installationGeneration": self.generation,
            "keyId": hashlib.sha256(public_key.encode("utf-8")).hexdigest()[:32],
            "publicKeyPem": public_key,
            "token": self.token,
        }
        status, _, data = http_request("POST", self.cloud + "/runtime/v1/enroll", payload)
        if status != 201 or not isinstance(data, dict):
            raise RuntimeError(f"enrollment_failed:{status}:{response_error_code(data)}")
        cloud_public_key = data.get("cloudPublicKeyPem")
        if not isinstance(cloud_public_key, str):
            raise RuntimeError("enrollment_missing_cloud_key")
        parsed = serialization.load_pem_public_key(cloud_public_key.encode("utf-8"))
        if not isinstance(parsed, rsa.RSAPublicKey):
            raise RuntimeError("enrollment_cloud_key_invalid")
        atomic(self.state / "cloud-key.pem", cloud_public_key.encode("utf-8"))
        self.meta["enrolled"] = True
        self._save("meta", self.meta)

    def request(
        self,
        method: str,
        path: str,
        payload: object | None = None,
        extra: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], object | None]:
        body = b"" if payload is None else json_bytes(payload)
        workspace_override = self.faults.get("workspaceOverride")
        workspace = workspace_override if isinstance(workspace_override, str) and workspace_override else self.workspace
        proof_key = (method, path, body)
        if self.faults.get("replayNext") is True and proof_key in self.proofs:
            headers = dict(self.proofs[proof_key])
            self.faults["replayNext"] = False
        else:
            self.meta["requestSequence"] += 1
            self._save("meta", self.meta)
            sequence = self.meta["requestSequence"]
            observed_at = iso(self._now())
            headers = {
                "x-hol-workspace-id": workspace,
                "x-hol-device-id": self.device,
                "x-hol-installation-generation": self.generation,
                "x-hol-request-sequence": str(sequence),
                "x-hol-request-time": observed_at,
                "x-hol-request-signature": sign_proof(
                    self.key,
                    method,
                    path,
                    body,
                    sequence,
                    observed_at,
                ),
            }
            self.proofs[proof_key] = dict(headers)
        headers.update(extra or {})
        return http_request(method, self.cloud + path, payload, headers)
