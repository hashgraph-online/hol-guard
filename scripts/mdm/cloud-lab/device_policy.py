from __future__ import annotations

import os
import stat
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from device_support import response_error_code
from lab_common import atomic, decode_json_object, json_bytes

from codex_plugin_scanner.guard.mdm.cloud_control import (
    ACK_SCHEMA,
    HEALTH_SCHEMA,
    ContractError,
    iso,
    policy_hash,
    verify_config,
)
from codex_plugin_scanner.guard.mdm.policy import parse_managed_policy


class DevicePolicyMixin:
    """No-follow policy application, integrity evidence, recovery, and sync."""

    def _read_policy_object(self) -> dict[str, object]:
        if self.policy_path.is_symlink():
            raise ContractError("managed_policy_symlink")
        if not self.policy_path.exists():
            raise ContractError("managed_policy_missing")
        metadata = self.policy_path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise ContractError("managed_policy_type_invalid")
        if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022:
            raise ContractError("managed_policy_permissions_invalid")
        policy = decode_json_object(self.policy_path.read_bytes())
        parse_managed_policy(policy)
        return policy

    def policy_integrity(self) -> dict[str, object]:
        try:
            policy = self._read_policy_object()
        except ContractError as error:
            state = "tampered" if error.code not in {"managed_policy_missing"} else "missing"
            return {"state": state, "reason": error.code, "hash": None}
        current_hash = policy_hash(policy)
        expected_hash = self.meta.get("policyHash")
        if expected_hash is not None and current_hash != expected_hash:
            return {"state": "tampered", "reason": "managed_policy_hash_mismatch", "hash": current_hash}
        return {"state": "healthy", "reason": "managed_policy_valid", "hash": current_hash}

    def recover(self) -> None:
        pending = self._load_json("pending", {})
        if not pending:
            return
        required = {"revision", "policyHash", "etag", "ack"}
        if set(pending) != required:
            raise RuntimeError("pending_checkpoint_invalid")
        policy = self._read_policy_object()
        if policy_hash(policy) != pending["policyHash"]:
            raise RuntimeError("pending_policy_mismatch")
        self.meta.update(
            {
                "revision": pending["revision"],
                "policyHash": pending["policyHash"],
                "etag": pending["etag"],
            }
        )
        self._save("meta", self.meta)
        self._queue("acks", pending["ack"])
        self._file("pending").unlink(missing_ok=True)

    def _apply_configuration(
        self,
        envelope: object,
        etag: str | None,
    ) -> int:
        if not etag:
            raise ContractError("configuration_etag_missing")
        cloud_key_path = self.state / "cloud-key.pem"
        if cloud_key_path.is_symlink() or not cloud_key_path.exists():
            raise ContractError("cloud_key_missing")
        cloud_key = serialization.load_pem_public_key(cloud_key_path.read_bytes())
        if not isinstance(cloud_key, rsa.RSAPublicKey):
            raise ContractError("cloud_key_invalid")
        verified = verify_config(
            envelope,
            cloud_key,
            workspace=self.workspace,
            device=self.device,
            generation=self.generation,
            current_revision=self.meta["revision"],
            current_hash=self.meta["policyHash"],
            now=self._now(),
        )
        policy = verified["policy"]
        parse_managed_policy(policy)
        acknowledgement = {
            "schemaVersion": ACK_SCHEMA,
            "workspaceId": self.workspace,
            "deviceId": self.device,
            "installationGeneration": self.generation,
            "revision": verified["revision"],
            "policyHash": verified["policyHash"],
            "status": "applied",
            "reasonCode": None,
            "observedAt": iso(self._now()),
            "requestId": "ack-" + uuid.uuid4().hex,
        }
        self._save(
            "pending",
            {
                "revision": verified["revision"],
                "policyHash": verified["policyHash"],
                "etag": etag,
                "ack": acknowledgement,
            },
        )
        if self.policy_path.is_symlink():
            raise ContractError("managed_policy_symlink")
        atomic(self.policy_path, json_bytes(policy))
        atomic(self.state / "last-good-policy.json", json_bytes(policy))
        if self.faults.get("crashAfterWrite") is True:
            self.faults["crashAfterWrite"] = False
            raise RuntimeError("fault_crash_after_write")
        self.recover()
        return int(verified["revision"])

    def _queue_health(self, sync_error: str | None) -> None:
        integrity = self.policy_integrity()
        self.meta["healthSequence"] += 1
        healthy = sync_error is None and integrity["state"] == "healthy"
        health = {
            "schemaVersion": HEALTH_SCHEMA,
            "workspaceId": self.workspace,
            "deviceId": self.device,
            "installationGeneration": self.generation,
            "sequence": self.meta["healthSequence"],
            "appliedRevision": self.meta["revision"],
            "appliedPolicyHash": self.meta["policyHash"],
            "observedAt": iso(self._now()),
            "requestId": "health-" + uuid.uuid4().hex,
            "status": {
                "healthy": healthy,
                "managementAssuranceLevel": "mdm-managed",
                "lastSyncError": sync_error,
                "policyIntegrity": integrity["state"],
                "policyIntegrityReason": integrity["reason"],
                "outboxDepth": self.outbox_depth,
                "deadLetterDepth": self.dead_letter_depth,
            },
        }
        self._queue("health", health)

    def sync(self) -> dict[str, object]:
        with self.lock:
            self.enroll()
            self.recover()
            self.flush()
            status, response_headers, data = self.request(
                "GET",
                "/runtime/v1/configuration",
                extra={"if-none-match": str(self.meta.get("etag") or "")},
            )
            result: dict[str, object] = {
                "configurationStatus": status,
                "applied": False,
                "error": None,
            }
            try:
                if status == 200:
                    revision = self._apply_configuration(data, response_headers.get("etag"))
                    result.update({"applied": True, "revision": revision})
                elif status == 304:
                    if self.meta.get("revision") is None:
                        raise ContractError("configuration_not_modified_without_state")
                elif status == 204:
                    if self.meta.get("revision") is not None:
                        raise ContractError("configuration_unexpectedly_absent")
                else:
                    raise ContractError(response_error_code(data) or "sync_failed", status if status < 599 else 503)
            except (ContractError, ValueError, RuntimeError, OSError) as error:
                error_code = getattr(error, "code", str(error))
                result["error"] = error_code
                if error_code != "fault_crash_after_write":
                    self._file("pending").unlink(missing_ok=True)
            self.meta["lastSyncError"] = result["error"]
            self._save("meta", self.meta)
            self._queue_health(result["error"] if isinstance(result["error"], str) else None)
            self.flush()
            self.remediate()
            return {**result, **self.view()}
