"""Purpose-bound transport contracts for machine health evidence."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
from pathlib import Path
from typing import Protocol, cast

from .health_lease_ack import HealthLeaseAck
from .health_lease_contract import HealthLeaseBinding, HealthLeaseOutbox
from .protection_lease_contract import ProtectionLeaseChallenge

_CHALLENGE_SCHEMA = "guard-protection-attestation-challenge.v1"
_CHALLENGE_KEYS = {
    "challengeId",
    "deviceId",
    "installationGeneration",
    "issuedAt",
    "machineInstallationId",
    "nonce",
    "schemaVersion",
    "validForSeconds",
    "workspaceId",
}


class MachineHealthTransport(Protocol):
    """Authenticated Cloud channel limited to challenge polling and lease delivery."""

    def register_key(self, payload: bytes) -> None: ...

    def poll_challenge(
        self,
        *,
        binding: HealthLeaseBinding,
        installation_generation: str,
        machine_installation_id: str,
    ) -> ProtectionLeaseChallenge | None: ...

    def deliver_lease(self, outbox: HealthLeaseOutbox) -> HealthLeaseAck: ...


class GuardCloudMachineHealthTransport:
    """OAuth/DPoP transport backed by a machine-owned Guard connection store."""

    def __init__(self, guard_home: Path) -> None:
        from ..store import GuardStore

        self._store = GuardStore(guard_home, prime_policy_integrity=False, source="machine-health")

    def configured(self) -> bool:
        return self._store.get_cloud_sync_profile() is not None

    def _request(self, method: str, path: str, body: bytes | None = None) -> tuple[int, bytes]:
        from ..runtime.runner import (
            _guard_sync_request,
            _resolve_guard_sync_auth_context,
        )
        from .network import managed_urlopen

        auth_context = _resolve_guard_sync_auth_context(self._store)
        sync_url = auth_context.get("sync_url")
        if not isinstance(sync_url, str):
            raise OSError("health_lease_delivery_auth_invalid")
        parsed = urllib.parse.urlsplit(sync_url)
        origin = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
        sync_suffix = "/api/guard/receipts/sync"
        if not parsed.path.endswith(sync_suffix):
            raise OSError("health_lease_delivery_auth_invalid")
        api_prefix = parsed.path[: -len(sync_suffix)]
        request_url = f"{origin}{api_prefix}{path}"
        request = _guard_sync_request(
            auth_context,
            request_url=request_url,
            method=method,
            data=body,
        )
        try:
            with managed_urlopen(request, timeout=15) as response:
                status = int(getattr(response, "status", 200))
                payload = response.read(4097)
        except urllib.error.HTTPError as exc:
            bounded = exc.read(1025)
            raise OSError(f"health_lease_delivery_http_{exc.code}:{_cloud_error_code(bounded)}") from exc
        if len(payload) > 4096:
            raise OSError("health_lease_delivery_response_oversized")
        return status, payload

    def poll_challenge(
        self,
        *,
        binding: HealthLeaseBinding,
        installation_generation: str,
        machine_installation_id: str,
    ) -> ProtectionLeaseChallenge | None:
        status, payload = self._request("GET", "/api/guard/runtime/machine-health/challenges/pending")
        if status == 204:
            if payload:
                raise ValueError("health_lease_challenge_invalid")
            return None
        if status != 200:
            raise OSError(f"health_lease_challenge_http_{status}")
        return parse_pending_challenge(
            payload,
            binding=binding,
            installation_generation=installation_generation,
            machine_installation_id=machine_installation_id,
        )

    def register_key(self, payload: bytes) -> None:
        status, response = self._request(
            "POST",
            "/api/guard/runtime/machine-health/keys",
            payload,
        )
        if status != 200:
            raise OSError(f"health_key_registration_http_{status}")
        try:
            decoded = json.loads(response.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise OSError("health_key_registration_ack_invalid") from exc
        if (
            not isinstance(decoded, dict)
            or decoded.get("schemaVersion") != "hol-guard-health-key-registration-ack.v1"
            or decoded.get("status") not in {"registered", "replayed"}
        ):
            raise OSError("health_key_registration_ack_invalid")

    def deliver_lease(self, outbox: HealthLeaseOutbox) -> HealthLeaseAck:
        status, payload = self._request(
            "POST",
            "/api/guard/runtime/machine-health/leases",
            outbox.canonical_bytes(),
        )
        if status != 200:
            raise OSError(f"health_lease_delivery_http_{status}")
        return HealthLeaseAck.parse(payload)


def build_machine_health_transport(state_root: Path) -> MachineHealthTransport | None:
    """Use an explicitly machine-connected OAuth store; never borrow a logged-in user's credentials."""

    guard_home = state_root / "cloud"
    if not (guard_home / "guard.db").is_file():
        return None
    transport = GuardCloudMachineHealthTransport(guard_home)
    if not transport.configured():
        return None
    return transport


def _cloud_error_code(payload: bytes) -> str:
    try:
        decoded = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return "unknown"
    if not isinstance(decoded, dict):
        return "unknown"
    for key in ("code", "error"):
        value = decoded.get(key)
        if isinstance(value, str) and value and len(value) <= 64:
            return value
    return "unknown"


def parse_pending_challenge(
    payload: bytes,
    *,
    binding: HealthLeaseBinding,
    installation_generation: str,
    machine_installation_id: str,
) -> ProtectionLeaseChallenge:
    """Parse only the frozen attestation challenge shape; reject command-like extensions."""

    if not payload or len(payload) > 4096:
        raise ValueError("health_lease_challenge_invalid")
    try:
        decoded = cast(object, json.loads(payload.decode("utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("health_lease_challenge_invalid") from exc
    if not isinstance(decoded, dict) or set(decoded) != _CHALLENGE_KEYS:
        raise ValueError("health_lease_challenge_invalid")
    raw = cast(dict[str, object], decoded)
    if (
        raw.get("schemaVersion") != _CHALLENGE_SCHEMA
        or raw.get("workspaceId") != binding.workspace_id
        or raw.get("deviceId") != binding.device_id
        or raw.get("machineInstallationId") != machine_installation_id
        or raw.get("installationGeneration") != installation_generation
    ):
        raise ValueError("health_lease_challenge_invalid")
    return ProtectionLeaseChallenge.parse(
        {
            "challengeId": raw.get("challengeId"),
            "issuedAt": raw.get("issuedAt"),
            "nonce": raw.get("nonce"),
            "validForSeconds": raw.get("validForSeconds"),
        }
    )


__all__ = [
    "GuardCloudMachineHealthTransport",
    "MachineHealthTransport",
    "build_machine_health_transport",
    "parse_pending_challenge",
]
