"""Typed MDM policy, machine path, and status contracts."""

from __future__ import annotations

import hashlib
import json
import os
import platform
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

MDM_POLICY_SCHEMA_VERSION = "hol-guard-mdm-policy.v1"
MDM_STATUS_SCHEMA_VERSION = "hol-guard-mdm-status.v1"
RELEASE_MANIFEST_SCHEMA_VERSION = "hol-guard-release-manifest.v1"

InstallOwner = Literal["user", "mdm"]
ProxyMode = Literal["system", "explicit", "none"]
ManagedPolicyStatus = Literal["absent", "active", "invalid", "inaccessible", "tampered"]


@dataclass(frozen=True, slots=True)
class MachinePaths:
    """Platform machine-owned locations used by native installers."""

    runtime_root: Path
    state_root: Path
    policy_path: Path | None
    log_root: Path
    manifest_path: Path

    def to_dict(self) -> dict[str, str | None]:
        return {
            "runtimeRoot": str(self.runtime_root),
            "stateRoot": str(self.state_root),
            "policyPath": str(self.policy_path) if self.policy_path is not None else None,
            "logRoot": str(self.log_root),
            "manifestPath": str(self.manifest_path),
        }


def default_machine_paths(*, system_name: str | None = None) -> MachinePaths:
    """Resolve stable machine paths without consulting user-controlled environment overrides."""

    resolved_system = system_name or platform.system()
    if resolved_system == "Darwin":
        runtime_root = Path("/Library/Application Support/HOL Guard")
        return MachinePaths(
            runtime_root=runtime_root,
            state_root=Path("/Library/Application Support/HOL Guard State"),
            policy_path=Path("/Library/Managed Preferences/org.hol.guard.plist"),
            log_root=Path("/Library/Logs/HOL Guard"),
            manifest_path=runtime_root / "release-manifest.json",
        )
    if resolved_system == "Windows":
        program_files = Path(os.environ.get("PROGRAMFILES", r"C:\Program Files"))
        program_data = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData"))
        runtime_root = program_files / "HOL Guard"
        state_root = program_data / "HOL Guard"
        return MachinePaths(
            runtime_root=runtime_root,
            state_root=state_root,
            policy_path=None,
            log_root=state_root / "Logs",
            manifest_path=runtime_root / "release-manifest.json",
        )
    runtime_root = Path("/opt/hol-guard")
    state_root = Path("/var/lib/hol-guard")
    return MachinePaths(
        runtime_root=runtime_root,
        state_root=state_root,
        policy_path=Path("/etc/hol-guard/managed-policy.json"),
        log_root=Path("/var/log/hol-guard"),
        manifest_path=runtime_root / "release-manifest.json",
    )


@dataclass(frozen=True, slots=True)
class ManagedNetworkPolicy:
    proxy_mode: ProxyMode = "system"
    proxy_url: str | None = None
    ca_bundle_path: str | None = None
    allow_public_registries: bool = True

    def to_dict(self) -> dict[str, object]:
        return {
            "proxyMode": self.proxy_mode,
            "proxyConfigured": self.proxy_url is not None,
            "caBundleConfigured": self.ca_bundle_path is not None,
            "allowPublicRegistries": self.allow_public_registries,
        }


@dataclass(frozen=True, slots=True)
class ManagedUpdatePolicy:
    owner: InstallOwner = "user"
    channel: str = "stable"
    minimum_version: str | None = None
    maximum_version: str | None = None
    allow_downgrade: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "owner": self.owner,
            "channel": self.channel,
            "minimumVersion": self.minimum_version,
            "maximumVersion": self.maximum_version,
            "allowDowngrade": self.allow_downgrade,
        }


@dataclass(frozen=True, slots=True)
class ManagedPolicy:
    schema_version: str
    settings: dict[str, object]
    locked_settings: frozenset[str]
    required_harnesses: tuple[str, ...] = ()
    network: ManagedNetworkPolicy = field(default_factory=ManagedNetworkPolicy)
    update: ManagedUpdatePolicy = field(default_factory=ManagedUpdatePolicy)
    daemon_startup: Literal["on-demand", "login"] = "on-demand"
    content_hash: str = ""

    @property
    def install_owner(self) -> InstallOwner:
        return self.update.owner

    def to_public_dict(self) -> dict[str, object]:
        return {
            "schemaVersion": self.schema_version,
            "contentHash": self.content_hash,
            "lockedSettings": sorted(self.locked_settings),
            "requiredHarnesses": list(self.required_harnesses),
            "network": self.network.to_dict(),
            "update": self.update.to_dict(),
            "daemonStartup": self.daemon_startup,
        }


@dataclass(frozen=True, slots=True)
class ManagedPolicyState:
    status: ManagedPolicyStatus
    source: str
    policy: ManagedPolicy | None = None
    reason_code: str | None = None
    detail: str | None = None

    def to_public_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "status": self.status,
            "source": self.source,
            "reasonCode": self.reason_code,
        }
        if self.policy is not None:
            payload["policy"] = self.policy.to_public_dict()
        if self.detail is not None:
            payload["detail"] = self.detail
        return payload


def canonical_payload_hash(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


__all__ = [
    "MDM_POLICY_SCHEMA_VERSION",
    "MDM_STATUS_SCHEMA_VERSION",
    "RELEASE_MANIFEST_SCHEMA_VERSION",
    "InstallOwner",
    "MachinePaths",
    "ManagedNetworkPolicy",
    "ManagedPolicy",
    "ManagedPolicyState",
    "ManagedUpdatePolicy",
    "canonical_payload_hash",
    "default_machine_paths",
]
