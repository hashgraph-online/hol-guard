"""Deterministic no-network and proxy-only Linux namespace plans."""

from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass, replace
from enum import Enum
from hashlib import sha256

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from codex_plugin_scanner.guard.runtime.containment_contract import ContainmentNetworkMode, ContainmentPolicy
from codex_plugin_scanner.guard.runtime.network_policy_contract import (
    ProcessTreeIdentity,
    canonical_digest,
    canonical_json,
)


class LinuxNamespaceMechanism(str, Enum):
    CLONE_NEWNET = "clone-newnet"


@dataclass(frozen=True, slots=True)
class LinuxProxyNamespaceRoute:
    workload_address: str
    broker_address: str
    broker_port: int
    broker_cgroup_id: int
    broker_executable_digest: str
    broker_public_key: str
    route_attestation_digest: str
    route_signature: str

    @property
    def digest(self) -> str:
        return _proxy_route_manifest_digest(self)

    def __post_init__(self) -> None:
        try:
            workload_address = ipaddress.ip_address(self.workload_address)
            broker_address = ipaddress.ip_address(self.broker_address)
        except (TypeError, ValueError) as error:
            raise ValueError("proxy route requires valid namespace endpoints") from error
        if workload_address.version != broker_address.version or workload_address == broker_address:
            raise ValueError("proxy route requires distinct same-family namespace endpoints")
        object.__setattr__(self, "workload_address", workload_address.compressed)
        object.__setattr__(self, "broker_address", broker_address.compressed)
        if (
            type(self.broker_port) is not int
            or type(self.broker_cgroup_id) is not int
            or not 1 <= self.broker_port <= 65535
            or self.broker_cgroup_id <= 0
        ):
            raise ValueError("proxy route requires a valid port and broker cgroup")
        for name, value, expected_size in (
            ("executable digest", self.broker_executable_digest, 32),
            ("attestation digest", self.route_attestation_digest, 32),
            ("public key", self.broker_public_key, 32),
            ("signature", self.route_signature, 64),
        ):
            try:
                decoded = bytes.fromhex(value)
            except (TypeError, ValueError) as error:
                raise ValueError(f"proxy route {name} is invalid") from error
            if len(decoded) != expected_size or value != decoded.hex():
                raise ValueError(f"proxy route {name} must use canonical hex")


def _proxy_route_manifest_digest(route: LinuxProxyNamespaceRoute) -> str:
    payload = asdict(route)
    del payload["route_attestation_digest"]
    del payload["route_signature"]
    return canonical_digest(payload)


def create_linux_proxy_namespace_route(
    workload_address: str,
    broker_address: str,
    broker_port: int,
    broker_cgroup_id: int,
    broker_executable_digest: str,
    broker_private_key: Ed25519PrivateKey,
) -> LinuxProxyNamespaceRoute:
    public_key = (
        broker_private_key.public_key()
        .public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        .hex()
    )
    provisional = LinuxProxyNamespaceRoute(
        workload_address,
        broker_address,
        broker_port,
        broker_cgroup_id,
        broker_executable_digest,
        public_key,
        "0" * 64,
        "0" * 128,
    )
    digest = _proxy_route_manifest_digest(provisional)
    return replace(
        provisional,
        route_attestation_digest=digest,
        route_signature=broker_private_key.sign(bytes.fromhex(digest)).hex(),
    )


def _proxy_route_is_attested(route: LinuxProxyNamespaceRoute, trusted_broker_public_key: str) -> bool:
    try:
        trusted_key = bytes.fromhex(trusted_broker_public_key)
        if (
            len(trusted_key) != 32
            or trusted_broker_public_key != trusted_key.hex()
            or route.broker_public_key != trusted_broker_public_key
        ):
            return False
        digest = _proxy_route_manifest_digest(route)
        if digest != route.route_attestation_digest:
            return False
        Ed25519PublicKey.from_public_bytes(trusted_key).verify(
            bytes.fromhex(route.route_signature),
            bytes.fromhex(digest),
        )
    except (InvalidSignature, ValueError):
        return False
    return True


@dataclass(frozen=True, slots=True)
class LinuxNamespaceNetworkPlan:
    mode: ContainmentNetworkMode
    mechanism: LinuxNamespaceMechanism
    containment_policy_digest: str
    process_tree: ProcessTreeIdentity
    workload_owner_uid: int
    loopback_up: bool
    default_route_present: bool
    host_namespace_reachable: bool
    proxy_route: LinuxProxyNamespaceRoute | None

    @property
    def payload(self) -> bytes:
        return canonical_json(asdict(self)).encode("utf-8")

    @property
    def digest(self) -> str:
        return canonical_digest(asdict(self))


def build_linux_namespace_network_plan(
    policy: ContainmentPolicy,
    process_tree: ProcessTreeIdentity,
    *,
    workload_owner_uid: int,
    proxy_route: LinuxProxyNamespaceRoute | None = None,
    trusted_broker_public_key: str | None = None,
) -> LinuxNamespaceNetworkPlan:
    """Lower containment mode to an inactive, fail-closed namespace plan."""
    if workload_owner_uid <= 0:
        raise ValueError("workload namespace owner must be an unprivileged UID")
    if policy.network_mode is ContainmentNetworkMode.OFFLINE:
        if proxy_route is not None:
            raise ValueError("offline namespace cannot declare a proxy route")
        loopback_up = True
    elif policy.network_mode is ContainmentNetworkMode.GUARDED_PROXY:
        if (
            proxy_route is None
            or trusted_broker_public_key is None
            or sha256(bytes.fromhex(trusted_broker_public_key)).hexdigest() != policy.proxy_verifier_key_digest
            or not _proxy_route_is_attested(proxy_route, trusted_broker_public_key)
            or proxy_route.digest != policy.proxy_endpoint_digest
        ):
            raise ValueError("proxy namespace route must match the trusted containment endpoint")
        loopback_up = True
    else:
        raise ValueError("unsupported containment network mode")
    return LinuxNamespaceNetworkPlan(
        mode=policy.network_mode,
        mechanism=LinuxNamespaceMechanism.CLONE_NEWNET,
        containment_policy_digest=policy.digest,
        process_tree=process_tree,
        workload_owner_uid=workload_owner_uid,
        loopback_up=loopback_up,
        default_route_present=False,
        host_namespace_reachable=False,
        proxy_route=proxy_route,
    )


__all__ = [
    "LinuxNamespaceMechanism",
    "LinuxNamespaceNetworkPlan",
    "LinuxProxyNamespaceRoute",
    "build_linux_namespace_network_plan",
    "create_linux_proxy_namespace_route",
]
