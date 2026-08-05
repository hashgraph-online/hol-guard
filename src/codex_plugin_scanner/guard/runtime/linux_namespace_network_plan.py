"""Deterministic no-network and proxy-only Linux namespace plans."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum

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
    endpoint_digest: str

    def __post_init__(self) -> None:
        if not 1 <= self.broker_port <= 65535 or self.broker_cgroup_id <= 0:
            raise ValueError("proxy route requires a valid port and broker cgroup")
        for digest in (self.broker_executable_digest, self.endpoint_digest):
            if len(digest) != 64:
                raise ValueError("proxy route digests must be SHA-256")
            _ = bytes.fromhex(digest)
        if self.workload_address == self.broker_address:
            raise ValueError("proxy route requires distinct namespace endpoints")


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
) -> LinuxNamespaceNetworkPlan:
    """Lower containment mode to an inactive, fail-closed namespace plan."""
    if workload_owner_uid <= 0:
        raise ValueError("workload namespace owner must be an unprivileged UID")
    if policy.network_mode is ContainmentNetworkMode.OFFLINE:
        if proxy_route is not None:
            raise ValueError("offline namespace cannot declare a proxy route")
        loopback_up = True
    elif policy.network_mode is ContainmentNetworkMode.GUARDED_PROXY:
        if proxy_route is None or proxy_route.endpoint_digest != policy.proxy_endpoint_digest:
            raise ValueError("proxy namespace route must match the containment endpoint")
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
]
