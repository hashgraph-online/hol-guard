"""Deterministic reference contract for Linux UDP and brokered DNS enforcement."""

from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Final

from codex_plugin_scanner.guard.runtime.linux_tcp_enforcement import LinuxTcpPolicyArtifact
from codex_plugin_scanner.guard.runtime.network_policy_contract import (
    DestinationKind,
    EnforcementGrade,
    NetworkAction,
    NetworkPolicy,
    NetworkProtocol,
    ProcessTreeIdentity,
    canonical_digest,
    canonical_json,
)

LINUX_UDP_DNS_SCHEMA_VERSION: Final = "guard.linux-udp-dns-policy.v1"


class LinuxSocketHook(str, Enum):
    CONNECT4 = "connect4"
    CONNECT6 = "connect6"
    UDP4_SENDMSG = "udp4-sendmsg"
    UDP6_SENDMSG = "udp6-sendmsg"


@dataclass(frozen=True, slots=True)
class LinuxL4RuleEntry:
    rule_id: str
    action: NetworkAction
    protocol: NetworkProtocol
    network: str
    port_start: int
    port_end: int
    expires_at_epoch_seconds: int | None


@dataclass(frozen=True, slots=True)
class LinuxHostRuleEntry:
    rule_id: str
    action: NetworkAction
    protocol: NetworkProtocol
    host: str
    port_start: int
    port_end: int
    expires_at_epoch_seconds: int | None


@dataclass(frozen=True, slots=True)
class LinuxResolverRoute:
    address: str
    udp_port: int
    tcp_port: int
    broker_cgroup_id: int
    executable_digest: str
    route_attestation_digest: str
    doh_boundary_digest: str

    def __post_init__(self) -> None:
        address = ipaddress.ip_address(self.address)
        if not address.is_loopback:
            raise ValueError("resolver route must terminate on loopback")
        if not 1 <= self.udp_port <= 65535 or not 1 <= self.tcp_port <= 65535:
            raise ValueError("resolver route ports must be within 1..65535")
        if type(self.broker_cgroup_id) is not int or self.broker_cgroup_id <= 0:
            raise ValueError("resolver broker cgroup id must be positive")
        for label, digest in (
            ("executable", self.executable_digest),
            ("route attestation", self.route_attestation_digest),
            ("DoH boundary", self.doh_boundary_digest),
        ):
            if len(digest) != 64:
                raise ValueError(f"resolver {label} digest must be SHA-256")
            try:
                _ = bytes.fromhex(digest)
            except ValueError as error:
                raise ValueError(f"resolver {label} digest must be SHA-256") from error
        object.__setattr__(self, "address", address.compressed)

    @property
    def digest(self) -> str:
        return canonical_digest(self)


@dataclass(frozen=True, slots=True)
class DnsBindingLease:
    policy_id: str
    generation: int
    process_tree_digest: str
    workload_cgroup_id: int
    host: str
    address: str
    protocol: NetworkProtocol
    port_start: int
    port_end: int
    issued_at_epoch_seconds: int
    authoritative_ttl_seconds: int
    expires_at_epoch_seconds: int
    resolver_route_digest: str
    resolver_nonce: str
    issuance_receipt_digest: str

    def __post_init__(self) -> None:
        if self.protocol not in (NetworkProtocol.TCP, NetworkProtocol.UDP):
            raise ValueError("DNS binding protocol must be TCP or UDP")
        if self.authoritative_ttl_seconds <= 0:
            raise ValueError("DNS binding TTL must be positive")
        if self.expires_at_epoch_seconds > self.issued_at_epoch_seconds + self.authoritative_ttl_seconds:
            raise ValueError("DNS binding expiry must not exceed authoritative TTL")
        for label, digest in (
            ("resolver nonce", self.resolver_nonce),
            ("issuance receipt", self.issuance_receipt_digest),
        ):
            if len(digest) != 64:
                raise ValueError(f"DNS binding {label} must be SHA-256")
            try:
                _ = bytes.fromhex(digest)
            except ValueError as error:
                raise ValueError(f"DNS binding {label} must be SHA-256") from error
        object.__setattr__(self, "address", ipaddress.ip_address(self.address).compressed)

    @property
    def digest(self) -> str:
        return canonical_digest(asdict(self))


@dataclass(frozen=True, slots=True)
class LinuxUdpDnsPolicyArtifact:
    policy_id: str
    generation: int
    policy_digest: str
    tcp_artifact_digest: str
    process_tree: ProcessTreeIdentity
    workload_cgroup_id: int
    resolver_route: LinuxResolverRoute
    l4_entries: tuple[LinuxL4RuleEntry, ...]
    host_entries: tuple[LinuxHostRuleEntry, ...]
    default_action: NetworkAction = NetworkAction.DENY
    decision_semantics: str = "all-matches-deny-wins"
    resolver_semantics: str = "deny-external-53-853-attested-route-only"
    schema_version: str = LINUX_UDP_DNS_SCHEMA_VERSION

    @property
    def digest(self) -> str:
        return canonical_digest(self)

    @property
    def payload(self) -> bytes:
        return canonical_json(asdict(self)).encode("utf-8")


def compile_linux_udp_dns_policy(
    policy: NetworkPolicy,
    process_tree: ProcessTreeIdentity,
    tcp_artifact: LinuxTcpPolicyArtifact,
    *,
    workload_cgroup_id: int,
    resolver_route: LinuxResolverRoute,
) -> LinuxUdpDnsPolicyArtifact:
    """Lower bounded UDP rules; runtime activation remains privileged and separate."""

    if policy.required_grade is not EnforcementGrade.UDP_DNS_DESTINATION_ENFORCED:
        raise ValueError("Linux UDP/DNS lowering requires its exact additive grade")
    if type(workload_cgroup_id) is not int or workload_cgroup_id <= 0:
        raise ValueError("workload cgroup id must be positive")
    if workload_cgroup_id == resolver_route.broker_cgroup_id:
        raise ValueError("resolver broker must be outside the workload cgroup")
    if (
        tcp_artifact.policy_id != policy.policy_id
        or tcp_artifact.generation != policy.generation
        or tcp_artifact.policy_digest != policy.digest
        or tcp_artifact.process_tree.digest != process_tree.digest
    ):
        raise ValueError("TCP artifact does not match policy generation and process tree")
    l4_entries: list[LinuxL4RuleEntry] = []
    host_entries: list[LinuxHostRuleEntry] = []
    for rule in policy.rules:
        if NetworkProtocol.DNS in rule.protocols:
            raise ValueError("direct DNS rules cannot authorize workload DNS sockets")
        if NetworkProtocol.UDP not in rule.protocols and NetworkProtocol.TCP not in rule.protocols:
            continue
        if rule.action is NetworkAction.APPROVE:
            raise ValueError("approval rules require interactive broker mediation")
        if rule.process_scopes and not any(
            (scope.kind.value == "installation" and scope.value == process_tree.installation_id)
            or (scope.kind.value == "session" and scope.value == process_tree.session_id)
            for scope in rule.process_scopes
        ):
            continue
        ports = tuple((item.start, item.end) for item in rule.ports) or ((1, 65535),)
        for destination in rule.destinations:
            if destination.kind is DestinationKind.PRIVATE_CLASS:
                raise ValueError("private classes must be expanded before native lowering")
            for protocol in rule.protocols:
                if protocol not in (NetworkProtocol.TCP, NetworkProtocol.UDP):
                    continue
                for port_start, port_end in ports:
                    if destination.kind is DestinationKind.HOST:
                        host_entries.append(
                            LinuxHostRuleEntry(
                                rule_id=rule.rule_id,
                                action=rule.action,
                                protocol=protocol,
                                host=destination.value,
                                port_start=port_start,
                                port_end=port_end,
                                expires_at_epoch_seconds=rule.expires_at_epoch_seconds,
                            )
                        )
                    else:
                        network = ipaddress.ip_network(destination.value, strict=False)
                        l4_entries.append(
                            LinuxL4RuleEntry(
                                rule.rule_id,
                                rule.action,
                                protocol,
                                network.with_prefixlen,
                                port_start,
                                port_end,
                                rule.expires_at_epoch_seconds,
                            )
                        )
    l4_entries.sort(
        key=lambda item: (
            item.network,
            item.port_start,
            item.port_end,
            item.protocol.value,
            item.action.value,
            item.rule_id,
        )
    )
    host_entries.sort(
        key=lambda item: (
            item.protocol.value,
            item.host,
            item.port_start,
            item.port_end,
            item.action.value,
            item.rule_id,
        )
    )
    return LinuxUdpDnsPolicyArtifact(
        policy.policy_id,
        policy.generation,
        policy.digest,
        tcp_artifact.digest,
        process_tree,
        workload_cgroup_id,
        resolver_route,
        tuple(l4_entries),
        tuple(host_entries),
    )


def evaluate_linux_udp_dns_artifact(
    artifact: LinuxUdpDnsPolicyArtifact,
    process_tree: ProcessTreeIdentity,
    *,
    cgroup_id: int,
    hook: LinuxSocketHook,
    protocol: NetworkProtocol,
    remote_address: str,
    remote_port: int,
    now_epoch_seconds: int,
    binding: DnsBindingLease | None = None,
    verified_binding_digest: str | None = None,
    verified_route_attestation_digest: str | None = None,
    application_intent_digest: str | None = None,
) -> NetworkAction:
    """Reference TCP-host and connected/sendmsg UDP semantics for cgroup hooks."""

    if process_tree.digest != artifact.process_tree.digest or cgroup_id != artifact.workload_cgroup_id:
        return NetworkAction.DENY
    address = ipaddress.ip_address(remote_address)
    expected_family = "4" if address.version == 4 else "6"
    if expected_family not in hook.value:
        return NetworkAction.DENY
    if protocol not in (NetworkProtocol.TCP, NetworkProtocol.UDP):
        return NetworkAction.DENY
    if protocol is NetworkProtocol.TCP and hook not in (
        LinuxSocketHook.CONNECT4,
        LinuxSocketHook.CONNECT6,
    ):
        return NetworkAction.DENY
    route_port = (
        artifact.resolver_route.tcp_port if protocol is NetworkProtocol.TCP else artifact.resolver_route.udp_port
    )
    route_address = ipaddress.ip_address(artifact.resolver_route.address)
    actions: set[NetworkAction] = set()
    actions.update(
        entry.action
        for entry in artifact.l4_entries
        if entry.protocol is protocol
        and entry.port_start <= remote_port <= entry.port_end
        and (entry.expires_at_epoch_seconds is None or now_epoch_seconds < entry.expires_at_epoch_seconds)
        and address in ipaddress.ip_network(entry.network)
    )
    if NetworkAction.DENY in actions:
        return NetworkAction.DENY
    if remote_port in (53, 853):
        return NetworkAction.DENY
    if remote_port == 443 and application_intent_digest != artifact.resolver_route.doh_boundary_digest:
        return NetworkAction.DENY
    if (
        address == route_address
        and remote_port == route_port
        and verified_route_attestation_digest == artifact.resolver_route.route_attestation_digest
    ):
        actions.add(NetworkAction.ALLOW)
    if (
        binding is not None
        and verified_binding_digest == binding.digest
        and _binding_matches(
            artifact,
            process_tree,
            cgroup_id=cgroup_id,
            address=address.compressed,
            port=remote_port,
            now_epoch_seconds=now_epoch_seconds,
            protocol=protocol,
            binding=binding,
        )
    ):
        actions.update(
            entry.action
            for entry in artifact.host_entries
            if entry.host == binding.host
            and entry.protocol is protocol
            and entry.port_start <= remote_port <= entry.port_end
            and (entry.expires_at_epoch_seconds is None or now_epoch_seconds < entry.expires_at_epoch_seconds)
        )
    if NetworkAction.DENY in actions:
        return NetworkAction.DENY
    if NetworkAction.ALLOW in actions:
        return NetworkAction.ALLOW
    return artifact.default_action


def _binding_matches(
    artifact: LinuxUdpDnsPolicyArtifact,
    process_tree: ProcessTreeIdentity,
    *,
    cgroup_id: int,
    address: str,
    port: int,
    protocol: NetworkProtocol,
    now_epoch_seconds: int,
    binding: DnsBindingLease,
) -> bool:
    return (
        binding.policy_id == artifact.policy_id
        and binding.generation == artifact.generation
        and binding.process_tree_digest == process_tree.digest
        and binding.workload_cgroup_id == cgroup_id
        and binding.address == address
        and binding.protocol is protocol
        and binding.port_start <= port <= binding.port_end
        and now_epoch_seconds < binding.expires_at_epoch_seconds
        and binding.resolver_route_digest == artifact.resolver_route.digest
    )
