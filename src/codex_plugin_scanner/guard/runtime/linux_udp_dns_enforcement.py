"""Deterministic reference contract for Linux UDP and brokered DNS enforcement."""

from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass, replace
from enum import Enum
from typing import Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

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
    resolver_public_key: str
    route_signature: str

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
        for label, value, expected_length in (
            ("public key", self.resolver_public_key, 64),
            ("signature", self.route_signature, 128),
        ):
            if len(value) != expected_length:
                raise ValueError(f"resolver route {label} is not valid Ed25519 evidence")
            try:
                _ = bytes.fromhex(value)
            except ValueError as error:
                raise ValueError(f"resolver route {label} is not valid Ed25519 evidence") from error
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
    resolver_signature: str

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
        if len(self.resolver_signature) != 128:
            raise ValueError("DNS binding signature is not valid Ed25519 evidence")
        try:
            _ = bytes.fromhex(self.resolver_signature)
        except ValueError as error:
            raise ValueError("DNS binding signature is not valid Ed25519 evidence") from error
        object.__setattr__(self, "address", ipaddress.ip_address(self.address).compressed)

    @property
    def digest(self) -> str:
        return canonical_digest(asdict(self))


def _resolver_route_manifest_digest(route: LinuxResolverRoute) -> str:
    return canonical_digest(
        {
            "address": route.address,
            "broker_cgroup_id": route.broker_cgroup_id,
            "doh_boundary_digest": route.doh_boundary_digest,
            "executable_digest": route.executable_digest,
            "resolver_public_key": route.resolver_public_key,
            "tcp_port": route.tcp_port,
            "udp_port": route.udp_port,
        }
    )


def _binding_manifest_digest(binding: DnsBindingLease) -> str:
    return canonical_digest(
        {
            "address": binding.address,
            "authoritative_ttl_seconds": binding.authoritative_ttl_seconds,
            "expires_at_epoch_seconds": binding.expires_at_epoch_seconds,
            "generation": binding.generation,
            "host": binding.host,
            "issued_at_epoch_seconds": binding.issued_at_epoch_seconds,
            "policy_id": binding.policy_id,
            "port_end": binding.port_end,
            "port_start": binding.port_start,
            "process_tree_digest": binding.process_tree_digest,
            "protocol": binding.protocol,
            "resolver_nonce": binding.resolver_nonce,
            "resolver_route_digest": binding.resolver_route_digest,
            "workload_cgroup_id": binding.workload_cgroup_id,
        }
    )


def create_linux_resolver_route(
    address: str,
    udp_port: int,
    tcp_port: int,
    broker_cgroup_id: int,
    executable_digest: str,
    doh_boundary_digest: str,
    resolver_private_key: Ed25519PrivateKey,
) -> LinuxResolverRoute:
    public_key = resolver_private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    provisional = LinuxResolverRoute(
        address,
        udp_port,
        tcp_port,
        broker_cgroup_id,
        executable_digest,
        "0" * 64,
        doh_boundary_digest,
        public_key.hex(),
        "0" * 128,
    )
    digest = _resolver_route_manifest_digest(provisional)
    return replace(
        provisional,
        route_attestation_digest=digest,
        route_signature=resolver_private_key.sign(bytes.fromhex(digest)).hex(),
    )


def create_dns_binding_lease(
    *,
    resolver_private_key: Ed25519PrivateKey,
    policy_id: str,
    generation: int,
    process_tree_digest: str,
    workload_cgroup_id: int,
    host: str,
    address: str,
    protocol: NetworkProtocol,
    port_start: int,
    port_end: int,
    issued_at_epoch_seconds: int,
    authoritative_ttl_seconds: int,
    expires_at_epoch_seconds: int,
    resolver_route_digest: str,
    resolver_nonce: str,
) -> DnsBindingLease:
    provisional = DnsBindingLease(
        policy_id,
        generation,
        process_tree_digest,
        workload_cgroup_id,
        host,
        address,
        protocol,
        port_start,
        port_end,
        issued_at_epoch_seconds,
        authoritative_ttl_seconds,
        expires_at_epoch_seconds,
        resolver_route_digest,
        resolver_nonce,
        "0" * 64,
        "0" * 128,
    )
    digest = _binding_manifest_digest(provisional)
    return replace(
        provisional,
        issuance_receipt_digest=digest,
        resolver_signature=resolver_private_key.sign(bytes.fromhex(digest)).hex(),
    )


def _resolver_route_is_attested(route: LinuxResolverRoute, trusted_resolver_public_key: str) -> bool:
    if route.resolver_public_key != trusted_resolver_public_key:
        return False
    digest = _resolver_route_manifest_digest(route)
    if digest != route.route_attestation_digest:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(route.resolver_public_key)).verify(
            bytes.fromhex(route.route_signature),
            bytes.fromhex(digest),
        )
    except (InvalidSignature, ValueError):
        return False
    return True


def _canonical_trusted_resolver_public_key(public_key: str) -> str:
    if len(public_key) != 64:
        raise ValueError("trusted resolver public key is not valid Ed25519 evidence")
    try:
        key_bytes = bytes.fromhex(public_key)
        _ = Ed25519PublicKey.from_public_bytes(key_bytes)
    except ValueError as error:
        raise ValueError("trusted resolver public key is not valid Ed25519 evidence") from error
    if public_key != key_bytes.hex():
        raise ValueError("trusted resolver public key must use canonical lowercase hex")
    return public_key


def _binding_is_attested(binding: DnsBindingLease, resolver_public_key: str) -> bool:
    digest = _binding_manifest_digest(binding)
    if digest != binding.issuance_receipt_digest:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(resolver_public_key)).verify(
            bytes.fromhex(binding.resolver_signature),
            bytes.fromhex(digest),
        )
    except (InvalidSignature, ValueError):
        return False
    return True


@dataclass(frozen=True, slots=True)
class LinuxUdpDnsPolicyArtifact:
    policy_id: str
    generation: int
    policy_digest: str
    tcp_artifact_digest: str
    process_tree_digest: str
    process_tree: ProcessTreeIdentity
    workload_cgroup_id: int
    resolver_route: LinuxResolverRoute
    trusted_resolver_public_key: str
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
    trusted_resolver_public_key: str,
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
        or tcp_artifact.process_tree_digest != process_tree.digest
        or tcp_artifact.process_tree.digest != tcp_artifact.process_tree_digest
    ):
        raise ValueError("TCP artifact does not match policy generation and process tree")
    trusted_resolver_public_key = _canonical_trusted_resolver_public_key(trusted_resolver_public_key)
    if not _resolver_route_is_attested(resolver_route, trusted_resolver_public_key):
        raise ValueError("resolver route attestation is invalid")
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
    process_tree_snapshot = ProcessTreeIdentity(
        installation_id=process_tree.installation_id,
        session_id=process_tree.session_id,
        root_pid=process_tree.root_pid,
        root_start_time_ns=process_tree.root_start_time_ns,
        executable_digest=process_tree.executable_digest,
    )
    return LinuxUdpDnsPolicyArtifact(
        policy.policy_id,
        policy.generation,
        policy.digest,
        tcp_artifact.digest,
        process_tree_snapshot.digest,
        process_tree_snapshot,
        workload_cgroup_id,
        resolver_route,
        trusted_resolver_public_key,
        tuple(l4_entries),
        tuple(host_entries),
    )


def evaluate_linux_udp_dns_artifact(
    artifact: LinuxUdpDnsPolicyArtifact,
    process_tree: ProcessTreeIdentity,
    *,
    cgroup_id: int,
    installed_artifact_digest: str,
    hook: LinuxSocketHook,
    protocol: NetworkProtocol,
    remote_address: str,
    remote_port: int,
    now_epoch_seconds: int,
    binding: DnsBindingLease | None = None,
    application_intent_digest: str | None = None,
) -> NetworkAction:
    """Evaluate trusted installation state and signed resolver evidence."""

    artifact_trusted_key = _canonical_trusted_resolver_public_key(artifact.trusted_resolver_public_key)
    if artifact.digest != installed_artifact_digest:
        raise ValueError("Linux UDP/DNS policy artifact digest does not match installation")
    if (
        not _resolver_route_is_attested(artifact.resolver_route, artifact_trusted_key)
        or artifact.schema_version != LINUX_UDP_DNS_SCHEMA_VERSION
        or artifact.decision_semantics != "all-matches-deny-wins"
        or artifact.resolver_semantics != "deny-external-53-853-attested-route-only"
        or artifact.default_action is not NetworkAction.DENY
        or artifact.process_tree.digest != artifact.process_tree_digest
    ):
        raise ValueError("invalid Linux UDP/DNS policy artifact")
    if process_tree.digest != artifact.process_tree_digest or cgroup_id != artifact.workload_cgroup_id:
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
    on_attested_resolver_route = address == route_address and remote_port == route_port
    binding_is_valid = (
        binding is not None
        and _binding_is_attested(binding, artifact_trusted_key)
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
    )
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
    if remote_port in (53, 853) and not on_attested_resolver_route:
        return NetworkAction.DENY
    if (
        on_attested_resolver_route
        and remote_port == 443
        and application_intent_digest != artifact.resolver_route.doh_boundary_digest
    ):
        return NetworkAction.DENY
    if (
        not on_attested_resolver_route
        and remote_port == 443
        and not binding_is_valid
        and application_intent_digest != artifact.resolver_route.doh_boundary_digest
    ):
        return NetworkAction.DENY
    if on_attested_resolver_route:
        actions.add(NetworkAction.ALLOW)
    if binding_is_valid and binding is not None:
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
