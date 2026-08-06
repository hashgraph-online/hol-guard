"""Deterministic, fail-closed lowering for Linux cgroup TCP enforcement."""

from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass
from typing import Final

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

LINUX_TCP_POLICY_SCHEMA_VERSION: Final = "guard.linux-tcp-policy.v1"
LINUX_TCP_DECISION_SEMANTICS: Final = "all-matches-deny-wins"
LINUX_TCP_EXPIRY_SEMANTICS: Final = "inactive-at-or-after-epoch-second"
LINUX_TCP_ATTACHMENT_SEMANTICS: Final = "cgroup-v2-descendants-pid-start-time-verified"


@dataclass(frozen=True, slots=True)
class LinuxTcpRuleEntry:
    """A canonical userspace-to-native rule; native evaluation remains deny-wins."""

    rule_id: str
    action: NetworkAction
    network: str
    port_start: int
    port_end: int
    expires_at_epoch_seconds: int | None


@dataclass(frozen=True, slots=True)
class LinuxTcpPolicyArtifact:
    """Digest-bound input for an atomic cgroup connect4/connect6 generation."""

    policy_id: str
    generation: int
    policy_digest: str
    process_tree_digest: str
    process_tree: ProcessTreeIdentity
    default_action: NetworkAction
    entries: tuple[LinuxTcpRuleEntry, ...]
    decision_semantics: str = LINUX_TCP_DECISION_SEMANTICS
    expiry_semantics: str = LINUX_TCP_EXPIRY_SEMANTICS
    attachment_semantics: str = LINUX_TCP_ATTACHMENT_SEMANTICS
    schema_version: str = LINUX_TCP_POLICY_SCHEMA_VERSION

    @property
    def digest(self) -> str:
        return canonical_digest(self)

    @property
    def payload(self) -> bytes:
        return canonical_json(asdict(self)).encode("utf-8")


def compile_linux_tcp_policy(
    policy: NetworkPolicy,
    process_tree: ProcessTreeIdentity,
) -> LinuxTcpPolicyArtifact:
    """Lower exact IP/CIDR TCP rules without claiming UDP, DNS, or runtime activation."""

    if policy.required_grade not in (
        EnforcementGrade.TCP_IP_DESTINATION_ENFORCED,
        EnforcementGrade.UDP_DNS_DESTINATION_ENFORCED,
    ):
        raise ValueError("Linux TCP lowering requires the exact TCP IP enforcement grade or composite UDP/DNS grade")

    entries: list[LinuxTcpRuleEntry] = []
    for rule in policy.rules:
        if NetworkProtocol.TCP not in rule.protocols:
            continue
        if rule.action is NetworkAction.APPROVE:
            raise ValueError("approval rules require broker mediation")
        if rule.process_scopes and not any(
            (scope.kind.value == "installation" and scope.value == process_tree.installation_id)
            or (scope.kind.value == "session" and scope.value == process_tree.session_id)
            for scope in rule.process_scopes
        ):
            continue
        port_ranges = tuple((item.start, item.end) for item in rule.ports) or ((1, 65535),)
        for destination in rule.destinations:
            if destination.kind is DestinationKind.HOST:
                if policy.required_grade is EnforcementGrade.UDP_DNS_DESTINATION_ENFORCED:
                    continue
                raise ValueError("host destinations require authenticated DNS correlation before TCP lowering")
            if destination.kind is DestinationKind.PRIVATE_CLASS:
                raise ValueError("private classes must be expanded before native lowering")
            network = ipaddress.ip_network(destination.value, strict=False)
            for port_start, port_end in port_ranges:
                entries.append(
                    LinuxTcpRuleEntry(
                        rule_id=rule.rule_id,
                        action=rule.action,
                        network=network.with_prefixlen,
                        port_start=port_start,
                        port_end=port_end,
                        expires_at_epoch_seconds=rule.expires_at_epoch_seconds,
                    )
                )
    entries.sort(
        key=lambda item: (
            item.network,
            item.port_start,
            item.port_end,
            0 if item.action is NetworkAction.DENY else 1,
            item.rule_id,
        )
    )
    return LinuxTcpPolicyArtifact(
        policy_id=policy.policy_id,
        generation=policy.generation,
        policy_digest=policy.digest,
        process_tree_digest=process_tree.digest,
        process_tree=process_tree,
        default_action=NetworkAction.DENY,
        entries=tuple(entries),
    )


def evaluate_linux_tcp_artifact(
    artifact: LinuxTcpPolicyArtifact,
    process_tree: ProcessTreeIdentity,
    *,
    installed_artifact_digest: str,
    remote_address: str,
    remote_port: int,
    now_epoch_seconds: int,
) -> NetworkAction:
    """Evaluate an artifact against its digest from the trusted installation record."""
    if artifact.digest != installed_artifact_digest:
        raise ValueError("Linux TCP policy artifact digest does not match installation")
    if (
        artifact.schema_version != LINUX_TCP_POLICY_SCHEMA_VERSION
        or artifact.decision_semantics != LINUX_TCP_DECISION_SEMANTICS
        or artifact.expiry_semantics != LINUX_TCP_EXPIRY_SEMANTICS
        or artifact.attachment_semantics != LINUX_TCP_ATTACHMENT_SEMANTICS
        or artifact.default_action is not NetworkAction.DENY
        or artifact.process_tree.digest != artifact.process_tree_digest
    ):
        raise ValueError("invalid Linux TCP policy artifact")

    if process_tree.digest != artifact.process_tree_digest:
        raise ValueError("process tree identity does not match the compiled artifact")
    address = ipaddress.ip_address(remote_address)
    matched_actions = {
        entry.action
        for entry in artifact.entries
        if entry.port_start <= remote_port <= entry.port_end
        and (entry.expires_at_epoch_seconds is None or now_epoch_seconds < entry.expires_at_epoch_seconds)
        and address in ipaddress.ip_network(entry.network)
    }
    if NetworkAction.DENY in matched_actions:
        return NetworkAction.DENY
    if NetworkAction.ALLOW in matched_actions:
        return NetworkAction.ALLOW
    return artifact.default_action
