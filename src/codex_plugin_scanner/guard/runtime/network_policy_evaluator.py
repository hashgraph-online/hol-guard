"""Deterministic, monotonic evaluation for guard.network-policy.v1."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from .network_broker_contract import (
    ConnectionObservation,
    CorrelationStatus,
    DnsResolutionBinding,
    correlate_dns_connection,
)
from .network_policy_contract import (
    Destination,
    DestinationKind,
    NetworkAction,
    NetworkDecision,
    NetworkFlowRequest,
    NetworkPolicy,
    NetworkProtocol,
    NetworkRule,
    PrivateNetworkClass,
    ProcessScope,
    ProcessScopeKind,
    ProcessTreeIdentity,
    canonical_digest,
    classify_private_address,
)

_ACTION_ORDER = {
    NetworkAction.DENY: 0,
    NetworkAction.APPROVE: 1,
    NetworkAction.ALLOW: 2,
}


@dataclass(frozen=True, slots=True)
class PolicyEvaluation:
    decision: NetworkDecision
    matched_rule_ids: tuple[str, ...]


def evaluate_policy(
    policy: NetworkPolicy,
    request: NetworkFlowRequest,
    *,
    now_epoch_ms: int,
    decision_ttl_ms: int = 30_000,
    verified_dns_bindings: tuple[DnsResolutionBinding, ...] = (),
) -> PolicyEvaluation:
    """Evaluate every matching rule; the most restrictive action always wins."""

    if type(now_epoch_ms) is not int or now_epoch_ms <= 0:
        raise ValueError("now_epoch_ms must be positive")
    if type(decision_ttl_ms) is not int or not 1 <= decision_ttl_ms <= 300_000:
        raise ValueError("decision_ttl_ms must be within 1..300000")

    matches = tuple(rule for rule in policy.rules if _rule_matches(rule, request, now_epoch_ms=now_epoch_ms))
    dns_binding = _verified_dns_binding(request, verified_dns_bindings, now_epoch_ms=now_epoch_ms)
    dns_binding_missing = protocol_requires_dns_binding(request.protocol, request.destination) and dns_binding is None
    if request.protocol is NetworkProtocol.UNKNOWN:
        action = NetworkAction.DENY
        rule_ids = ("builtin.unsupported-protocol",)
    elif dns_binding_missing:
        action = NetworkAction.DENY
        rule_ids = ("builtin.dns-binding-required",)
    elif matches:
        action = min((rule.action for rule in matches), key=_ACTION_ORDER.__getitem__)
        rule_ids = tuple(rule.rule_id for rule in matches if rule.action is action)
    else:
        action = NetworkAction.DENY
        rule_ids = ("builtin.default-deny",)

    expiry_candidates = [now_epoch_ms + decision_ttl_ms]
    if action in (NetworkAction.ALLOW, NetworkAction.APPROVE):
        expiry_candidates.extend(
            rule.expires_at_epoch_seconds * 1_000
            for rule in matches
            if rule.action is action and rule.expires_at_epoch_seconds is not None
        )
        if dns_binding is not None:
            expiry_candidates.append(dns_binding.expires_at_epoch_ms)
    decision = NetworkDecision(
        request_digest=canonical_digest(request),
        policy_digest=policy.digest,
        generation=policy.generation,
        action=action,
        rule_ids=rule_ids,
        expires_at_epoch_ms=min(expiry_candidates),
    )
    return PolicyEvaluation(
        decision=decision,
        matched_rule_ids=tuple(rule.rule_id for rule in matches),
    )


def _rule_matches(rule: NetworkRule, request: NetworkFlowRequest, *, now_epoch_ms: int) -> bool:
    if rule.expires_at_epoch_seconds is not None and rule.expires_at_epoch_seconds * 1_000 <= now_epoch_ms:
        return False
    if request.protocol not in rule.protocols:
        return False
    if rule.ports and not any(port.start <= request.port <= port.end for port in rule.ports):
        return False
    if rule.process_scopes and not any(_scope_matches(scope, request.process_tree) for scope in rule.process_scopes):
        return False
    requested_destinations = [request.destination]
    if request.destination.kind is DestinationKind.HOST and request.connected_address is not None:
        requested_destinations.append(Destination(DestinationKind.IP, request.connected_address))
    return any(
        _destination_matches(destination, requested)
        for destination in rule.destinations
        for requested in requested_destinations
    )


def _verified_dns_binding(
    request: NetworkFlowRequest,
    bindings: tuple[DnsResolutionBinding, ...],
    *,
    now_epoch_ms: int,
) -> DnsResolutionBinding | None:
    if not protocol_requires_dns_binding(request.protocol, request.destination):
        return None
    if request.dns_binding_digest is None or request.connected_address is None:
        return None
    for binding in bindings:
        if request.destination.value not in (binding.query_name, binding.canonical_name):
            continue
        if request.connected_address not in binding.addresses:
            continue
        if binding.digest != request.dns_binding_digest:
            continue
        if now_epoch_ms >= binding.expires_at_epoch_ms:
            continue
        observation = ConnectionObservation(
            flow_id=request.request_id,
            process_tree=request.process_tree,
            remote_address=request.connected_address,
            remote_port=request.port,
            protocol=request.protocol,
            observed_at_epoch_ms=request.observed_at_epoch_ms,
        )
        if correlate_dns_connection(observation, binding) is CorrelationStatus.MATCHED:
            return binding
    return None


def _scope_matches(scope: ProcessScope, process_tree: ProcessTreeIdentity) -> bool:
    if scope.kind is ProcessScopeKind.INSTALLATION:
        return scope.value == process_tree.installation_id
    return scope.value == process_tree.session_id


def _destination_matches(rule: Destination, requested: Destination) -> bool:
    if rule == requested:
        return True
    if rule.kind is DestinationKind.CIDR and requested.kind is DestinationKind.IP:
        return ipaddress.ip_address(requested.value) in ipaddress.ip_network(rule.value)
    if rule.kind is DestinationKind.PRIVATE_CLASS and requested.kind is DestinationKind.IP:
        classified = classify_private_address(requested.value)
        return classified is PrivateNetworkClass(rule.value)
    return False


def action_is_no_less_restrictive(candidate: NetworkAction, baseline: NetworkAction) -> bool:
    """Return whether candidate preserves or tightens baseline authority."""

    return _ACTION_ORDER[candidate] <= _ACTION_ORDER[baseline]


def protocol_requires_dns_binding(protocol: NetworkProtocol, destination: Destination) -> bool:
    """Host-based TCP/UDP authority requires an authenticated DNS binding."""

    return destination.kind is DestinationKind.HOST and protocol in (
        NetworkProtocol.TCP,
        NetworkProtocol.UDP,
    )
