from __future__ import annotations

from codex_plugin_scanner.guard.runtime.network_broker_contract import DnsResolutionBinding
from codex_plugin_scanner.guard.runtime.network_policy_contract import (
    Destination,
    DestinationKind,
    EnforcementGrade,
    NetworkAction,
    NetworkFlowRequest,
    NetworkPolicy,
    NetworkProtocol,
    NetworkRule,
    PolicyOwner,
    PortRange,
    ProcessScope,
    ProcessScopeKind,
    ProcessTreeIdentity,
)
from codex_plugin_scanner.guard.runtime.network_policy_evaluator import (
    action_is_no_less_restrictive,
    evaluate_policy,
    protocol_requires_dns_binding,
)

_DIGEST = "a" * 64
_RESOLVER_DIGEST = "b" * 64
_NOW = 2_000_000


def _process(session: str = "session.one") -> ProcessTreeIdentity:
    return ProcessTreeIdentity("install.one", session, 123, 456, _DIGEST)


def _binding(
    *,
    process: ProcessTreeIdentity | None = None,
    host: str = "example.com",
    address: str = "192.0.2.2",
    expires_at_epoch_ms: int = _NOW + 5_000,
) -> DnsResolutionBinding:
    return DnsResolutionBinding(
        binding_id="binding.one",
        process_tree_digest=(process or _process()).digest,
        query_name=host,
        canonical_name=host,
        addresses=(address,),
        observed_at_epoch_ms=_NOW - 1,
        expires_at_epoch_ms=expires_at_epoch_ms,
        resolver_digest=_RESOLVER_DIGEST,
    )


def _request(
    destination: Destination,
    *,
    process: ProcessTreeIdentity | None = None,
    binding: DnsResolutionBinding | None = None,
    connected_address: str | None = "192.0.2.2",
) -> NetworkFlowRequest:
    return NetworkFlowRequest(
        request_id="request.one",
        process_tree=process or _process(),
        destination=destination,
        protocol=NetworkProtocol.TCP,
        port=443,
        observed_at_epoch_ms=_NOW,
        connected_address=connected_address,
        dns_binding_digest=binding.digest if binding is not None else None,
    )


def _rule(rule_id: str, action: NetworkAction, destination: Destination) -> NetworkRule:
    return NetworkRule(
        rule_id=rule_id,
        owner=PolicyOwner.LOCAL,
        action=action,
        destinations=(destination,),
        protocols=(NetworkProtocol.TCP,),
        ports=(PortRange(443, 443),),
    )


def test_default_deny_is_explicit_and_digest_bound() -> None:
    destination = Destination(DestinationKind.HOST, "example.com")
    binding = _binding()
    policy = NetworkPolicy("policy.one", 1, (), EnforcementGrade.DESTINATION_ENFORCED)
    result = evaluate_policy(
        policy,
        _request(destination, binding=binding),
        now_epoch_ms=_NOW,
        verified_dns_bindings=(binding,),
    )
    assert result.decision.action is NetworkAction.DENY
    assert result.decision.rule_ids == ("builtin.default-deny",)
    assert result.decision.policy_digest == policy.digest


def test_deny_overrides_allow_independent_of_owner_or_order() -> None:
    destination = Destination(DestinationKind.HOST, "example.com")
    binding = _binding()
    allow = _rule("local.allow", NetworkAction.ALLOW, destination)
    deny = NetworkRule(
        rule_id="organization.deny",
        owner=PolicyOwner.ORGANIZATION,
        action=NetworkAction.DENY,
        destinations=(destination,),
        protocols=(NetworkProtocol.TCP,),
    )
    policy = NetworkPolicy("policy.one", 1, (allow, deny), EnforcementGrade.DESTINATION_ENFORCED)
    result = evaluate_policy(
        policy,
        _request(destination, binding=binding),
        now_epoch_ms=_NOW,
        verified_dns_bindings=(binding,),
    )
    assert result.decision.action is NetworkAction.DENY
    assert result.decision.rule_ids == ("organization.deny",)
    assert result.matched_rule_ids == ("local.allow", "organization.deny")


def test_cidr_and_private_class_match_ip_without_matching_public_ip() -> None:
    private = Destination(DestinationKind.PRIVATE_CLASS, "private")
    rule = _rule("local.private", NetworkAction.APPROVE, private)
    policy = NetworkPolicy("policy.one", 1, (rule,), EnforcementGrade.DESTINATION_ENFORCED)
    assert (
        evaluate_policy(
            policy, _request(Destination(DestinationKind.IP, "10.1.2.3")), now_epoch_ms=_NOW
        ).decision.action
        is NetworkAction.APPROVE
    )
    assert (
        evaluate_policy(policy, _request(Destination(DestinationKind.IP, "8.8.8.8")), now_epoch_ms=_NOW).decision.action
        is NetworkAction.DENY
    )


def test_host_allow_requires_exact_dns_connection_correlation() -> None:
    destination = Destination(DestinationKind.HOST, "example.com")
    binding = _binding()
    policy = NetworkPolicy(
        "policy.one",
        1,
        (_rule("local.allow", NetworkAction.ALLOW, destination),),
        EnforcementGrade.DESTINATION_ENFORCED,
    )

    allowed = evaluate_policy(
        policy,
        _request(destination, binding=binding),
        now_epoch_ms=_NOW,
        verified_dns_bindings=(binding,),
    )
    assert allowed.decision.action is NetworkAction.ALLOW

    wrong_process = _process("session.two")
    wrong_host_binding = _binding(host="other.example")
    stale_binding = _binding(expires_at_epoch_ms=_NOW)
    failures = (
        (_request(destination), ()),
        (_request(destination, binding=binding, connected_address="192.0.2.3"), (binding,)),
        (_request(destination, process=wrong_process, binding=binding), (binding,)),
        (
            _request(destination, binding=wrong_host_binding),
            (wrong_host_binding,),
        ),
        (_request(destination, binding=stale_binding), (stale_binding,)),
    )
    for request, verified_bindings in failures:
        denied = evaluate_policy(
            policy,
            request,
            now_epoch_ms=_NOW,
            verified_dns_bindings=verified_bindings,
        )
        assert denied.decision.action is NetworkAction.DENY
        assert denied.decision.rule_ids == ("builtin.dns-binding-required",)


def test_allow_expiry_is_capped_by_rule_and_dns_binding() -> None:
    destination = Destination(DestinationKind.HOST, "example.com")
    binding = _binding(expires_at_epoch_ms=_NOW + 4_000)
    rule = NetworkRule(
        "local.allow",
        PolicyOwner.LOCAL,
        NetworkAction.ALLOW,
        (destination,),
        (NetworkProtocol.TCP,),
        expires_at_epoch_seconds=(_NOW + 2_000) // 1_000,
    )
    policy = NetworkPolicy("policy.one", 1, (rule,), EnforcementGrade.DESTINATION_ENFORCED)
    result = evaluate_policy(
        policy,
        _request(destination, binding=binding),
        now_epoch_ms=_NOW - 1,
        decision_ttl_ms=300_000,
        verified_dns_bindings=(binding,),
    )
    assert result.decision.expires_at_epoch_ms == _NOW + 2_000
    expired = evaluate_policy(
        policy,
        _request(destination, binding=binding),
        now_epoch_ms=_NOW + 2_000,
        verified_dns_bindings=(binding,),
    )
    assert expired.decision.action is NetworkAction.DENY


def test_host_request_can_match_connected_ip_cidr_only_with_valid_binding() -> None:
    destination = Destination(DestinationKind.HOST, "example.com")
    binding = _binding(address="203.0.113.9")
    rule = _rule("local.cidr", NetworkAction.ALLOW, Destination(DestinationKind.CIDR, "203.0.113.0/24"))
    policy = NetworkPolicy("policy.one", 1, (rule,), EnforcementGrade.DESTINATION_ENFORCED)
    result = evaluate_policy(
        policy,
        _request(destination, binding=binding, connected_address="203.0.113.9"),
        now_epoch_ms=_NOW,
        verified_dns_bindings=(binding,),
    )
    assert result.decision.action is NetworkAction.ALLOW


def test_expired_and_wrong_process_scope_rules_do_not_match() -> None:
    destination = Destination(DestinationKind.HOST, "example.com")
    binding = _binding()
    rule = NetworkRule(
        "local.allow",
        PolicyOwner.LOCAL,
        NetworkAction.ALLOW,
        (destination,),
        (NetworkProtocol.TCP,),
        process_scopes=(ProcessScope(ProcessScopeKind.SESSION, "session.other"),),
        expires_at_epoch_seconds=1,
    )
    policy = NetworkPolicy("policy.one", 1, (rule,), EnforcementGrade.DESTINATION_ENFORCED)
    result = evaluate_policy(
        policy,
        _request(destination, binding=binding),
        now_epoch_ms=_NOW,
        verified_dns_bindings=(binding,),
    )
    assert result.decision.action is NetworkAction.DENY


def test_action_lattice_is_monotonic() -> None:
    assert action_is_no_less_restrictive(NetworkAction.DENY, NetworkAction.ALLOW)
    assert action_is_no_less_restrictive(NetworkAction.APPROVE, NetworkAction.ALLOW)
    assert not action_is_no_less_restrictive(NetworkAction.ALLOW, NetworkAction.DENY)


def test_host_tcp_and_udp_require_dns_binding_but_ip_and_dns_do_not() -> None:
    host = Destination(DestinationKind.HOST, "example.com")
    ip = Destination(DestinationKind.IP, "192.0.2.1")
    assert protocol_requires_dns_binding(NetworkProtocol.TCP, host)
    assert protocol_requires_dns_binding(NetworkProtocol.UDP, host)
    assert not protocol_requires_dns_binding(NetworkProtocol.DNS, host)
    assert not protocol_requires_dns_binding(NetworkProtocol.TCP, ip)


def test_unknown_protocol_is_explicitly_denied() -> None:
    request = NetworkFlowRequest(
        request_id="request.unknown",
        process_tree=_process(),
        destination=Destination(DestinationKind.IP, "192.0.2.1"),
        protocol=NetworkProtocol.UNKNOWN,
        port=443,
        observed_at_epoch_ms=_NOW,
    )
    policy = NetworkPolicy("policy.one", 1, (), EnforcementGrade.DESTINATION_ENFORCED)
    result = evaluate_policy(policy, request, now_epoch_ms=_NOW)
    assert result.decision.action is NetworkAction.DENY
    assert result.decision.rule_ids == ("builtin.unsupported-protocol",)
