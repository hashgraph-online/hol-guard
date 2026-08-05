from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime.linux_tcp_enforcement import (
    compile_linux_tcp_policy,
)
from codex_plugin_scanner.guard.runtime.linux_udp_dns_enforcement import (
    DnsBindingLease,
    LinuxResolverRoute,
    LinuxSocketHook,
    LinuxUdpDnsPolicyArtifact,
    compile_linux_udp_dns_policy,
    evaluate_linux_udp_dns_artifact,
)
from codex_plugin_scanner.guard.runtime.network_policy_contract import (
    Destination,
    DestinationKind,
    EnforcementGrade,
    NetworkAction,
    NetworkPolicy,
    NetworkProtocol,
    NetworkRule,
    PolicyOwner,
    PortRange,
    ProcessTreeIdentity,
)


def _tree() -> ProcessTreeIdentity:
    return ProcessTreeIdentity("install.alpha", "session.alpha", 123, 456, "a" * 64)


def _route() -> LinuxResolverRoute:
    return LinuxResolverRoute("127.0.0.1", 5353, 5354, 99, "b" * 64, "c" * 64, "d" * 64)


def _policy(*rules: NetworkRule) -> NetworkPolicy:
    return NetworkPolicy(
        "policy.udp-dns",
        8,
        rules,
        required_grade=EnforcementGrade.UDP_DNS_DESTINATION_ENFORCED,
    )


def _compile(*rules: NetworkRule):
    policy = _policy(*rules)
    return compile_linux_udp_dns_policy(
        policy,
        _tree(),
        compile_linux_tcp_policy(policy, _tree()),
        workload_cgroup_id=42,
        resolver_route=_route(),
    )


def _lease(
    artifact: LinuxUdpDnsPolicyArtifact,
    protocol: NetworkProtocol,
    *,
    generation: int | None = None,
    expires_at: int = 20,
) -> DnsBindingLease:
    return DnsBindingLease(
        policy_id=artifact.policy_id,
        generation=artifact.generation if generation is None else generation,
        process_tree_digest=_tree().digest,
        workload_cgroup_id=42,
        host="api.example.com",
        address="203.0.113.7",
        protocol=protocol,
        port_start=443,
        port_end=443,
        issued_at_epoch_seconds=0,
        authoritative_ttl_seconds=30,
        expires_at_epoch_seconds=expires_at,
        resolver_route_digest=_route().digest,
        resolver_nonce="e" * 64,
        issuance_receipt_digest="f" * 64,
    )


def _evaluate(
    artifact: LinuxUdpDnsPolicyArtifact,
    *,
    protocol: NetworkProtocol,
    hook: LinuxSocketHook,
    address: str,
    port: int,
    cgroup_id: int = 42,
    now: int = 1,
    binding: DnsBindingLease | None = None,
    trust_route: bool = True,
) -> NetworkAction:
    return evaluate_linux_udp_dns_artifact(
        artifact,
        _tree(),
        cgroup_id=cgroup_id,
        hook=hook,
        protocol=protocol,
        remote_address=address,
        remote_port=port,
        now_epoch_seconds=now,
        binding=binding,
        verified_binding_digest=binding.digest if binding is not None else None,
        verified_route_attestation_digest=(artifact.resolver_route.route_attestation_digest if trust_route else None),
        application_intent_digest=artifact.resolver_route.doh_boundary_digest,
    )


def test_udp_hooks_force_dns_to_attested_route_and_cover_sendmsg() -> None:
    ntp = NetworkRule(
        "allow.ntp",
        PolicyOwner.LOCAL,
        NetworkAction.ALLOW,
        (Destination(DestinationKind.IP, "192.0.2.7"),),
        (NetworkProtocol.UDP,),
        (PortRange(123, 123),),
    )
    artifact = _compile(ntp)

    assert (
        _evaluate(
            artifact,
            protocol=NetworkProtocol.UDP,
            hook=LinuxSocketHook.UDP4_SENDMSG,
            address="127.0.0.1",
            port=5353,
        )
        is NetworkAction.ALLOW
    )
    assert (
        _evaluate(
            artifact,
            protocol=NetworkProtocol.UDP,
            hook=LinuxSocketHook.CONNECT4,
            address="127.0.0.1",
            port=5354,
        )
        is NetworkAction.DENY
    )
    assert (
        _evaluate(
            artifact,
            protocol=NetworkProtocol.UDP,
            hook=LinuxSocketHook.CONNECT4,
            address="8.8.8.8",
            port=53,
        )
        is NetworkAction.DENY
    )
    assert (
        _evaluate(
            artifact,
            protocol=NetworkProtocol.UDP,
            hook=LinuxSocketHook.UDP4_SENDMSG,
            address="192.0.2.7",
            port=123,
        )
        is NetworkAction.ALLOW
    )


def test_resolver_route_is_protocol_and_port_specific() -> None:
    artifact = _compile()

    assert (
        _evaluate(
            artifact,
            protocol=NetworkProtocol.UDP,
            hook=LinuxSocketHook.CONNECT4,
            address="127.0.0.1",
            port=5353,
        )
        is NetworkAction.ALLOW
    )
    assert (
        _evaluate(
            artifact,
            protocol=NetworkProtocol.TCP,
            hook=LinuxSocketHook.CONNECT4,
            address="127.0.0.1",
            port=5354,
        )
        is NetworkAction.ALLOW
    )
    assert (
        _evaluate(
            artifact,
            protocol=NetworkProtocol.TCP,
            hook=LinuxSocketHook.CONNECT4,
            address="127.0.0.1",
            port=5353,
        )
        is NetworkAction.DENY
    )
    assert (
        _evaluate(
            artifact,
            protocol=NetworkProtocol.TCP,
            hook=LinuxSocketHook.CONNECT4,
            address="1.1.1.1",
            port=853,
        )
        is NetworkAction.DENY
    )
    assert (
        _evaluate(
            artifact,
            protocol=NetworkProtocol.UDP,
            hook=LinuxSocketHook.CONNECT4,
            address="127.0.0.1",
            port=5353,
            trust_route=False,
        )
        is NetworkAction.DENY
    )


def test_resolver_route_allow_does_not_bypass_explicit_deny() -> None:
    deny_route = NetworkRule(
        "deny.route",
        PolicyOwner.BUILTIN,
        NetworkAction.DENY,
        (Destination(DestinationKind.IP, "127.0.0.1"),),
        (NetworkProtocol.TCP, NetworkProtocol.UDP),
        (PortRange(5353, 5354),),
    )
    artifact = _compile(deny_route)

    assert (
        _evaluate(
            artifact,
            protocol=NetworkProtocol.UDP,
            hook=LinuxSocketHook.CONNECT4,
            address="127.0.0.1",
            port=5353,
        )
        is NetworkAction.DENY
    )
    assert (
        _evaluate(
            artifact,
            protocol=NetworkProtocol.TCP,
            hook=LinuxSocketHook.CONNECT4,
            address="127.0.0.1",
            port=5354,
        )
        is NetworkAction.DENY
    )


def test_host_udp_requires_generation_cgroup_route_and_ttl_bound_lease() -> None:
    host = NetworkRule(
        "allow.host",
        PolicyOwner.LOCAL,
        NetworkAction.ALLOW,
        (Destination(DestinationKind.HOST, "api.example.com"),),
        (NetworkProtocol.UDP,),
        (PortRange(443, 443),),
        expires_at_epoch_seconds=30,
    )
    artifact = _compile(host)
    lease = _lease(artifact, NetworkProtocol.UDP)

    assert (
        _evaluate(
            artifact,
            protocol=NetworkProtocol.UDP,
            hook=LinuxSocketHook.CONNECT4,
            address="203.0.113.7",
            port=443,
            now=19,
            binding=lease,
        )
        is NetworkAction.ALLOW
    )
    assert (
        _evaluate(
            artifact,
            protocol=NetworkProtocol.UDP,
            hook=LinuxSocketHook.CONNECT4,
            address="203.0.113.7",
            port=443,
            now=20,
            binding=lease,
        )
        is NetworkAction.DENY
    )
    stale = _lease(
        artifact,
        NetworkProtocol.UDP,
        generation=artifact.generation - 1,
        expires_at=30,
    )
    assert (
        _evaluate(
            artifact,
            protocol=NetworkProtocol.UDP,
            hook=LinuxSocketHook.CONNECT4,
            address="203.0.113.7",
            port=443,
            now=19,
            binding=stale,
        )
        is NetworkAction.DENY
    )


def test_tcp_host_requires_protocol_bound_dns_lease() -> None:
    host = NetworkRule(
        "allow.host.tcp",
        PolicyOwner.LOCAL,
        NetworkAction.ALLOW,
        (Destination(DestinationKind.HOST, "api.example.com"),),
        (NetworkProtocol.TCP,),
        (PortRange(443, 443),),
    )
    artifact = _compile(host)
    lease = _lease(artifact, NetworkProtocol.TCP)

    assert (
        _evaluate(
            artifact,
            protocol=NetworkProtocol.TCP,
            hook=LinuxSocketHook.CONNECT4,
            address="203.0.113.7",
            port=443,
            binding=lease,
        )
        is NetworkAction.ALLOW
    )
    assert (
        _evaluate(
            artifact,
            protocol=NetworkProtocol.UDP,
            hook=LinuxSocketHook.CONNECT4,
            address="203.0.113.7",
            port=443,
            binding=lease,
        )
        is NetworkAction.DENY
    )


def test_udp_dns_artifact_is_deterministic_process_bound_and_deny_wins() -> None:
    allow = NetworkRule(
        "allow.range",
        PolicyOwner.LOCAL,
        NetworkAction.ALLOW,
        (Destination(DestinationKind.CIDR, "2001:db8::/64"),),
        (NetworkProtocol.UDP,),
    )
    deny = NetworkRule(
        "deny.host",
        PolicyOwner.BUILTIN,
        NetworkAction.DENY,
        (Destination(DestinationKind.IP, "2001:db8::7"),),
        (NetworkProtocol.UDP,),
    )
    artifact = _compile(allow, deny)
    repeated = _compile(deny, allow)

    assert artifact.digest == repeated.digest
    assert artifact.payload == repeated.payload
    assert (
        _evaluate(
            artifact,
            protocol=NetworkProtocol.UDP,
            hook=LinuxSocketHook.CONNECT6,
            address="2001:db8::7",
            port=443,
        )
        is NetworkAction.DENY
    )
    assert (
        _evaluate(
            artifact,
            protocol=NetworkProtocol.UDP,
            hook=LinuxSocketHook.CONNECT6,
            address="2001:db8::8",
            port=443,
            cgroup_id=41,
        )
        is NetworkAction.DENY
    )


def test_udp_dns_lowering_rejects_direct_dns_and_grade_overclaim() -> None:
    direct_dns = NetworkRule(
        "allow.dns",
        PolicyOwner.LOCAL,
        NetworkAction.ALLOW,
        (Destination(DestinationKind.HOST, "api.example.com"),),
        (NetworkProtocol.DNS,),
    )
    with pytest.raises(ValueError, match="direct DNS"):
        _ = _compile(direct_dns)

    additive_policy = _policy()
    tcp_artifact = compile_linux_tcp_policy(additive_policy, _tree())
    with pytest.raises(ValueError, match="exact additive grade"):
        _ = compile_linux_udp_dns_policy(
            NetworkPolicy(
                "policy.full",
                1,
                (),
                required_grade=EnforcementGrade.DESTINATION_ENFORCED,
            ),
            _tree(),
            tcp_artifact,
            workload_cgroup_id=42,
            resolver_route=_route(),
        )
