from __future__ import annotations

from dataclasses import replace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from codex_plugin_scanner.guard.runtime.linux_tcp_enforcement import (
    compile_linux_tcp_policy,
)
from codex_plugin_scanner.guard.runtime.linux_udp_dns_enforcement import (
    DnsBindingLease,
    LinuxResolverRoute,
    LinuxSocketHook,
    LinuxUdpDnsPolicyArtifact,
    compile_linux_udp_dns_policy,
    create_dns_binding_lease,
    create_linux_resolver_route,
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

RESOLVER_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
TRUSTED_RESOLVER_PUBLIC_KEY = (
    RESOLVER_PRIVATE_KEY.public_key()
    .public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    .hex()
)


def _tree() -> ProcessTreeIdentity:
    return ProcessTreeIdentity("install.alpha", "session.alpha", 123, 456, "a" * 64)


def _route() -> LinuxResolverRoute:
    return create_linux_resolver_route(
        "127.0.0.1",
        5353,
        5354,
        99,
        "b" * 64,
        "d" * 64,
        RESOLVER_PRIVATE_KEY,
    )


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
        trusted_resolver_public_key=TRUSTED_RESOLVER_PUBLIC_KEY,
    )


def _lease(
    artifact: LinuxUdpDnsPolicyArtifact,
    protocol: NetworkProtocol,
    *,
    generation: int | None = None,
    expires_at: int = 20,
) -> DnsBindingLease:
    return create_dns_binding_lease(
        resolver_private_key=RESOLVER_PRIVATE_KEY,
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
) -> NetworkAction:
    return evaluate_linux_udp_dns_artifact(
        artifact,
        _tree(),
        installed_artifact_digest=artifact.digest,
        cgroup_id=cgroup_id,
        hook=hook,
        protocol=protocol,
        remote_address=address,
        remote_port=port,
        now_epoch_seconds=now,
        binding=binding,
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


@pytest.mark.parametrize(
    ("protocol", "hook"),
    (
        (NetworkProtocol.TCP, LinuxSocketHook.CONNECT4),
        (NetworkProtocol.UDP, LinuxSocketHook.UDP4_SENDMSG),
    ),
)
def test_external_https_requires_authenticated_dns_or_doh_intent(
    protocol: NetworkProtocol,
    hook: LinuxSocketHook,
) -> None:
    https = NetworkRule(
        "allow.https",
        PolicyOwner.LOCAL,
        NetworkAction.ALLOW,
        (Destination(DestinationKind.IP, "203.0.113.7"),),
        (protocol,),
        (PortRange(443, 443),),
    )
    artifact = _compile(https)

    assert (
        evaluate_linux_udp_dns_artifact(
            artifact,
            _tree(),
            installed_artifact_digest=artifact.digest,
            cgroup_id=42,
            hook=hook,
            protocol=protocol,
            remote_address="203.0.113.7",
            remote_port=443,
            now_epoch_seconds=1,
        )
        is NetworkAction.DENY
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


def test_udp_dns_rejects_tampered_resolver_attestations() -> None:
    route = replace(_route(), route_signature="0" * 128)
    policy = _policy()
    with pytest.raises(ValueError, match="resolver route attestation"):
        _ = compile_linux_udp_dns_policy(
            policy,
            _tree(),
            compile_linux_tcp_policy(policy, _tree()),
            workload_cgroup_id=42,
            resolver_route=route,
            trusted_resolver_public_key=TRUSTED_RESOLVER_PUBLIC_KEY,
        )

    attacker_private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    attacker_route = create_linux_resolver_route(
        "127.0.0.1",
        5353,
        5354,
        99,
        "b" * 64,
        "d" * 64,
        attacker_private_key,
    )
    with pytest.raises(ValueError, match="resolver route attestation"):
        _ = compile_linux_udp_dns_policy(
            policy,
            _tree(),
            compile_linux_tcp_policy(policy, _tree()),
            workload_cgroup_id=42,
            resolver_route=attacker_route,
            trusted_resolver_public_key=TRUSTED_RESOLVER_PUBLIC_KEY,
        )

    host = NetworkRule(
        "allow.host.tcp",
        PolicyOwner.LOCAL,
        NetworkAction.ALLOW,
        (Destination(DestinationKind.HOST, "api.example.com"),),
        (NetworkProtocol.TCP,),
        (PortRange(443, 443),),
    )
    artifact = _compile(host)
    forged_lease = replace(
        _lease(artifact, NetworkProtocol.TCP),
        address="203.0.113.8",
    )
    assert (
        _evaluate(
            artifact,
            protocol=NetworkProtocol.TCP,
            hook=LinuxSocketHook.CONNECT4,
            address="203.0.113.8",
            port=443,
            binding=forged_lease,
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
            trusted_resolver_public_key=TRUSTED_RESOLVER_PUBLIC_KEY,
        )
