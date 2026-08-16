from __future__ import annotations

from dataclasses import replace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from codex_plugin_scanner.guard.runtime.linux_tcp_enforcement import (
    compile_linux_tcp_policy,
    evaluate_linux_tcp_artifact,
)
from codex_plugin_scanner.guard.runtime.linux_udp_dns_enforcement import (
    LinuxResolverRoute,
    LinuxSocketHook,
    compile_linux_udp_dns_policy,
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
    return ProcessTreeIdentity("install.conformance", "session.conformance", 410, 920, "a" * 64)


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


def _policy() -> NetworkPolicy:
    rules = (
        NetworkRule(
            "allow.test-net",
            PolicyOwner.LOCAL,
            NetworkAction.ALLOW,
            (Destination(DestinationKind.CIDR, "192.0.2.0/24"),),
            (NetworkProtocol.TCP, NetworkProtocol.UDP),
            (PortRange(443, 443),),
        ),
    )
    return NetworkPolicy(
        "policy.linux-conformance",
        11,
        rules,
        required_grade=EnforcementGrade.UDP_DNS_DESTINATION_ENFORCED,
    )


def _artifacts(tree: ProcessTreeIdentity | None = None):
    bound_tree = tree or _tree()
    policy = _policy()
    tcp = compile_linux_tcp_policy(policy, bound_tree)
    udp = compile_linux_udp_dns_policy(
        policy,
        bound_tree,
        tcp,
        workload_cgroup_id=42,
        resolver_route=_route(),
        trusted_resolver_public_key=TRUSTED_RESOLVER_PUBLIC_KEY,
    )
    return tcp, udp


def test_udp_artifact_snapshots_process_identity_against_post_compile_mutation() -> None:
    tree = _tree()
    _, artifact = _artifacts(tree)
    object.__setattr__(tree, "root_pid", 999)

    assert (
        evaluate_linux_udp_dns_artifact(
            artifact,
            tree,
            installed_artifact_digest=artifact.digest,
            cgroup_id=42,
            hook=LinuxSocketHook.UDP4_SENDMSG,
            protocol=NetworkProtocol.UDP,
            remote_address="192.0.2.7",
            remote_port=443,
            now_epoch_seconds=1,
        )
        is NetworkAction.DENY
    )
    assert artifact.process_tree.root_pid == 410


def test_evaluators_reject_mutated_fail_open_artifact_defaults() -> None:
    tcp, udp = _artifacts()
    tcp_digest = tcp.digest
    udp_digest = udp.digest
    object.__setattr__(tcp, "default_action", NetworkAction.ALLOW)
    object.__setattr__(udp, "default_action", NetworkAction.ALLOW)

    with pytest.raises(ValueError, match="digest does not match installation"):
        _ = evaluate_linux_tcp_artifact(
            tcp,
            _tree(),
            installed_artifact_digest=tcp_digest,
            remote_address="198.51.100.9",
            remote_port=443,
            now_epoch_seconds=1,
        )
    with pytest.raises(ValueError, match="digest does not match installation"):
        _ = evaluate_linux_udp_dns_artifact(
            udp,
            _tree(),
            installed_artifact_digest=udp_digest,
            cgroup_id=42,
            hook=LinuxSocketHook.UDP4_SENDMSG,
            protocol=NetworkProtocol.UDP,
            remote_address="198.51.100.9",
            remote_port=443,
            now_epoch_seconds=1,
        )


def test_evaluators_reject_tampered_semantics_and_embedded_identity() -> None:
    tcp, udp = _artifacts()
    forged_tcp = replace(tcp, decision_semantics="first-match-wins")
    forged_udp = replace(udp, process_tree=replace(udp.process_tree, root_pid=999))

    with pytest.raises(ValueError, match="digest does not match installation"):
        _ = evaluate_linux_tcp_artifact(
            forged_tcp,
            _tree(),
            installed_artifact_digest=tcp.digest,
            remote_address="192.0.2.7",
            remote_port=443,
            now_epoch_seconds=1,
        )
    with pytest.raises(ValueError, match="digest does not match installation"):
        _ = evaluate_linux_udp_dns_artifact(
            forged_udp,
            _tree(),
            installed_artifact_digest=udp.digest,
            cgroup_id=42,
            hook=LinuxSocketHook.UDP4_SENDMSG,
            protocol=NetworkProtocol.UDP,
            remote_address="192.0.2.7",
            remote_port=443,
            now_epoch_seconds=1,
        )


@pytest.mark.parametrize(
    ("hook", "protocol", "address", "port", "cgroup_id"),
    (
        (LinuxSocketHook.CONNECT6, NetworkProtocol.TCP, "192.0.2.7", 443, 42),
        (LinuxSocketHook.UDP6_SENDMSG, NetworkProtocol.UDP, "192.0.2.7", 443, 42),
        (LinuxSocketHook.UDP4_SENDMSG, NetworkProtocol.UDP, "192.0.2.7", 53, 42),
        (LinuxSocketHook.UDP4_SENDMSG, NetworkProtocol.UDP, "192.0.2.7", 853, 42),
        (LinuxSocketHook.UDP4_SENDMSG, NetworkProtocol.UDP, "192.0.2.7", 443, 41),
    ),
)
def test_adversarial_socket_matrix_fails_closed(
    hook: LinuxSocketHook,
    protocol: NetworkProtocol,
    address: str,
    port: int,
    cgroup_id: int,
) -> None:
    _, artifact = _artifacts()

    assert (
        evaluate_linux_udp_dns_artifact(
            artifact,
            _tree(),
            installed_artifact_digest=artifact.digest,
            cgroup_id=cgroup_id,
            hook=hook,
            protocol=protocol,
            remote_address=address,
            remote_port=port,
            now_epoch_seconds=1,
        )
        is NetworkAction.DENY
    )
