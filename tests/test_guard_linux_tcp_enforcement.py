from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime.linux_tcp_enforcement import (
    compile_linux_tcp_policy,
    evaluate_linux_tcp_artifact,
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
    ProcessScope,
    ProcessScopeKind,
    ProcessTreeIdentity,
)


def _tree() -> ProcessTreeIdentity:
    return ProcessTreeIdentity(
        installation_id="install.alpha",
        session_id="session.alpha",
        root_pid=123,
        root_start_time_ns=456,
        executable_digest="a" * 64,
    )


def _policy(*rules: NetworkRule) -> NetworkPolicy:
    return NetworkPolicy(
        policy_id="policy.linux",
        generation=7,
        rules=rules,
        required_grade=EnforcementGrade.TCP_IP_DESTINATION_ENFORCED,
    )


def test_tcp_lowering_is_deterministic_default_deny_and_process_bound() -> None:
    allow = NetworkRule(
        rule_id="allow.api",
        owner=PolicyOwner.LOCAL,
        action=NetworkAction.ALLOW,
        destinations=(Destination(DestinationKind.IP, "203.0.113.7"),),
        protocols=(NetworkProtocol.TCP,),
        ports=(PortRange(443, 443),),
        process_scopes=(ProcessScope(ProcessScopeKind.SESSION, "session.alpha"),),
    )
    deny = NetworkRule(
        rule_id="deny.range",
        owner=PolicyOwner.BUILTIN,
        action=NetworkAction.DENY,
        destinations=(Destination(DestinationKind.CIDR, "203.0.113.0/24"),),
        protocols=(NetworkProtocol.TCP,),
    )

    artifact = compile_linux_tcp_policy(_policy(allow, deny), _tree())
    repeated = compile_linux_tcp_policy(_policy(deny, allow), _tree())

    assert artifact.default_action is NetworkAction.DENY
    assert artifact.process_tree_digest == _tree().digest
    assert artifact.digest == repeated.digest
    assert artifact.payload == repeated.payload
    assert [(entry.rule_id, entry.network, entry.port_start, entry.port_end) for entry in artifact.entries] == [
        ("deny.range", "203.0.113.0/24", 1, 65535),
        ("allow.api", "203.0.113.7/32", 443, 443),
    ]


def test_tcp_lowering_fails_closed_for_semantics_the_native_hook_cannot_prove() -> None:
    host_rule = NetworkRule(
        rule_id="allow.host",
        owner=PolicyOwner.LOCAL,
        action=NetworkAction.ALLOW,
        destinations=(Destination(DestinationKind.HOST, "api.example.com"),),
        protocols=(NetworkProtocol.TCP,),
    )
    approval_rule = NetworkRule(
        rule_id="approve.ip",
        owner=PolicyOwner.LOCAL,
        action=NetworkAction.APPROVE,
        destinations=(Destination(DestinationKind.IP, "203.0.113.8"),),
        protocols=(NetworkProtocol.TCP,),
    )

    with pytest.raises(ValueError, match="DNS correlation"):
        _ = compile_linux_tcp_policy(_policy(host_rule), _tree())
    with pytest.raises(ValueError, match="broker mediation"):
        _ = compile_linux_tcp_policy(_policy(approval_rule), _tree())


def test_tcp_lowering_does_not_claim_full_destination_enforcement() -> None:
    policy = NetworkPolicy(
        policy_id="policy.full",
        generation=1,
        rules=(),
        required_grade=EnforcementGrade.DESTINATION_ENFORCED,
    )

    with pytest.raises(ValueError, match="exact TCP IP enforcement grade"):
        _ = compile_linux_tcp_policy(policy, _tree())


def test_tcp_reference_semantics_enforce_overlap_expiry_and_identity() -> None:
    allow = NetworkRule(
        rule_id="allow.range",
        owner=PolicyOwner.LOCAL,
        action=NetworkAction.ALLOW,
        destinations=(Destination(DestinationKind.CIDR, "203.0.113.0/24"),),
        protocols=(NetworkProtocol.TCP,),
        expires_at_epoch_seconds=20,
    )
    deny = NetworkRule(
        rule_id="deny.host",
        owner=PolicyOwner.BUILTIN,
        action=NetworkAction.DENY,
        destinations=(Destination(DestinationKind.IP, "203.0.113.7"),),
        protocols=(NetworkProtocol.TCP,),
    )
    artifact = compile_linux_tcp_policy(_policy(allow, deny), _tree())
    allow_artifact = compile_linux_tcp_policy(_policy(allow), _tree())

    assert (
        evaluate_linux_tcp_artifact(
            artifact,
            _tree(),
            installed_artifact_digest=artifact.digest,
            remote_address="203.0.113.7",
            remote_port=443,
            now_epoch_seconds=19,
        )
        is NetworkAction.DENY
    )
    assert (
        evaluate_linux_tcp_artifact(
            allow_artifact,
            _tree(),
            installed_artifact_digest=allow_artifact.digest,
            remote_address="203.0.113.8",
            remote_port=443,
            now_epoch_seconds=20,
        )
        is NetworkAction.DENY
    )
    other_tree = ProcessTreeIdentity(
        installation_id="install.alpha",
        session_id="session.alpha",
        root_pid=124,
        root_start_time_ns=456,
        executable_digest="a" * 64,
    )
    with pytest.raises(ValueError, match="identity does not match"):
        _ = evaluate_linux_tcp_artifact(
            artifact,
            other_tree,
            installed_artifact_digest=artifact.digest,
            remote_address="203.0.113.8",
            remote_port=443,
            now_epoch_seconds=19,
        )
