from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime.network_policy_contract import (
    NETWORK_BACKEND_SCHEMA_VERSION,
    NETWORK_BROKER_SCHEMA_VERSION,
    NETWORK_EVIDENCE_SCHEMA_VERSION,
    NETWORK_POLICY_SCHEMA_VERSION,
    BackendAdvertisement,
    BackendCapability,
    Destination,
    DestinationKind,
    EnforcementGrade,
    FailureMode,
    NetworkAction,
    NetworkEvidence,
    NetworkFlowRequest,
    NetworkPolicy,
    NetworkProtocol,
    NetworkRule,
    PolicyOwner,
    PortRange,
    PrivateNetworkClass,
    ProcessTreeIdentity,
    canonical_digest,
    canonical_json,
    classify_private_address,
)

_DIGEST = "a" * 64


def _tree() -> ProcessTreeIdentity:
    return ProcessTreeIdentity(
        installation_id="install.alpha",
        session_id="session.alpha",
        root_pid=123,
        root_start_time_ns=456,
        executable_digest=_DIGEST,
    )


def _rule(*, rule_id: str = "rule.alpha") -> NetworkRule:
    return NetworkRule(
        rule_id=rule_id,
        owner=PolicyOwner.ORGANIZATION,
        action=NetworkAction.DENY,
        destinations=(Destination(DestinationKind.HOST, "API.Example.COM."),),
        protocols=(NetworkProtocol.TCP,),
        ports=(PortRange(443, 443),),
    )


def test_schema_versions_are_explicit() -> None:
    assert NETWORK_POLICY_SCHEMA_VERSION == "guard.network-policy.v1"
    assert NETWORK_BROKER_SCHEMA_VERSION == "guard.network-broker.v1"
    assert NETWORK_BACKEND_SCHEMA_VERSION == "guard.network-backend.v1"
    assert NETWORK_EVIDENCE_SCHEMA_VERSION == "guard.network-evidence.v1"


def test_destination_canonicalization_is_unambiguous() -> None:
    assert Destination(DestinationKind.HOST, "API.Example.COM.").value == "api.example.com"
    assert Destination(DestinationKind.IP, "2001:0db8::1").value == "2001:db8::1"
    assert Destination(DestinationKind.CIDR, "10.0.0.0/8").value == "10.0.0.0/8"
    assert Destination(DestinationKind.HOST, "bücher.example").value == "xn--bcher-kva.example"
    assert Destination(DestinationKind.HOST, "xn--bcher-kva.example").value == "xn--bcher-kva.example"
    with pytest.raises(ValueError, match="invalid IDNA"):
        Destination(DestinationKind.HOST, "\uff45xample.com")
    with pytest.raises(ValueError, match="invalid IDNA"):
        Destination(DestinationKind.HOST, "*.example.com")
    with pytest.raises(ValueError):
        Destination(DestinationKind.CIDR, "10.0.0.1/8")


def test_canonical_json_keeps_structured_set_members_distinct() -> None:
    assert canonical_json(frozenset({("a", "b"), ("ab",)})) == '[["a","b"],["ab"]]'


def test_private_address_classification_is_explicit() -> None:
    assert classify_private_address("127.0.0.1") is PrivateNetworkClass.LOOPBACK
    assert classify_private_address("169.254.1.1") is PrivateNetworkClass.LINK_LOCAL
    assert classify_private_address("10.1.2.3") is PrivateNetworkClass.PRIVATE
    assert classify_private_address("224.0.0.1") is PrivateNetworkClass.MULTICAST
    assert classify_private_address("0.0.0.0") is PrivateNetworkClass.UNSPECIFIED
    assert classify_private_address("8.8.8.8") is None


def test_policy_digest_is_order_independent_and_version_bound() -> None:
    alpha = _rule(rule_id="rule.alpha")
    beta = _rule(rule_id="rule.beta")
    first = NetworkPolicy(
        policy_id="policy.alpha",
        generation=1,
        rules=(beta, alpha),
        required_grade=EnforcementGrade.DESTINATION_ENFORCED,
    )
    second = NetworkPolicy(
        policy_id="policy.alpha",
        generation=1,
        rules=(alpha, beta),
        required_grade=EnforcementGrade.DESTINATION_ENFORCED,
    )
    assert first.digest == second.digest
    assert canonical_json(first) == canonical_json(second)
    with pytest.raises(ValueError, match="unsupported"):
        NetworkPolicy(
            policy_id="policy.alpha",
            generation=1,
            rules=(),
            required_grade=EnforcementGrade.DENY_ALL,
            schema_version="guard.network-policy.v2",
        )


def test_policy_rejects_duplicate_rules_and_malformed_ports() -> None:
    alpha = _rule()
    with pytest.raises(ValueError, match="unique"):
        NetworkPolicy(
            policy_id="policy.alpha",
            generation=1,
            rules=(alpha, alpha),
            required_grade=EnforcementGrade.DENY_ALL,
        )
    with pytest.raises(ValueError, match=r"1\.\.65535"):
        PortRange(0, 443)
    with pytest.raises(ValueError, match="include port 53"):
        NetworkRule(
            rule_id="rule.dns",
            owner=PolicyOwner.LOCAL,
            action=NetworkAction.ALLOW,
            destinations=(Destination(DestinationKind.HOST, "resolver.example"),),
            protocols=(NetworkProtocol.DNS,),
            ports=(PortRange(443, 443),),
        )
    with pytest.raises(ValueError, match="unknown protocols"):
        NetworkRule(
            rule_id="rule.unknown",
            owner=PolicyOwner.LOCAL,
            action=NetworkAction.ALLOW,
            destinations=(Destination(DestinationKind.HOST, "example.test"),),
            protocols=(NetworkProtocol.UNKNOWN,),
        )


def test_process_identity_binds_pid_start_time_and_executable() -> None:
    tree = _tree()
    assert tree.digest == canonical_digest(
        {
            "installation_id": "install.alpha",
            "session_id": "session.alpha",
            "root_pid": 123,
            "root_start_time_ns": 456,
            "executable_digest": _DIGEST,
        }
    )
    with pytest.raises(ValueError, match="root_pid"):
        ProcessTreeIdentity("install.alpha", "session.alpha", 0, 456, _DIGEST)


def test_broker_request_requires_dns_binding_digest_when_present() -> None:
    request = NetworkFlowRequest(
        request_id="request.alpha",
        process_tree=_tree(),
        destination=Destination(DestinationKind.IP, "203.0.113.1"),
        protocol=NetworkProtocol.TCP,
        port=443,
        observed_at_epoch_ms=1,
        dns_binding_digest=_DIGEST,
    )
    assert request.schema_version == NETWORK_BROKER_SCHEMA_VERSION
    with pytest.raises(ValueError, match="dns_binding_digest"):
        NetworkFlowRequest(
            request_id="request.alpha",
            process_tree=_tree(),
            destination=Destination(DestinationKind.IP, "203.0.113.1"),
            protocol=NetworkProtocol.TCP,
            port=443,
            observed_at_epoch_ms=1,
            dns_binding_digest="bad",
        )


def test_backend_advertisement_is_versioned_and_bounded() -> None:
    backend = BackendAdvertisement(
        backend_id="backend.alpha",
        backend_digest=_DIGEST,
        capabilities=frozenset({BackendCapability.DENY_ALL, BackendCapability.RECEIPTS}),
        maximum_grade=EnforcementGrade.DENY_ALL,
        healthy_until_epoch_ms=100,
    )
    assert backend.schema_version == NETWORK_BACKEND_SCHEMA_VERSION
    with pytest.raises(ValueError, match="capabilities"):
        BackendAdvertisement(
            backend_id="backend.alpha",
            backend_digest=_DIGEST,
            capabilities=frozenset(),
            maximum_grade=EnforcementGrade.UNAVAILABLE,
            healthy_until_epoch_ms=100,
        )
    with pytest.raises(ValueError, match="exceeds verified capabilities"):
        BackendAdvertisement(
            backend_id="backend.alpha",
            backend_digest=_DIGEST,
            capabilities=frozenset({BackendCapability.DENY_ALL}),
            maximum_grade=EnforcementGrade.DESTINATION_ENFORCED,
            healthy_until_epoch_ms=100,
        )


def test_evidence_rejects_raw_destination() -> None:
    evidence = NetworkEvidence(
        flow_id="flow.alpha",
        process_tree_digest=_DIGEST,
        destination_digest=_DIGEST,
        protocol=NetworkProtocol.TCP,
        port=443,
        action=NetworkAction.DENY,
        policy_digest=_DIGEST,
        backend_digest=_DIGEST,
        grade=EnforcementGrade.DESTINATION_ENFORCED,
        observed_at_epoch_ms=1,
    )
    assert evidence.raw_destination is None
    with pytest.raises(ValueError, match="separate opt-in"):
        NetworkEvidence(
            flow_id="flow.alpha",
            process_tree_digest=_DIGEST,
            destination_digest=_DIGEST,
            protocol=NetworkProtocol.TCP,
            port=443,
            action=NetworkAction.DENY,
            policy_digest=_DIGEST,
            backend_digest=_DIGEST,
            grade=EnforcementGrade.DESTINATION_ENFORCED,
            observed_at_epoch_ms=1,
            raw_destination="api.example.com",
        )


def test_canonical_serializer_rejects_floats_and_unknown_values() -> None:
    with pytest.raises(ValueError, match="unsupported canonical value"):
        canonical_json({"latency": 1.5})


def test_failure_modes_are_explicit_and_fail_closed_by_default() -> None:
    policy = NetworkPolicy(
        policy_id="policy.alpha",
        generation=1,
        rules=(),
        required_grade=EnforcementGrade.DENY_ALL,
    )
    assert policy.failure_mode is FailureMode.DENY


def test_canonical_json_rejects_non_string_mapping_keys() -> None:
    with pytest.raises(ValueError, match="mapping keys"):
        canonical_json({1: "integer", "1": "string"})
