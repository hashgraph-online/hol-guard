from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime.network_broker_contract import (
    BackendReceipt,
    BrokerPerformanceBudget,
    ConnectionObservation,
    CorrelationStatus,
    DnsResolutionBinding,
    ReceiptTrust,
    ReceiptVerification,
    correlate_dns_connection,
    receipt_authority_current,
)
from codex_plugin_scanner.guard.runtime.network_policy_contract import (
    BackendCapability,
    EnforcementGrade,
    NetworkAction,
    NetworkProtocol,
    ProcessTreeIdentity,
    canonical_digest,
)

_DIGEST = "a" * 64
_OTHER_DIGEST = "b" * 64
_NOW = 1_000_000


def _process(session: str = "session.one") -> ProcessTreeIdentity:
    return ProcessTreeIdentity("install.one", session, 10, 20, _DIGEST)


def _binding(process: ProcessTreeIdentity, *, expires: int = _NOW + 5_000) -> DnsResolutionBinding:
    return DnsResolutionBinding(
        binding_id="binding.one",
        process_tree_digest=process.digest,
        query_name="api.example.test",
        canonical_name="edge.example.test",
        addresses=("2001:0db8::1", "192.0.2.2", "192.0.2.2"),
        observed_at_epoch_ms=_NOW,
        expires_at_epoch_ms=expires,
        resolver_digest=_OTHER_DIGEST,
    )


def _observation(process: ProcessTreeIdentity, address: str, *, observed: int = _NOW + 1) -> ConnectionObservation:
    return ConnectionObservation(
        "flow.one",
        process,
        address,
        443,
        NetworkProtocol.TCP,
        observed,
    )


def test_dns_binding_rejects_noncanonical_host_names() -> None:
    with pytest.raises(ValueError, match="canonical ASCII host"):
        DnsResolutionBinding(
            binding_id="binding.one",
            process_tree_digest=_DIGEST,
            query_name="API.Example.Test.",
            canonical_name="edge.example.test",
            addresses=("192.0.2.2",),
            observed_at_epoch_ms=_NOW,
            expires_at_epoch_ms=_NOW + 1,
            resolver_digest=_OTHER_DIGEST,
        )


def test_dns_binding_canonicalizes_addresses_and_correlates_exact_process() -> None:
    process = _process()
    binding = _binding(process)
    assert binding.addresses == ("192.0.2.2", "2001:db8::1")
    assert correlate_dns_connection(_observation(process, "2001:db8::1"), binding) is CorrelationStatus.MATCHED


@pytest.mark.parametrize(
    ("observation", "binding", "expected"),
    (
        (_observation(_process(), "192.0.2.2"), None, CorrelationStatus.MISSING),
        (_observation(_process("session.two"), "192.0.2.2"), _binding(_process()), CorrelationStatus.PROCESS_MISMATCH),
        (_observation(_process(), "192.0.2.3"), _binding(_process()), CorrelationStatus.ADDRESS_MISMATCH),
        (_observation(_process(), "192.0.2.2", observed=_NOW + 6_000), _binding(_process()), CorrelationStatus.EXPIRED),
        (
            _observation(_process(), "192.0.2.2", observed=_NOW - 1),
            _binding(_process()),
            CorrelationStatus.BEFORE_RESOLUTION,
        ),
        (
            _observation(_process(), "192.0.2.2", observed=_NOW + 5_000),
            _binding(_process()),
            CorrelationStatus.EXPIRED,
        ),
    ),
)
def test_dns_correlation_fails_closed(
    observation: ConnectionObservation, binding: DnsResolutionBinding | None, expected: CorrelationStatus
) -> None:
    assert correlate_dns_connection(observation, binding) is expected


def test_dns_correlation_includes_start_and_excludes_expiry() -> None:
    process = _process()
    binding = _binding(process)
    assert (
        correlate_dns_connection(
            _observation(process, "192.0.2.2", observed=_NOW),
            binding,
        )
        is CorrelationStatus.MATCHED
    )
    assert (
        correlate_dns_connection(
            _observation(process, "192.0.2.2", observed=_NOW + 4_999),
            binding,
        )
        is CorrelationStatus.MATCHED
    )


def test_backend_receipt_payload_excludes_signature_but_binds_authority() -> None:
    receipt = BackendReceipt(
        receipt_id="receipt.one",
        backend_id="backend.one",
        backend_digest=_DIGEST,
        process_tree_digest=_OTHER_DIGEST,
        policy_digest=_DIGEST,
        generation=3,
        flow_digest=_OTHER_DIGEST,
        action=NetworkAction.DENY,
        achieved_grade=EnforcementGrade.DESTINATION_ENFORCED,
        capabilities=frozenset(
            {
                BackendCapability.RECEIPTS,
                BackendCapability.TCP_DESTINATION,
                BackendCapability.DENY_ALL,
                BackendCapability.ATOMIC_POLICY,
                BackendCapability.FORCED_BROKER_ROUTING,
                BackendCapability.RESOLVER_ROUTE_ATTESTATION,
                BackendCapability.DOH_CLASSIFICATION_OR_APP_INTENT,
                BackendCapability.UDP_DESTINATION,
                BackendCapability.DNS_CORRELATION,
                BackendCapability.PROCESS_TREE,
            }
        ),
        applied_at_epoch_ms=_NOW,
        valid_until_epoch_ms=_NOW + 1_000,
        signature_key_id="key.one",
        signature="synthetic-signature",
    )
    changed_signature = BackendReceipt(
        **{**{field: getattr(receipt, field) for field in receipt.__dataclass_fields__}, "signature": "other-signature"}
    )
    assert receipt.signed_payload_digest == changed_signature.signed_payload_digest
    changed_capabilities = BackendReceipt(
        **{
            **{field: getattr(receipt, field) for field in receipt.__dataclass_fields__},
            "capabilities": receipt.capabilities | {BackendCapability.OBSERVE},
        }
    )
    assert receipt.signed_payload_digest != changed_capabilities.signed_payload_digest
    assert not receipt_authority_current(receipt, None, now_epoch_ms=_NOW)
    unverified = ReceiptVerification(
        canonical_digest(receipt),
        "verifier.one",
        ReceiptTrust.UNVERIFIED,
        _NOW,
        "signature-unchecked",
    )
    assert not receipt_authority_current(receipt, unverified, now_epoch_ms=_NOW)
    verified = ReceiptVerification(
        canonical_digest(receipt),
        "verifier.one",
        ReceiptTrust.VERIFIED,
        _NOW,
        "signature-valid",
    )
    assert receipt_authority_current(receipt, verified, now_epoch_ms=_NOW)
    mismatched = ReceiptVerification(
        _OTHER_DIGEST,
        "verifier.one",
        ReceiptTrust.VERIFIED,
        _NOW,
        "signature-valid",
    )
    assert not receipt_authority_current(receipt, mismatched, now_epoch_ms=_NOW)
    assert not receipt_authority_current(
        receipt,
        verified,
        now_epoch_ms=_NOW + 1_000,
    )


def test_receipt_requires_truthful_receipt_capability() -> None:
    with pytest.raises(ValueError, match="receipt capability"):
        BackendReceipt(
            "receipt.one",
            "backend.one",
            _DIGEST,
            _OTHER_DIGEST,
            _DIGEST,
            1,
            _OTHER_DIGEST,
            NetworkAction.ALLOW,
            EnforcementGrade.OBSERVE,
            frozenset({BackendCapability.OBSERVE}),
            _NOW,
            _NOW + 1,
            "key.one",
            "signature",
        )


def test_performance_and_dx_budgets_are_bounded() -> None:
    budget = BrokerPerformanceBudget()
    assert budget.decision_p95_ms == 20
    assert budget.maximum_prompts_per_logical_flow == 1
    assert budget.primary_view_usable_ms == 1_000
    with pytest.raises(ValueError, match="p95"):
        BrokerPerformanceBudget(decision_p95_ms=51, decision_p99_ms=50)
