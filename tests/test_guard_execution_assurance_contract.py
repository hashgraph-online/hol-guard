"""Tests for the shared execution-assurance contracts and canonical serializer."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime.execution_assurance_contract import (
    AtomicGuarantee,
    AtomicGuaranteeKind,
    DecisionContext,
    EvidenceSummary,
    ExecutionLease,
    ExecutionOutcome,
    GuardExecutionAssuranceBoundary,
    GuardExecutionAttestationTrust,
    ProviderHealthState,
    ProviderIdentity,
    SecretHandle,
    TerminalStatement,
    framed_digest,
    require_guarantees_satisfied,
)

_SHA = "a" * 64
_OTHER_SHA = "b" * 64


def _identity() -> ProviderIdentity:
    return ProviderIdentity(
        provider_kind="local-seatbelt",
        implementation_version="1.0.0",
        binary_or_image_digest=_SHA,
        signing_identity="guard-local",
        trust_domain="guard.local",
    )


def _guarantee(
    kind: AtomicGuaranteeKind = AtomicGuaranteeKind.FILESYSTEM,
    *,
    enforced: bool = True,
    boundary: GuardExecutionAssuranceBoundary = GuardExecutionAssuranceBoundary.OS_ISOLATED,
) -> AtomicGuarantee:
    return AtomicGuarantee(kind=kind, enforced=enforced, boundary=boundary)


class TestAtomicGuarantee:
    def test_valid_constructs(self) -> None:
        g = _guarantee()
        assert g.enforced is True
        assert g.kind is AtomicGuaranteeKind.FILESYSTEM

    def test_rejects_non_enum_kind(self) -> None:
        with pytest.raises(ValueError, match="AtomicGuaranteeKind"):
            AtomicGuarantee(kind="filesystem", enforced=True, boundary=GuardExecutionAssuranceBoundary.OS_ISOLATED)  # type: ignore[arg-type]

    def test_rejects_non_bool_enforced(self) -> None:
        with pytest.raises(ValueError, match="enforced"):
            AtomicGuarantee(
                kind=AtomicGuaranteeKind.SECRET, enforced="yes", boundary=GuardExecutionAssuranceBoundary.OS_ISOLATED
            )  # type: ignore[arg-type]

    def test_rejects_oversized_evidence_refs(self) -> None:
        with pytest.raises(ValueError, match="evidence refs"):
            AtomicGuarantee(
                kind=AtomicGuaranteeKind.SECRET,
                enforced=True,
                boundary=GuardExecutionAssuranceBoundary.OS_ISOLATED,
                evidence_refs=tuple(f"ref-{i}" for i in range(65)),
            )


class TestFramedDigest:
    def test_deterministic(self) -> None:
        assert framed_digest("d", {"a": "1", "b": "2"}) == framed_digest("d", {"b": "2", "a": "1"})

    def test_distinct_domains(self) -> None:
        assert framed_digest("d1", {"a": "1"}) != framed_digest("d2", {"a": "1"})

    def test_framing_prevents_field_aliasing(self) -> None:
        # ("ab","c") must not equal ("a","bc") under length framing.
        assert framed_digest("d", {"x": "ab", "y": "c"}) != framed_digest("d", {"x": "a", "y": "bc"})

    def test_nested_mappings_are_order_independent(self) -> None:
        first = {"outer": {"b": [2, {"d": None, "c": 1.5}], "a": True}}
        second = {"outer": {"a": True, "b": [2, {"c": 1.5, "d": None}]}}

        assert framed_digest("d", first) == framed_digest("d", second)

    @pytest.mark.parametrize(
        ("left", "right"),
        [
            (None, "null"),
            (True, "true"),
            (1, "1"),
            (1.5, "1.5"),
        ],
    )
    def test_scalar_types_cannot_alias(self, left: object, right: object) -> None:
        assert framed_digest("d", {"value": left}) != framed_digest("d", {"value": right})

    @pytest.mark.parametrize("value", [{"unsafe"}, ["safe", {"unsafe"}]])
    def test_unsupported_values_fail_closed(self, value: object) -> None:
        with pytest.raises(ValueError, match="unsupported digest field type: set"):
            framed_digest("d", {"value": value})

    def test_unsupported_values_never_call_repr(self) -> None:
        class ReprSentinel:
            def __repr__(self) -> str:
                raise AssertionError("repr must not influence a security digest")

        with pytest.raises(ValueError, match="unsupported digest field type: ReprSentinel"):
            framed_digest("d", {"value": [ReprSentinel()]})


class TestProviderIdentity:
    def test_thumbprint_stable(self) -> None:
        assert _identity().thumbprint() == _identity().thumbprint()

    def test_rejects_bad_digest(self) -> None:
        with pytest.raises(ValueError, match="binary_or_image_digest"):
            ProviderIdentity(
                provider_kind="k",
                implementation_version="1",
                binary_or_image_digest="not-a-sha",
                signing_identity="s",
                trust_domain="t",
            )

    def test_rejects_empty_kind(self) -> None:
        with pytest.raises(ValueError, match="provider_kind"):
            ProviderIdentity(
                provider_kind="",
                implementation_version="1",
                binary_or_image_digest=_SHA,
                signing_identity="s",
                trust_domain="t",
            )


class TestExecutionLease:
    def test_valid(self) -> None:
        lease = ExecutionLease(
            plan_digest=_SHA,
            provider_thumbprint=_OTHER_SHA,
            fencing_generation=1,
            lease_expiry_epoch_seconds=1000,
            attempt_nonce="nonce",
            input_manifest_digest=_SHA,
        )
        assert lease.fencing_generation == 1

    def test_rejects_zero_generation(self) -> None:
        with pytest.raises(ValueError, match="fencing_generation"):
            ExecutionLease(
                plan_digest=_SHA,
                provider_thumbprint=_OTHER_SHA,
                fencing_generation=0,
                lease_expiry_epoch_seconds=1000,
                attempt_nonce="nonce",
                input_manifest_digest=_SHA,
            )


class TestTerminalStatement:
    def _statement(self, **overrides: object) -> TerminalStatement:
        base = dict(
            outcome=ExecutionOutcome.SUCCEEDED,
            exit_code=0,
            stream_byte_counts=(("stdout", 10),),
            stream_digests=(("stdout", _SHA),),
            truncated=False,
            declared_output_digests=(),
            cleanup_complete=True,
            execution_instance="inst-1",
            attestation_trust=GuardExecutionAttestationTrust.SELF_ATTESTED,
        )
        base.update(overrides)
        return TerminalStatement(**base)  # type: ignore[arg-type]

    def test_valid(self) -> None:
        assert self._statement().outcome is ExecutionOutcome.SUCCEEDED

    def test_rejects_mismatched_stream_digests(self) -> None:
        with pytest.raises(ValueError, match="every stream"):
            self._statement(stream_digests=(("stderr", _SHA),))

    def test_rejects_exit_code_bool(self) -> None:
        with pytest.raises(ValueError, match="exit_code"):
            self._statement(exit_code=True)


class TestDecisionContextAndEvidence:
    def test_context_digest_computed(self) -> None:
        ctx = DecisionContext(
            repository_digest=_SHA,
            workspace_digest=_OTHER_SHA,
            executable_digest=_SHA,
            action_class="package-install",
        )
        assert len(ctx.context_digest) == 64

    def test_rejects_short_digest(self) -> None:
        with pytest.raises(ValueError, match="repository_digest"):
            DecisionContext(
                repository_digest="short",
                workspace_digest=_OTHER_SHA,
                executable_digest=_SHA,
                action_class="x",
            )

    def test_evidence_summary(self) -> None:
        ev = EvidenceSummary(
            context_digest=_SHA,
            guarantee_kinds=("filesystem", "network"),
            achieved_boundary=GuardExecutionAssuranceBoundary.OS_ISOLATED,
        )
        assert ev.degraded_reason is None


class TestRequireGuaranteesSatisfied:
    def test_all_satisfied(self) -> None:
        provided = [_guarantee(AtomicGuaranteeKind.FILESYSTEM), _guarantee(AtomicGuaranteeKind.NETWORK)]
        assert (
            require_guarantees_satisfied(
                [AtomicGuaranteeKind.FILESYSTEM, AtomicGuaranteeKind.NETWORK],
                provided,
                GuardExecutionAssuranceBoundary.CONTROLLED_HOST,
            )
            == ()
        )

    def test_missing_guarantee_not_substituted_by_boundary(self) -> None:
        # High boundary but the required guarantee is absent.
        provided = [
            _guarantee(AtomicGuaranteeKind.FILESYSTEM, boundary=GuardExecutionAssuranceBoundary.HARDWARE_ISOLATED)
        ]
        assert require_guarantees_satisfied(
            [AtomicGuaranteeKind.NETWORK],
            provided,
            GuardExecutionAssuranceBoundary.OBSERVED_HOST,
        ) == ("network",)

    def test_unenforced_guarantee_unsatisfied(self) -> None:
        provided = [_guarantee(AtomicGuaranteeKind.NETWORK, enforced=False)]
        assert require_guarantees_satisfied(
            [AtomicGuaranteeKind.NETWORK],
            provided,
            GuardExecutionAssuranceBoundary.OBSERVED_HOST,
        ) == ("network",)

    def test_boundary_below_minimum_unsatisfied(self) -> None:
        provided = [_guarantee(AtomicGuaranteeKind.FILESYSTEM, boundary=GuardExecutionAssuranceBoundary.OBSERVED_HOST)]
        assert require_guarantees_satisfied(
            [AtomicGuaranteeKind.FILESYSTEM],
            provided,
            GuardExecutionAssuranceBoundary.OS_ISOLATED,
        ) == ("filesystem",)


class TestEnums:
    def test_health_states(self) -> None:
        assert {s.value for s in ProviderHealthState} == {
            "unknown",
            "verifying",
            "healthy",
            "degraded",
            "unavailable",
            "revoked",
            "incompatible",
        }

    def test_outcome_unknown(self) -> None:
        assert ExecutionOutcome.UNKNOWN.value == "unknown_outcome"

    def test_secret_handle_no_value(self) -> None:
        handle = SecretHandle(handle_id="h1", scope="provider")
        assert not hasattr(handle, "value")
