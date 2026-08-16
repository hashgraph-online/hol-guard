"""Tests for the reference local OS containment provider (wave two)."""

from __future__ import annotations

import sys
from typing import cast

import pytest

from codex_plugin_scanner.guard.runtime.execution_assurance_contract import (
    AtomicGuaranteeKind,
    DecisionContext,
    ExecutionOutcome,
    GuardExecutionAssuranceBoundary,
    GuardExecutionAttestationTrust,
    ProviderHealthState,
)
from codex_plugin_scanner.guard.runtime.isolation_provider import (
    IsolationProvider,
    ProviderPlanError,
)
from codex_plugin_scanner.guard.runtime.local_os_containment_provider import (
    LocalOSContainmentProvider,
)

_SHA = "a" * 64
_OTHER = "b" * 64


def _context() -> DecisionContext:
    return DecisionContext(
        repository_digest=_SHA,
        workspace_digest=_OTHER,
        executable_digest=_SHA,
        action_class="package-install",
    )


class TestProviderContractConformance:
    def test_satisfies_isolation_provider_protocol(self) -> None:
        assert isinstance(LocalOSContainmentProvider(), IsolationProvider)


class TestIdentity:
    def test_identity_is_pinned_and_self_declared_unsigned(self) -> None:
        provider = LocalOSContainmentProvider()
        identity = provider.identity()
        assert identity.provider_kind == "local-os-containment"
        assert identity.signing_identity == "guard-local-unsigned"
        assert identity.trust_domain == "guard.local"
        assert len(identity.binary_or_image_digest) == 64

    def test_identity_digest_matches_supplied(self) -> None:
        provider = LocalOSContainmentProvider(backend_digest=_SHA)
        assert provider.identity().binary_or_image_digest == _SHA


class TestCapabilities:
    def test_absent_guarantees_never_inferred(self) -> None:
        provider = LocalOSContainmentProvider()
        capabilities = {g.kind: g for g in provider.capabilities()}
        # kernel/hardware and tenant separation are never inferred by the local backend.
        assert capabilities[AtomicGuaranteeKind.KERNEL_HARDWARE].enforced is False
        assert capabilities[AtomicGuaranteeKind.TENANT].enforced is False
        assert capabilities[AtomicGuaranteeKind.PRIVILEGE].enforced is False

    def test_enforced_guarantees_reflect_backend_availability(self) -> None:
        provider = LocalOSContainmentProvider()
        capabilities = {g.kind: g for g in provider.capabilities()}
        # Enforced tracks actual backend binary availability, not just the platform.
        expected = provider.health_check().state is ProviderHealthState.HEALTHY
        assert capabilities[AtomicGuaranteeKind.FILESYSTEM].enforced is expected
        assert capabilities[AtomicGuaranteeKind.NETWORK].enforced is expected

    def test_unavailable_platform_marks_all_unenforced(self) -> None:
        provider = LocalOSContainmentProvider(platform="win32")
        assert all(g.enforced is False for g in provider.capabilities())


class TestHealthCheck:
    def test_unsupported_platform_is_incompatible(self) -> None:
        provider = LocalOSContainmentProvider(platform="win32")
        health = provider.health_check()
        assert health.state is ProviderHealthState.INCOMPATIBLE

    def test_supported_platform_health_matches_availability(self) -> None:
        provider = LocalOSContainmentProvider()
        health = provider.health_check()
        if sys.platform == "darwin":
            assert health.state is ProviderHealthState.HEALTHY
        else:
            assert health.state in (ProviderHealthState.HEALTHY, ProviderHealthState.UNAVAILABLE)


class TestPlan:
    def test_plan_produces_valid_lease_when_available(self) -> None:
        provider = LocalOSContainmentProvider()
        if provider.health_check().state is not ProviderHealthState.HEALTHY:
            return
        ctx = _context()
        lease = provider.plan(ctx, GuardExecutionAssuranceBoundary.OS_ISOLATED)
        assert len(lease.plan_digest) == 64

    def test_plan_rejects_unavailable_required_boundary(self) -> None:
        provider = LocalOSContainmentProvider(platform="win32")
        with pytest.raises(ProviderPlanError):
            provider.plan(_context(), GuardExecutionAssuranceBoundary.OS_ISOLATED)

    def test_plan_rejects_non_context(self) -> None:
        provider = LocalOSContainmentProvider()
        with pytest.raises(ProviderPlanError):
            provider.plan(cast(object, 0), GuardExecutionAssuranceBoundary.OS_ISOLATED)


class TestExecuteStatement:
    def test_statement_is_self_attested_not_verified(self) -> None:
        provider = LocalOSContainmentProvider()
        if provider.health_check().state is not ProviderHealthState.HEALTHY:
            return
        lease = provider.plan(_context(), GuardExecutionAssuranceBoundary.OS_ISOLATED)
        statement = provider.execute(lease)
        # Unsigned v1 output is self-attested, never claimed as verified evidence.
        assert statement.attestation_trust is GuardExecutionAttestationTrust.SELF_ATTESTED

    def test_statement_outcome_matches_health(self) -> None:
        provider = LocalOSContainmentProvider(platform="win32")
        lease = provider.plan(_context(), GuardExecutionAssuranceBoundary.OBSERVED_HOST)
        statement = provider.execute(lease)
        assert statement.outcome is ExecutionOutcome.FAILED


def test_plan_rejects_hardware_isolation_unconditionally() -> None:
    provider = LocalOSContainmentProvider()
    with __import__("pytest").raises(ProviderPlanError):
        provider.plan(_context(), GuardExecutionAssuranceBoundary.HARDWARE_ISOLATED)


def test_plan_rejects_forbidden_input_paths() -> None:
    provider = LocalOSContainmentProvider()
    with __import__("pytest").raises(ProviderPlanError):
        provider.plan(_context(), GuardExecutionAssuranceBoundary.OBSERVED_HOST, input_paths=("/app/.env",))
