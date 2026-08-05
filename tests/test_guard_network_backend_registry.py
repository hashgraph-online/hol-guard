from __future__ import annotations

from dataclasses import replace

import pytest

from codex_plugin_scanner.guard.runtime.network_backend_registry import NetworkBackendRegistry
from codex_plugin_scanner.guard.runtime.network_capability_contract import (
    CapabilityRequirement,
    PlatformFamily,
    default_platform_profiles,
)
from codex_plugin_scanner.guard.runtime.network_policy_contract import (
    BackendCapability,
    EnforcementGrade,
)


def test_registry_selects_deterministically_without_inflating_grade() -> None:
    profiles = default_platform_profiles()
    ready_linux = replace(profiles[0], production_ready=True, reason_code="verified")
    registry = NetworkBackendRegistry((ready_linux, *profiles[1:]))
    requirement = CapabilityRequirement(
        frozenset({BackendCapability.DENY_ALL, BackendCapability.PROXY_ONLY, BackendCapability.PROCESS_TREE}),
        EnforcementGrade.PROXY_ONLY,
    )

    selection = registry.select(platform=PlatformFamily.LINUX, requirement=requirement)

    assert selection is not None
    assert selection.profile.backend_id == "linux.oci-proxy"
    assert selection.achieved_grade is EnforcementGrade.PROXY_ONLY
    assert tuple(item.backend_id for item in registry.profiles()) == (
        "kubernetes.network-policy",
        "linux.oci-proxy",
        "macos.observe",
        "windows.observe",
    )


def test_registry_returns_none_for_unsupported_requirement_and_rejects_conflict() -> None:
    profiles = default_platform_profiles()
    registry = NetworkBackendRegistry(profiles)
    requirement = CapabilityRequirement(
        frozenset(
            {
                BackendCapability.TCP_DESTINATION,
                BackendCapability.UDP_DESTINATION,
                BackendCapability.DNS_CORRELATION,
                BackendCapability.PROCESS_TREE,
                BackendCapability.RECEIPTS,
                BackendCapability.DENY_ALL,
                BackendCapability.ATOMIC_POLICY,
                BackendCapability.FORCED_BROKER_ROUTING,
                BackendCapability.RESOLVER_ROUTE_ATTESTATION,
                BackendCapability.DOH_CLASSIFICATION_OR_APP_INTENT,
            }
        ),
        EnforcementGrade.DESTINATION_ENFORCED,
    )

    assert registry.select(platform=PlatformFamily.MACOS, requirement=requirement) is None
    with pytest.raises(ValueError, match="backend profile conflict"):
        registry.register(
            profiles[0].__class__(
                platform=profiles[0].platform,
                backend_id=profiles[0].backend_id,
                capabilities=profiles[0].capabilities,
                maximum_grade=profiles[0].maximum_grade,
                requires_privilege=profiles[0].requires_privilege,
                production_ready=True,
                reason_code="changed",
            )
        )
