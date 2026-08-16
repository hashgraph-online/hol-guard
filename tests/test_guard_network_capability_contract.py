from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime.network_capability_contract import (
    BackendState,
    CapabilityRequirement,
    ControlPlaneEscapeHatch,
    ControlPlaneRoute,
    NetworkPrivacyPolicy,
    PlatformCapabilityProfile,
    PlatformFamily,
    RecoveryAction,
    default_platform_profiles,
    failure_disposition,
    negotiate_capability,
)
from codex_plugin_scanner.guard.runtime.network_policy_contract import (
    BackendCapability,
    EnforcementGrade,
    FailureMode,
)

_DIGEST = "b" * 64


def test_capability_negotiation_never_infers_missing_support() -> None:
    profile = PlatformCapabilityProfile(
        platform=PlatformFamily.LINUX,
        backend_id="linux.alpha",
        capabilities=frozenset({BackendCapability.DENY_ALL}),
        maximum_grade=EnforcementGrade.DENY_ALL,
        requires_privilege=True,
        production_ready=True,
        reason_code="verified",
    )
    assert (
        negotiate_capability(
            profile,
            CapabilityRequirement(
                capabilities=frozenset({BackendCapability.DENY_ALL}),
                minimum_grade=EnforcementGrade.DENY_ALL,
            ),
        )
        is EnforcementGrade.DENY_ALL
    )
    assert (
        negotiate_capability(
            profile,
            CapabilityRequirement(
                capabilities=frozenset(
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
                minimum_grade=EnforcementGrade.DESTINATION_ENFORCED,
            ),
        )
        is EnforcementGrade.UNAVAILABLE
    )


def test_profile_rejects_grade_capability_contradiction() -> None:
    with pytest.raises(ValueError, match="maximum_grade"):
        PlatformCapabilityProfile(
            platform=PlatformFamily.LINUX,
            backend_id="linux.invalid",
            capabilities=frozenset({BackendCapability.DENY_ALL}),
            maximum_grade=EnforcementGrade.DESTINATION_ENFORCED,
            requires_privilege=True,
            production_ready=True,
            reason_code="invalid",
        )


def test_requirement_rejects_grade_capability_contradiction() -> None:
    with pytest.raises(ValueError, match="minimum_grade"):
        CapabilityRequirement(
            capabilities=frozenset({BackendCapability.OBSERVE}),
            minimum_grade=EnforcementGrade.DESTINATION_ENFORCED,
        )


def test_non_ready_backend_cannot_negotiate_enforcement() -> None:
    profile = default_platform_profiles()[0]
    assert profile.production_ready is False
    assert (
        negotiate_capability(
            profile,
            CapabilityRequirement(
                capabilities=frozenset({BackendCapability.DENY_ALL}),
                minimum_grade=EnforcementGrade.DENY_ALL,
            ),
        )
        is EnforcementGrade.UNAVAILABLE
    )


@pytest.mark.parametrize(
    ("state", "recovery"),
    [
        (BackendState.UNAVAILABLE, RecoveryAction.RETRY),
        (BackendState.STALE, RecoveryAction.REPAIR),
        (BackendState.TAMPERED, RecoveryAction.REQUIRE_ADMIN),
        (BackendState.DEGRADED, RecoveryAction.ROLLBACK),
    ],
)
def test_failure_matrix_never_permits_network(
    state: BackendState,
    recovery: RecoveryAction,
) -> None:
    disposition = failure_disposition(backend_state=state, policy_mode=FailureMode.DENY)
    assert disposition.permit_workload_network is False
    assert disposition.effective_grade is EnforcementGrade.UNAVAILABLE
    assert disposition.recovery is recovery


def test_offline_failure_mode_reports_only_deny_all() -> None:
    disposition = failure_disposition(
        backend_state=BackendState.UNAVAILABLE,
        policy_mode=FailureMode.OFFLINE,
    )
    assert disposition.permit_workload_network is False
    assert disposition.effective_grade is EnforcementGrade.DENY_ALL


def test_control_plane_escape_hatch_is_non_inheritable() -> None:
    hatch = ControlPlaneEscapeHatch(
        installation_id="install.alpha",
        routes=frozenset({ControlPlaneRoute.POLICY, ControlPlaneRoute.HEALTH}),
        endpoint_digests=(_DIGEST,),
        executable_digest=_DIGEST,
        expires_at_epoch_ms=100,
    )
    assert hatch.inheritable_by_workload is False
    with pytest.raises(ValueError, match="cannot be inherited"):
        ControlPlaneEscapeHatch(
            installation_id="install.alpha",
            routes=frozenset({ControlPlaneRoute.POLICY}),
            endpoint_digests=(_DIGEST,),
            executable_digest=_DIGEST,
            expires_at_epoch_ms=100,
            inheritable_by_workload=True,
        )


def test_privacy_contract_prohibits_sensitive_flow_fields() -> None:
    policy = NetworkPrivacyPolicy(
        raw_destination_enabled=False,
        retention_seconds=86_400,
        maximum_events=1000,
    )
    assert policy.include_payload_bytes is False
    with pytest.raises(ValueError, match="sensitive flow fields"):
        NetworkPrivacyPolicy(
            raw_destination_enabled=True,
            retention_seconds=86_400,
            maximum_events=1000,
            include_url_components=True,
        )
    minimized = NetworkPrivacyPolicy(
        raw_destination_enabled=False,
        retention_seconds=2_592_000,
        maximum_events=1000,
    )
    assert minimized.retention_seconds == 2_592_000
    with pytest.raises(ValueError, match="one day"):
        NetworkPrivacyPolicy(
            raw_destination_enabled=True,
            retention_seconds=86_401,
            maximum_events=1000,
        )


def test_platform_matrix_is_explicitly_alpha_only() -> None:
    profiles = default_platform_profiles()
    assert {profile.platform for profile in profiles} == set(PlatformFamily)
    assert all(profile.production_ready is False for profile in profiles)
    linux_profile = next(profile for profile in profiles if profile.platform is PlatformFamily.LINUX)
    assert linux_profile.maximum_grade is EnforcementGrade.PROXY_ONLY
