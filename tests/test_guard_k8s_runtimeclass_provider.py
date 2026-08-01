"""Tests for the Kubernetes RuntimeClass provider adapter.

Covers deny-by-default on handler-name-alone, admission downgrade,
sidecar injection, host-network, untrusted node, mutable image digest,
missing runtime evidence, and fully-verified pod yielding mapped guarantees.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from codex_plugin_scanner.guard.runtime.execution_assurance_contract import (
    AtomicGuaranteeKind,
    DecisionContext,
    GuardExecutionAssuranceBoundary,
    ProviderHealthState,
)
from codex_plugin_scanner.guard.runtime.isolation_provider import (
    IsolationProvider,
    ProviderPlanError,
)
from codex_plugin_scanner.guard.runtime.k8s_runtimeclass_provider import (
    AdmissionEvidence,
    ClusterTrustEvidence,
    K8sRuntimeClassEvidence,
    K8sRuntimeClassProvider,
    NodeEvidence,
    PodSpecEvidence,
    RBACNetworkEvidence,
    RuntimeEvidence,
    _evidence_boundary,
    _evidence_sufficient,
    _map_guarantees,
    build_k8s_evidence,
)

_SHA = "a" * 64
_OTHER = "b" * 64


def _context() -> DecisionContext:
    return DecisionContext(
        repository_digest=_SHA,
        workspace_digest=_OTHER,
        executable_digest=_SHA,
        action_class="execute",
    )


def _provider() -> K8sRuntimeClassProvider:
    return K8sRuntimeClassProvider(trust_ca_digest=_SHA)


# ---------------------------------------------------------------------------
# Provider contract conformance
# ---------------------------------------------------------------------------


class TestProviderContractConformance:
    def test_satisfies_isolation_provider_protocol(self) -> None:
        assert isinstance(_provider(), IsolationProvider)


class TestIdentity:
    def test_identity_fields(self) -> None:
        provider = _provider()
        identity = provider.identity()
        assert identity.provider_kind == "k8s-runtimeclass"
        assert identity.signing_identity == "guard-k8s-runtimeclass"
        assert identity.trust_domain == "guard.k8s"
        assert len(identity.binary_or_image_digest) == 64
        assert len(identity.implementation_version) > 0

    def test_identity_thumbprint_stable(self) -> None:
        p1 = _provider()
        p2 = _provider()
        assert p1.identity().thumbprint() == p2.identity().thumbprint()

    def test_identity_different_ca_digest(self) -> None:
        p1 = K8sRuntimeClassProvider(trust_ca_digest="1" * 64)
        p2 = K8sRuntimeClassProvider(trust_ca_digest="2" * 64)
        assert p1.identity().thumbprint() != p2.identity().thumbprint()


class TestCapabilities:
    def test_enforced_guarantees(self) -> None:
        provider = _provider()
        caps = provider.capabilities()
        enforced = [g for g in caps if g.enforced]
        kinds = {g.kind for g in enforced}
        assert AtomicGuaranteeKind.PROCESS in kinds
        assert AtomicGuaranteeKind.NETWORK in kinds
        assert AtomicGuaranteeKind.IDENTITY in kinds
        assert AtomicGuaranteeKind.PRIVILEGE in kinds
        assert AtomicGuaranteeKind.RESOURCE in kinds
        assert AtomicGuaranteeKind.CLEANUP in kinds
        assert AtomicGuaranteeKind.TENANT in kinds
        absent = [g for g in caps if not g.enforced]
        absent_kinds = {g.kind for g in absent}
        assert AtomicGuaranteeKind.KERNEL_HARDWARE in absent_kinds
        assert AtomicGuaranteeKind.OUTPUT in absent_kinds


class TestHealthCheck:
    def test_health_is_derived(self) -> None:
        provider = _provider()
        health = provider.health_check()
        assert health.state is ProviderHealthState.HEALTHY
        assert health.guarantees == provider.capabilities()
        assert health.reason is None


class TestEvidenceDataclasses:
    def _valid_evidence(self) -> K8sRuntimeClassEvidence:
        return build_k8s_evidence(
            cluster_ca_pinned=True,
            cluster_api_server_verified=True,
            admission_verified=True,
            admission_weaker=False,
            pod_spec_immutable=True,
            image_digest_verified=True,
            image_digest_changed=False,
            sidecar_unexpected=False,
            host_network=False,
            host_pid=False,
            privileged_containers=(),
            network_policy_enforced=True,
            node_id_verified=True,
            runtime_handler_verified=True,
        )

    def test_valid_evidence_constructs(self) -> None:
        ev = self._valid_evidence()
        assert ev.cluster.ca_pinned is True
        assert ev.runtime.runtime_handler_verified is True
        assert _evidence_sufficient(ev) is True


# ---------------------------------------------------------------------------
# Handler-name-alone grants nothing
# ---------------------------------------------------------------------------


class TestHandlerNameAloneDenyByDefault:
    """handler name ALONE never grants assurance — deny-by-default."""

    def test_handler_name_alone_no_guarantees(self) -> None:
        evidence = build_k8s_evidence(
            cluster_ca_pinned=False,
            cluster_api_server_verified=False,
            admission_verified=False,
            pod_spec_immutable=False,
            image_digest_verified=False,
            image_digest_changed=False,
            sidecar_unexpected=False,
            host_network=False,
            host_pid=False,
            privileged_containers=(),
            network_policy_enforced=False,
            node_id_verified=False,
            runtime_handler="guard-runtimeclass",
            runtime_handler_verified=False,
        )
        guarantees = _map_guarantees(evidence)
        enforced = [g for g in guarantees if g.enforced]
        assert enforced == []

    def test_handler_name_alone_boundary_observed_host(self) -> None:
        evidence = build_k8s_evidence(
            runtime_handler="guard-runtimeclass",
            runtime_handler_verified=False,
        )
        boundary = _evidence_boundary(evidence)
        assert boundary is GuardExecutionAssuranceBoundary.OBSERVED_HOST

    def test_handler_name_alone_no_evidence_object(self) -> None:
        provider = _provider()
        ctx = _context()
        with pytest.raises(ProviderPlanError, match="exceeds achievable"):
            provider.plan(ctx, GuardExecutionAssuranceBoundary.CONTROLLED_HOST)


# ---------------------------------------------------------------------------
# Changed / weaker admission fails
# ---------------------------------------------------------------------------


class TestAdmissionDowngrade:
    def test_weaker_admission_fails(self) -> None:
        evidence = build_k8s_evidence(
            admission_verified=True,
            admission_weaker=True,
            pod_spec_immutable=True,
            image_digest_verified=True,
            image_digest_changed=False,
            sidecar_unexpected=False,
            host_network=False,
            host_pid=False,
            privileged_containers=(),
            network_policy_enforced=True,
            node_id_verified=True,
            runtime_handler_verified=True,
        )
        assert _evidence_sufficient(evidence) is False
        guaranteed = _map_guarantees(evidence)
        enforced = [g for g in guaranteed if g.enforced]
        assert enforced == []

    def test_admission_not_verified_fails(self) -> None:
        evidence = build_k8s_evidence(
            admission_verified=False,
            admission_weaker=False,
            pod_spec_immutable=True,
            image_digest_verified=True,
            image_digest_changed=False,
            sidecar_unexpected=False,
            host_network=False,
            host_pid=False,
            privileged_containers=(),
            network_policy_enforced=True,
            node_id_verified=True,
            runtime_handler_verified=True,
        )
        assert _evidence_sufficient(evidence) is False

    def test_plan_refuses_when_admission_weaker(self) -> None:
        provider = _provider()
        ctx = _context()
        evidence = build_k8s_evidence(admission_weaker=True)
        lease = provider.plan(ctx, GuardExecutionAssuranceBoundary.OBSERVED_HOST, evidence=evidence)
        assert len(lease.plan_digest) == 64
        with pytest.raises(ProviderPlanError, match="exceeds achievable"):
            provider.plan(ctx, GuardExecutionAssuranceBoundary.CONTROLLED_HOST, evidence=evidence)


# ---------------------------------------------------------------------------
# Sidecar injection fails
# ---------------------------------------------------------------------------


class TestSidecarInjection:
    def test_unexpected_sidecar_fails(self) -> None:
        evidence = build_k8s_evidence(
            sidecar_containers=("istio-proxy", "envoy"),
            sidecar_unexpected=True,
            pod_spec_immutable=True,
            image_digest_verified=True,
            image_digest_changed=False,
            host_network=False,
            host_pid=False,
            privileged_containers=(),
            network_policy_enforced=True,
            node_id_verified=True,
            runtime_handler_verified=True,
        )
        assert _evidence_sufficient(evidence) is False
        guaranteed = _map_guarantees(evidence)
        enforced = [g for g in guaranteed if g.enforced]
        assert enforced == []

    def test_unconfigured_sidecars_fail_closed(self) -> None:
        evidence = build_k8s_evidence(
            sidecar_containers=("istio-proxy",),
            sidecar_unexpected=False,
            pod_spec_immutable=True,
            image_digest_verified=True,
            image_digest_changed=False,
            host_network=False,
            host_pid=False,
            privileged_containers=(),
            network_policy_enforced=True,
            node_id_verified=True,
            runtime_handler_verified=True,
        )
        assert _evidence_sufficient(evidence) is False


# ---------------------------------------------------------------------------
# Host-network fails
# ---------------------------------------------------------------------------


class TestHostNetwork:
    def test_host_network_fails(self) -> None:
        evidence = build_k8s_evidence(
            pod_spec_immutable=True,
            image_digest_verified=True,
            image_digest_changed=False,
            sidecar_unexpected=False,
            host_network=True,
            host_pid=False,
            privileged_containers=(),
            network_policy_enforced=True,
            node_id_verified=True,
            runtime_handler_verified=True,
        )
        assert _evidence_sufficient(evidence) is False
        guaranteed = _map_guarantees(evidence)
        enforced = [g for g in guaranteed if g.enforced]
        assert enforced == []

    def test_no_host_network_ok(self) -> None:
        evidence = build_k8s_evidence(
            pod_spec_immutable=True,
            image_digest_verified=True,
            image_digest_changed=False,
            sidecar_unexpected=False,
            host_network=False,
            host_pid=False,
            privileged_containers=(),
            network_policy_enforced=True,
            node_id_verified=True,
            runtime_handler_verified=True,
        )
        assert _evidence_sufficient(evidence) is True


# ---------------------------------------------------------------------------
# Host-PID and privileged containers fail
# ---------------------------------------------------------------------------


class TestHostPIDAndPrivileged:
    def test_host_pid_fails(self) -> None:
        evidence = build_k8s_evidence(
            pod_spec_immutable=True,
            image_digest_verified=True,
            image_digest_changed=False,
            sidecar_unexpected=False,
            host_network=False,
            host_pid=True,
            privileged_containers=(),
            network_policy_enforced=True,
            node_id_verified=True,
            runtime_handler_verified=True,
        )
        assert _evidence_sufficient(evidence) is False

    def test_privileged_containers_fails(self) -> None:
        evidence = build_k8s_evidence(
            pod_spec_immutable=True,
            image_digest_verified=True,
            image_digest_changed=False,
            sidecar_unexpected=False,
            host_network=False,
            host_pid=False,
            privileged_containers=("sidecar-privileged",),
            network_policy_enforced=True,
            node_id_verified=True,
            runtime_handler_verified=True,
        )
        assert _evidence_sufficient(evidence) is False


# ---------------------------------------------------------------------------
# Untrusted node fails
# ---------------------------------------------------------------------------


class TestUntrustedNode:
    def test_node_not_verified_fails(self) -> None:
        evidence = build_k8s_evidence(
            pod_spec_immutable=True,
            image_digest_verified=True,
            image_digest_changed=False,
            sidecar_unexpected=False,
            host_network=False,
            host_pid=False,
            privileged_containers=(),
            network_policy_enforced=True,
            node_id_verified=False,
            node_name="untrusted-worker",
            node_trust_domain=None,
            runtime_handler_verified=True,
        )
        assert _evidence_sufficient(evidence) is False
        guaranteed = _map_guarantees(evidence)
        enforced = [g for g in guaranteed if g.enforced]
        assert enforced == []

    def test_trusted_node_ok(self) -> None:
        evidence = build_k8s_evidence(
            pod_spec_immutable=True,
            image_digest_verified=True,
            image_digest_changed=False,
            sidecar_unexpected=False,
            host_network=False,
            host_pid=False,
            privileged_containers=(),
            network_policy_enforced=True,
            node_id_verified=True,
            node_name="trusted-worker-01",
            node_trust_domain="guard.cluster",
            runtime_handler_verified=True,
        )
        assert _evidence_sufficient(evidence) is True


# ---------------------------------------------------------------------------
# Mutable image digest fails
# ---------------------------------------------------------------------------


class TestMutableImageDigest:
    def test_image_digest_changed_fails(self) -> None:
        evidence = build_k8s_evidence(
            pod_spec_immutable=True,
            image_digest_verified=True,
            image_digest_changed=True,
            sidecar_unexpected=False,
            host_network=False,
            host_pid=False,
            privileged_containers=(),
            network_policy_enforced=True,
            node_id_verified=True,
            runtime_handler_verified=True,
        )
        assert _evidence_sufficient(evidence) is False
        guaranteed = _map_guarantees(evidence)
        enforced = [g for g in guaranteed if g.enforced]
        assert enforced == []

    def test_image_digest_not_verified_fails(self) -> None:
        evidence = build_k8s_evidence(
            pod_spec_immutable=True,
            image_digest_verified=False,
            image_digest_changed=False,
            sidecar_unexpected=False,
            host_network=False,
            host_pid=False,
            privileged_containers=(),
            network_policy_enforced=True,
            node_id_verified=True,
            runtime_handler_verified=True,
        )
        assert _evidence_sufficient(evidence) is False

    def test_image_digest_ok(self) -> None:
        evidence = build_k8s_evidence(
            pod_spec_immutable=True,
            image_digest_verified=True,
            image_digest_changed=False,
            sidecar_unexpected=False,
            host_network=False,
            host_pid=False,
            privileged_containers=(),
            network_policy_enforced=True,
            node_id_verified=True,
            runtime_handler_verified=True,
        )
        assert _evidence_sufficient(evidence) is True


# ---------------------------------------------------------------------------
# Missing runtime evidence fails
# ---------------------------------------------------------------------------


class TestMissingRuntimeEvidence:
    def test_runtime_handler_not_verified_fails(self) -> None:
        evidence = build_k8s_evidence(
            pod_spec_immutable=True,
            image_digest_verified=True,
            image_digest_changed=False,
            sidecar_unexpected=False,
            host_network=False,
            host_pid=False,
            privileged_containers=(),
            network_policy_enforced=True,
            node_id_verified=True,
            runtime_handler="guard-runtimeclass",
            runtime_handler_verified=False,
            execution_instance="exec-001",
        )
        assert _evidence_sufficient(evidence) is False
        guaranteed = _map_guarantees(evidence)
        enforced = [g for g in guaranteed if g.enforced]
        assert enforced == []

    def test_missing_cluster_ca_fails(self) -> None:
        evidence = build_k8s_evidence(cluster_ca_pinned=False)
        assert _evidence_sufficient(evidence) is False

    def test_missing_api_server_verified_fails(self) -> None:
        evidence = build_k8s_evidence(cluster_api_server_verified=False)
        assert _evidence_sufficient(evidence) is False

    def test_missing_pod_spec_immutable_fails(self) -> None:
        evidence = build_k8s_evidence(pod_spec_immutable=False)
        assert _evidence_sufficient(evidence) is False

    def test_missing_network_policy_fails(self) -> None:
        evidence = build_k8s_evidence(network_policy_enforced=False)
        assert _evidence_sufficient(evidence) is False

    def test_missing_execution_instance_fails(self) -> None:
        evidence = build_k8s_evidence(
            execution_instance=None,
            runtime_handler_verified=True,
        )
        assert _evidence_sufficient(evidence) is False

    def test_verified_image_without_digest_fails(self) -> None:
        evidence = build_k8s_evidence(image_digest=None)
        assert _evidence_sufficient(evidence) is False

    def test_missing_rbac_identifiers_fail(self) -> None:
        evidence = build_k8s_evidence()
        invalid_values = (
            replace(evidence.rbac_network, service_account=None),
            replace(evidence.rbac_network, namespace=None),
            replace(evidence.rbac_network, network_policy_name=None),
        )
        for invalid_rbac in invalid_values:
            assert _evidence_sufficient(replace(evidence, rbac_network=invalid_rbac)) is False

    def test_missing_node_identifiers_fail(self) -> None:
        evidence = build_k8s_evidence()
        invalid_values = (
            replace(evidence.node, node_name=None),
            replace(evidence.node, node_trust_domain=None),
        )
        for invalid_node in invalid_values:
            assert _evidence_sufficient(replace(evidence, node=invalid_node)) is False

    def test_mismatched_runtime_handler_refused(self) -> None:
        provider = _provider()
        evidence = build_k8s_evidence(runtime_handler="unexpected-runtime")
        with pytest.raises(ProviderPlanError, match="exceeds achievable"):
            provider.plan(
                _context(),
                GuardExecutionAssuranceBoundary.OS_ISOLATED,
                evidence=evidence,
            )

    def test_mismatched_cluster_ca_refused(self) -> None:
        provider = _provider()
        evidence = build_k8s_evidence(cluster_ca_digest=_OTHER)
        with pytest.raises(ProviderPlanError, match="exceeds achievable"):
            provider.plan(
                _context(),
                GuardExecutionAssuranceBoundary.OS_ISOLATED,
                evidence=evidence,
            )

    def test_zero_trust_anchor_rejected(self) -> None:
        with pytest.raises(ValueError, match="nonzero"):
            K8sRuntimeClassProvider(trust_ca_digest="0" * 64)


# ---------------------------------------------------------------------------
# Missing evidence = deny-by-default to OBSERVED_HOST
# ---------------------------------------------------------------------------


class TestNoEvidenceDenyByDefault:
    def test_no_evidence_boundary(self) -> None:
        provider = _provider()
        ctx = _context()
        lease = provider.plan(ctx, GuardExecutionAssuranceBoundary.OBSERVED_HOST)
        assert lease is not None

    def test_no_evidence_plan_refuses_controlled_host(self) -> None:
        provider = _provider()
        ctx = _context()
        with pytest.raises(ProviderPlanError, match="exceeds achievable"):
            provider.plan(ctx, GuardExecutionAssuranceBoundary.CONTROLLED_HOST)

    def test_no_evidence_plan_refuses_hardware_isolated(self) -> None:
        provider = _provider()
        ctx = _context()
        with pytest.raises(ProviderPlanError, match="hardware-isolated"):
            provider.plan(ctx, GuardExecutionAssuranceBoundary.HARDWARE_ISOLATED)


# ---------------------------------------------------------------------------
# Valid fully-verified pod yields mapped guarantees
# ---------------------------------------------------------------------------


class TestFullyVerifiedPod:
    def _valid_evidence(self) -> K8sRuntimeClassEvidence:
        return build_k8s_evidence(
            cluster_ca_pinned=True,
            cluster_api_server_verified=True,
            admission_verified=True,
            admission_policy_name="guard-runtimeclass-policy",
            admission_weaker=False,
            pod_spec_immutable=True,
            image_digest="d" * 64,
            image_digest_verified=True,
            image_digest_changed=False,
            sidecar_containers=(),
            sidecar_unexpected=False,
            host_network=False,
            host_pid=False,
            privileged_containers=(),
            service_account="guard-execution-sa",
            namespace="guard-execution",
            network_policy_enforced=True,
            network_policy_name="guard-netpol",
            node_name="worker-node-01",
            node_id_verified=True,
            node_trust_domain="guard.cluster",
            runtime_handler="guard-runtimeclass",
            runtime_handler_verified=True,
            execution_instance="exec-001",
        )

    def test_evidence_sufficient(self) -> None:
        evidence = self._valid_evidence()
        assert _evidence_sufficient(evidence) is True

    def test_evidence_boundary_os_isolated(self) -> None:
        evidence = self._valid_evidence()
        assert _evidence_boundary(evidence) is GuardExecutionAssuranceBoundary.OS_ISOLATED

    def test_all_guarantees_mapped(self) -> None:
        evidence = self._valid_evidence()
        guarantees = _map_guarantees(evidence)
        enforced = [g for g in guarantees if g.enforced]
        enforced_kinds = {g.kind: g.boundary for g in enforced}
        assert AtomicGuaranteeKind.PROCESS in enforced_kinds
        assert enforced_kinds[AtomicGuaranteeKind.PROCESS] is GuardExecutionAssuranceBoundary.OS_ISOLATED
        assert AtomicGuaranteeKind.NETWORK in enforced_kinds
        assert enforced_kinds[AtomicGuaranteeKind.NETWORK] is GuardExecutionAssuranceBoundary.OS_ISOLATED
        assert AtomicGuaranteeKind.IDENTITY in enforced_kinds
        assert enforced_kinds[AtomicGuaranteeKind.IDENTITY] is GuardExecutionAssuranceBoundary.OS_ISOLATED
        assert AtomicGuaranteeKind.PRIVILEGE in enforced_kinds
        assert enforced_kinds[AtomicGuaranteeKind.PRIVILEGE] is GuardExecutionAssuranceBoundary.OS_ISOLATED
        assert AtomicGuaranteeKind.RESOURCE in enforced_kinds
        assert enforced_kinds[AtomicGuaranteeKind.RESOURCE] is GuardExecutionAssuranceBoundary.OS_ISOLATED
        assert AtomicGuaranteeKind.CLEANUP in enforced_kinds
        assert enforced_kinds[AtomicGuaranteeKind.CLEANUP] is GuardExecutionAssuranceBoundary.OS_ISOLATED
        assert AtomicGuaranteeKind.TENANT in enforced_kinds
        assert enforced_kinds[AtomicGuaranteeKind.TENANT] is GuardExecutionAssuranceBoundary.OS_ISOLATED

    def test_fs_and_secret_enforced(self) -> None:
        evidence = self._valid_evidence()
        guarantees = _map_guarantees(evidence)
        kinds = {g.kind: g for g in guarantees}
        assert kinds[AtomicGuaranteeKind.FILESYSTEM].enforced is True
        assert kinds[AtomicGuaranteeKind.SECRET].enforced is True

    def test_kernel_hardware_not_enforced(self) -> None:
        evidence = self._valid_evidence()
        guarantees = _map_guarantees(evidence)
        kinds = {g.kind: g for g in guarantees}
        assert kinds[AtomicGuaranteeKind.KERNEL_HARDWARE].enforced is False

    def test_output_not_enforced(self) -> None:
        evidence = self._valid_evidence()
        guarantees = _map_guarantees(evidence)
        kinds = {g.kind: g for g in guarantees}
        assert kinds[AtomicGuaranteeKind.OUTPUT].enforced is False

    def test_plan_succeeds_at_os_isolated(self) -> None:
        provider = _provider()
        ctx = _context()
        evidence = self._valid_evidence()
        lease = provider.plan(ctx, GuardExecutionAssuranceBoundary.OS_ISOLATED, evidence=evidence)
        assert lease is not None
        assert len(lease.attempt_nonce) == 32

    def test_plan_refuses_hardware_isolated(self) -> None:
        provider = _provider()
        ctx = _context()
        evidence = self._valid_evidence()
        with pytest.raises(ProviderPlanError, match="hardware-isolated"):
            provider.plan(ctx, GuardExecutionAssuranceBoundary.HARDWARE_ISOLATED, evidence=evidence)

    def test_execute_refuses_without_authenticated_runner(self) -> None:
        provider = _provider()
        ctx = _context()
        evidence = self._valid_evidence()
        lease = provider.plan(
            ctx,
            GuardExecutionAssuranceBoundary.OS_ISOLATED,
            evidence=evidence,
        )
        with pytest.raises(ProviderPlanError, match="planning-only"):
            provider.execute(lease)


# ---------------------------------------------------------------------------
# Provider integration test
# ---------------------------------------------------------------------------


class TestProviderIntegration:
    def test_planning_only_lifecycle(self) -> None:
        provider = _provider()
        ctx = _context()
        evidence = build_k8s_evidence()
        lease = provider.plan(
            ctx,
            GuardExecutionAssuranceBoundary.OS_ISOLATED,
            evidence=evidence,
        )
        with pytest.raises(ProviderPlanError, match="planning-only"):
            provider.execute(lease)
        provider.cancel(lease.attempt_nonce)
        provider.cleanup(lease.attempt_nonce)

    def test_evidence_to_guarantees_static(self) -> None:
        valid = build_k8s_evidence()
        invalid = build_k8s_evidence(cluster_ca_pinned=False)
        valid_guarantees = K8sRuntimeClassProvider.evidence_to_guarantees(valid)
        invalid_guarantees = K8sRuntimeClassProvider.evidence_to_guarantees(invalid)
        assert any(g.enforced for g in valid_guarantees)
        assert not any(g.enforced for g in invalid_guarantees)


# ---------------------------------------------------------------------------
# Deny-by-default: handler name alone — explicit edge cases
# ---------------------------------------------------------------------------


class TestDenyByDefaultHandlerNameAlone:
    """handler name ALONE grants nothing — deny-by-default."""

    def test_handler_label_only(self) -> None:
        evidence = K8sRuntimeClassEvidence(
            cluster=ClusterTrustEvidence(ca_pinned=False, api_server_verified=False),
            admission=AdmissionEvidence(
                admission_verified=False,
                admission_policy_name="",
                admission_weaker=False,
            ),
            pod_spec=PodSpecEvidence(
                pod_spec_immutable=False,
                image_digest=None,
                image_digest_verified=False,
                image_digest_changed=False,
            ),
            rbac_network=RBACNetworkEvidence(
                service_account=None,
                namespace=None,
                network_policy_enforced=False,
                network_policy_name=None,
            ),
            node=NodeEvidence(
                node_name=None,
                node_id_verified=False,
                node_trust_domain=None,
            ),
            runtime=RuntimeEvidence(
                runtime_handler="guard-runtimeclass",
                runtime_handler_verified=False,
                execution_instance=None,
            ),
        )
        guarantees = _map_guarantees(evidence)
        enforced = [g for g in guarantees if g.enforced]
        assert enforced == [], "handler name alone must not grant any enforcement"

    def test_only_evidence_fields_present_nothing_enforced(self) -> None:
        evidence = K8sRuntimeClassEvidence(
            cluster=ClusterTrustEvidence(ca_pinned=False, api_server_verified=False),
            admission=AdmissionEvidence(
                admission_verified=False,
                admission_policy_name="",
                admission_weaker=False,
            ),
            pod_spec=PodSpecEvidence(
                pod_spec_immutable=False,
                image_digest=None,
                image_digest_verified=False,
                image_digest_changed=False,
            ),
            rbac_network=RBACNetworkEvidence(
                service_account=None,
                namespace=None,
                network_policy_enforced=False,
                network_policy_name=None,
            ),
            node=NodeEvidence(
                node_name=None,
                node_id_verified=False,
                node_trust_domain=None,
            ),
            runtime=RuntimeEvidence(
                runtime_handler=None,
                runtime_handler_verified=False,
                execution_instance=None,
            ),
        )
        assert _evidence_sufficient(evidence) is False
        guarantees = _map_guarantees(evidence)
        boundary = _evidence_boundary(evidence)
        assert boundary is GuardExecutionAssuranceBoundary.OBSERVED_HOST
        assert all(not guarantee.enforced for guarantee in guarantees)
        assert all(guarantee.boundary is GuardExecutionAssuranceBoundary.OBSERVED_HOST for guarantee in guarantees)
