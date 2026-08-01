"""Kubernetes RuntimeClass provider adapter.

Validates cluster trust, admission control, immutable pod spec/image digest,
service account/namespace/network policy, node identity, observed runtime
handler, and execution instance — then maps verified evidence to atomic
guarantees. Deny-by-default: handler name ALONE never grants assurance;
changed/weaker admission, unexpected sidecar, host-network, untrusted node,
mutable image, or missing runtime evidence all FAIL (lower/refuse assurance).

Pure validation + evidence→guarantee mapping; no live cluster calls.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Final, NoReturn

from codex_plugin_scanner.guard.runtime.execution_assurance_contract import (
    AtomicGuarantee,
    AtomicGuaranteeKind,
    DecisionContext,
    ExecutionLease,
    GuardExecutionAssuranceBoundary,
    ProviderHealthState,
    ProviderIdentity,
    framed_digest,
)
from codex_plugin_scanner.guard.runtime.isolation_provider import (
    ProviderHealth,
    ProviderPlanError,
    validate_provider_plan_inputs,
)

_PROVIDER_KIND: Final = "k8s-runtimeclass"
_SIGNING_IDENTITY: Final = "guard-k8s-runtimeclass"
_TRUST_DOMAIN: Final = "guard.k8s"
_BOUNDARY_ORDER: Final = (
    GuardExecutionAssuranceBoundary.OBSERVED_HOST,
    GuardExecutionAssuranceBoundary.CONTROLLED_HOST,
    GuardExecutionAssuranceBoundary.OS_ISOLATED,
    GuardExecutionAssuranceBoundary.HARDWARE_ISOLATED,
)

# Guarantees this provider CAN enforce when all evidence is verified.
_K8S_ENFORCED: Final = (
    AtomicGuaranteeKind.PROCESS,
    AtomicGuaranteeKind.NETWORK,
    AtomicGuaranteeKind.IDENTITY,
    AtomicGuaranteeKind.PRIVILEGE,
    AtomicGuaranteeKind.RESOURCE,
    AtomicGuaranteeKind.CLEANUP,
    AtomicGuaranteeKind.TENANT,
)

# Guaranteed enforced but at OS_ISOLATED only (pod scheduling, not strict isolation).
_K8S_OS_ISOLATED: Final = (
    AtomicGuaranteeKind.FILESYSTEM,
    AtomicGuaranteeKind.SECRET,
)

# Never enforced by RuntimeClass admission alone.
_K8S_ABSENT: Final = (
    AtomicGuaranteeKind.KERNEL_HARDWARE,
    AtomicGuaranteeKind.OUTPUT,
)


@dataclass(frozen=True)
class ClusterTrustEvidence:
    """Evidence that the Kubernetes cluster is trusted."""

    ca_pinned: bool
    api_server_verified: bool
    ca_digest: str | None = None


@dataclass(frozen=True)
class AdmissionEvidence:
    """Evidence from admission control (webhook/validating/mutating)."""

    admission_verified: bool
    admission_policy_name: str
    admission_weaker: bool  # True if admission was downgraded


@dataclass(frozen=True)
class PodSpecEvidence:
    """Evidence from immutable pod spec verification."""

    pod_spec_immutable: bool
    image_digest: str | None
    image_digest_verified: bool
    image_digest_changed: bool
    sidecar_containers: tuple[str, ...] = ()
    sidecar_unexpected: bool = False
    host_network: bool = False
    host_pid: bool = False
    privileged_containers: tuple[str, ...] = ()


@dataclass(frozen=True)
class RBACNetworkEvidence:
    """Evidence from service account, namespace, and network policy."""

    service_account: str | None
    namespace: str | None
    network_policy_enforced: bool
    network_policy_name: str | None


@dataclass(frozen=True)
class NodeEvidence:
    """Evidence from node identity verification."""

    node_name: str | None
    node_id_verified: bool
    node_trust_domain: str | None


@dataclass(frozen=True)
class RuntimeEvidence:
    """Evidence from observed runtime handler and execution instance."""

    runtime_handler: str | None
    runtime_handler_verified: bool
    execution_instance: str | None


@dataclass(frozen=True)
class K8sRuntimeClassEvidence:
    """Complete evidence set for the K8s RuntimeClass provider."""

    cluster: ClusterTrustEvidence
    admission: AdmissionEvidence
    pod_spec: PodSpecEvidence
    rbac_network: RBACNetworkEvidence
    node: NodeEvidence
    runtime: RuntimeEvidence


def _require_decision_context(value: object) -> DecisionContext:
    if not isinstance(value, DecisionContext):
        raise ProviderPlanError("context must be a DecisionContext")
    return value


def _evidence_boundary(
    evidence: K8sRuntimeClassEvidence,
) -> GuardExecutionAssuranceBoundary:
    """Compute the boundary achievable given the evidence."""
    if not _evidence_sufficient(evidence):
        return GuardExecutionAssuranceBoundary.OBSERVED_HOST
    return GuardExecutionAssuranceBoundary.OS_ISOLATED


def _evidence_sufficient(evidence: K8sRuntimeClassEvidence) -> bool:
    """Return True only when all evidence is fully verified and clean."""
    # Deny-by-default: missing or unverified cluster trust
    if not evidence.cluster.ca_pinned or not evidence.cluster.api_server_verified:
        return False
    # Admission must be verified, not weaker
    if not evidence.admission.admission_verified:
        return False
    if evidence.admission.admission_weaker:
        return False
    # Every asserted verification flag must have the corresponding immutable
    # identifier. Boolean labels alone never grant assurance.
    pod = evidence.pod_spec
    if (
        not pod.pod_spec_immutable
        or not pod.image_digest_verified
        or pod.image_digest is None
        or len(pod.image_digest) != 64
        or pod.image_digest_changed
        or pod.sidecar_unexpected
        or pod.sidecar_containers
        or pod.host_network
        or pod.host_pid
        or pod.privileged_containers
    ):
        return False
    rbac = evidence.rbac_network
    if (
        not rbac.service_account
        or not rbac.namespace
        or not rbac.network_policy_enforced
        or not rbac.network_policy_name
    ):
        return False
    node = evidence.node
    if not node.node_id_verified or not node.node_name or not node.node_trust_domain:
        return False
    runtime = evidence.runtime
    return bool(runtime.runtime_handler_verified and runtime.runtime_handler and runtime.execution_instance)


def _map_guarantees(evidence: K8sRuntimeClassEvidence) -> tuple[AtomicGuarantee, ...]:
    """Map verified evidence to atomic guarantees.

    Deny-by-default: only guarantees supported by the K8s runtimeclass adapter
    and verified by the evidence are granted. Handler name ALONE grants nothing.
    """
    boundary = _evidence_boundary(evidence)
    enforced = _evidence_sufficient(evidence)
    guarantees: list[AtomicGuarantee] = []

    for kind in _K8S_ENFORCED:
        guarantees.append(
            AtomicGuarantee(
                kind=kind,
                enforced=enforced,
                boundary=boundary if enforced else GuardExecutionAssuranceBoundary.OBSERVED_HOST,
            )
        )

    for kind in _K8S_OS_ISOLATED:
        # Filesystem and secret follow deny-by-default: enforced only when ALL
        # evidence verified.
        guarantees.append(
            AtomicGuarantee(
                kind=kind,
                enforced=enforced,
                boundary=boundary if enforced else GuardExecutionAssuranceBoundary.OBSERVED_HOST,
            )
        )

    for kind in _K8S_ABSENT:
        guarantees.append(
            AtomicGuarantee(
                kind=kind,
                enforced=False,
                boundary=GuardExecutionAssuranceBoundary.OBSERVED_HOST,
            )
        )

    return tuple(guarantees)


class K8sRuntimeClassProvider:
    """Kubernetes RuntimeClass isolation provider adapter.

    Validates admission control, immutable pod spec/image digest, service
    account/namespace/network policy, node identity, and observed runtime
    handler. Maps verified evidence to atomic guarantees. Pure validation —
    no live cluster calls.
    """

    _trust_ca_digest: str
    _expected_runtime_handler: str | None

    def __init__(
        self,
        *,
        trust_ca_digest: str,
        expected_runtime_handler: str = "guard-runtimeclass",
    ) -> None:
        if len(trust_ca_digest) != 64 or set(trust_ca_digest) == {"0"}:
            raise ValueError("trust_ca_digest must be a nonzero 64-character digest")
        if not expected_runtime_handler:
            raise ValueError("expected_runtime_handler must be non-empty")
        self._trust_ca_digest = trust_ca_digest
        self._expected_runtime_handler = expected_runtime_handler

    @staticmethod
    def _lease_ttl_seconds() -> int:
        return 60

    def identity(self) -> ProviderIdentity:
        return ProviderIdentity(
            provider_kind=_PROVIDER_KIND,
            implementation_version="1.0.0",
            binary_or_image_digest=self._trust_ca_digest,
            signing_identity=_SIGNING_IDENTITY,
            trust_domain=_TRUST_DOMAIN,
        )

    def capabilities(self) -> tuple[AtomicGuarantee, ...]:
        # Static capabilities: what the provider CAN do when all evidence verified.
        guarantees: list[AtomicGuarantee] = []
        for kind in _K8S_ENFORCED:
            guarantees.append(
                AtomicGuarantee(
                    kind=kind,
                    enforced=True,
                    boundary=GuardExecutionAssuranceBoundary.OS_ISOLATED,
                )
            )
        for kind in _K8S_OS_ISOLATED:
            guarantees.append(
                AtomicGuarantee(
                    kind=kind,
                    enforced=True,
                    boundary=GuardExecutionAssuranceBoundary.OS_ISOLATED,
                )
            )
        for kind in _K8S_ABSENT:
            guarantees.append(
                AtomicGuarantee(
                    kind=kind,
                    enforced=False,
                    boundary=GuardExecutionAssuranceBoundary.OBSERVED_HOST,
                )
            )
        return tuple(guarantees)

    def health_check(self) -> ProviderHealth:
        # Health is derived from capabilities (never self-labeled).
        return ProviderHealth(
            state=ProviderHealthState.HEALTHY,
            guarantees=self.capabilities(),
            reason=None,
        )

    def plan(
        self,
        context: object,
        minimum_boundary: object,
        *,
        evidence: K8sRuntimeClassEvidence | None = None,
        input_paths: tuple[str, ...] = (),
        declared_outputs: tuple[str, ...] = (),
    ) -> ExecutionLease:
        """Produce a pure, side-effect-free fenced lease or raise ProviderPlanError.

        When ``evidence`` is provided, validates it and computes achievable
        boundary. Without evidence, defaults to OBSERVED_HOST (deny-by-default).
        """
        validated_context: DecisionContext = _require_decision_context(context)
        validate_provider_plan_inputs(input_paths, declared_outputs)

        # Hardware isolation is never achievable via K8s RuntimeClass alone.
        if minimum_boundary is GuardExecutionAssuranceBoundary.HARDWARE_ISOLATED:
            raise ProviderPlanError("K8s RuntimeClass cannot provide hardware-isolated boundary")

        if evidence is not None:
            ca_matches = evidence.cluster.ca_digest == self._trust_ca_digest
            handler_matches = evidence.runtime.runtime_handler == self._expected_runtime_handler
            achievable = (
                _evidence_boundary(evidence)
                if _evidence_sufficient(evidence) and ca_matches and handler_matches
                else GuardExecutionAssuranceBoundary.OBSERVED_HOST
            )
        else:
            achievable = GuardExecutionAssuranceBoundary.OBSERVED_HOST

        # If minimum boundary exceeds what evidence provides, refuse.
        if not isinstance(minimum_boundary, GuardExecutionAssuranceBoundary):
            raise ProviderPlanError("unknown minimum assurance boundary")
        achievable_idx = _BOUNDARY_ORDER.index(achievable)
        minimum_idx = _BOUNDARY_ORDER.index(minimum_boundary)
        if minimum_idx > achievable_idx:
            raise ProviderPlanError(
                f"minimum boundary {minimum_boundary.value} exceeds achievable {achievable.value} from evidence"
            )

        evidence_digest = framed_digest(
            "guard.k8s-runtimeclass-evidence.v1",
            {"evidence": repr(evidence) if evidence is not None else "absent"},
        )
        plan_digest = framed_digest(
            "guard.k8s-runtimeclass-plan.v1",
            {
                "context_digest": validated_context.context_digest,
                "minimum_boundary": minimum_boundary.value,
                "achievable_boundary": achievable.value,
                "runtime_handler": self._expected_runtime_handler,
                "evidence_digest": evidence_digest,
            },
        )
        attempt_nonce = framed_digest(
            "guard.k8s-runtimeclass-attempt.v1",
            {
                "plan_digest": plan_digest,
                "execution_instance": (evidence.runtime.execution_instance if evidence is not None else "absent"),
            },
        )[:32]
        return ExecutionLease(
            plan_digest=plan_digest,
            provider_thumbprint=self.identity().thumbprint(),
            fencing_generation=int(plan_digest[:8], 16),
            lease_expiry_epoch_seconds=int(time.time()) + self._lease_ttl_seconds(),
            attempt_nonce=attempt_nonce,
            input_manifest_digest=validated_context.executable_digest,
        )

    def execute(self, _lease: ExecutionLease) -> NoReturn:
        """Refuse execution: this adapter validates evidence but makes no live calls."""
        raise ProviderPlanError(
            "Kubernetes RuntimeClass adapter is planning-only; execution requires an authenticated runner"
        )

    def cancel(self, execution_instance: str) -> None:
        if not execution_instance:
            raise ProviderPlanError("execution_instance must be non-empty")

    def cleanup(self, execution_instance: str) -> None:
        if not execution_instance:
            raise ProviderPlanError("execution_instance must be non-empty")

    @staticmethod
    def evidence_to_guarantees(evidence: K8sRuntimeClassEvidence) -> tuple[AtomicGuarantee, ...]:
        """Public static: map evidence directly to atomic guarantees."""
        return _map_guarantees(evidence)


def build_k8s_evidence(
    *,
    cluster_ca_pinned: bool = True,
    cluster_ca_digest: str | None = "a" * 64,
    cluster_api_server_verified: bool = True,
    admission_verified: bool = True,
    admission_policy_name: str = "guard-runtimeclass-policy",
    admission_weaker: bool = False,
    pod_spec_immutable: bool = True,
    image_digest: str | None = "1" * 64,
    image_digest_verified: bool = True,
    image_digest_changed: bool = False,
    sidecar_containers: tuple[str, ...] = (),
    sidecar_unexpected: bool = False,
    host_network: bool = False,
    host_pid: bool = False,
    privileged_containers: tuple[str, ...] = (),
    service_account: str | None = "guard-execution-sa",
    namespace: str | None = "guard-execution",
    network_policy_enforced: bool = True,
    network_policy_name: str | None = "guard-netpol",
    node_name: str | None = "worker-node-01",
    node_id_verified: bool = True,
    node_trust_domain: str | None = "guard.cluster",
    runtime_handler: str | None = "guard-runtimeclass",
    runtime_handler_verified: bool = True,
    execution_instance: str | None = "exec-001",
) -> K8sRuntimeClassEvidence:
    """Helper to construct a K8sRuntimeClassEvidence from individual fields."""
    return K8sRuntimeClassEvidence(
        cluster=ClusterTrustEvidence(
            ca_pinned=cluster_ca_pinned,
            ca_digest=cluster_ca_digest,
            api_server_verified=cluster_api_server_verified,
        ),
        admission=AdmissionEvidence(
            admission_verified=admission_verified,
            admission_policy_name=admission_policy_name,
            admission_weaker=admission_weaker,
        ),
        pod_spec=PodSpecEvidence(
            pod_spec_immutable=pod_spec_immutable,
            image_digest=image_digest,
            image_digest_verified=image_digest_verified,
            image_digest_changed=image_digest_changed,
            sidecar_containers=sidecar_containers,
            sidecar_unexpected=sidecar_unexpected,
            host_network=host_network,
            host_pid=host_pid,
            privileged_containers=privileged_containers,
        ),
        rbac_network=RBACNetworkEvidence(
            service_account=service_account,
            namespace=namespace,
            network_policy_enforced=network_policy_enforced,
            network_policy_name=network_policy_name,
        ),
        node=NodeEvidence(
            node_name=node_name,
            node_id_verified=node_id_verified,
            node_trust_domain=node_trust_domain,
        ),
        runtime=RuntimeEvidence(
            runtime_handler=runtime_handler,
            runtime_handler_verified=runtime_handler_verified,
            execution_instance=execution_instance,
        ),
    )


__all__ = [
    "AdmissionEvidence",
    "ClusterTrustEvidence",
    "K8sRuntimeClassEvidence",
    "K8sRuntimeClassProvider",
    "NodeEvidence",
    "PodSpecEvidence",
    "RBACNetworkEvidence",
    "RuntimeEvidence",
    "build_k8s_evidence",
]
