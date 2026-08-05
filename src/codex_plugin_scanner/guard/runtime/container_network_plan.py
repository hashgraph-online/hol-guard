"""Fail-closed network plans for portable Linux container backends."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from codex_plugin_scanner.guard.runtime.containment_contract import (
    ContainmentNetworkMode,
    ContainmentPolicy,
)
from codex_plugin_scanner.guard.runtime.execution_assurance_contract import framed_digest
from codex_plugin_scanner.guard.runtime.oci_plan_generator import OCIExecutionPlan


class ContainerNetworkPlanError(ValueError):
    """Raised when an OCI plan cannot satisfy the requested network boundary."""


class ContainerNetworkMechanism(str, Enum):
    NETWORK_NAMESPACE = "network-namespace"


class ContainerNetworkReceiptOutcome(str, Enum):
    ENFORCED = "enforced"
    FAILED_CLOSED = "failed-closed"


@dataclass(frozen=True)
class VerifiedContainerNetworkPlan:
    """Deterministic proof that an OCI plan enforces a containment network mode."""

    mode: ContainmentNetworkMode
    mechanism: ContainerNetworkMechanism
    oci_plan_digest: str
    proxy_endpoint_digest: str | None
    containment_policy_digest: str
    loopback_only: bool
    plan_digest: str


@dataclass(frozen=True)
class ContainerNetworkReceipt:
    """Privacy-bounded evidence emitted after applying a verified plan."""

    plan_digest: str
    containment_policy_digest: str
    namespace_identity_digest: str
    observed_at_epoch_ms: int
    outcome: ContainerNetworkReceiptOutcome
    receipt_digest: str


def issue_container_network_receipt(
    *,
    plan: VerifiedContainerNetworkPlan,
    namespace_identity_digest: str,
    observed_at_epoch_ms: int,
    outcome: ContainerNetworkReceiptOutcome,
) -> ContainerNetworkReceipt:
    if len(namespace_identity_digest) != 64 or any(
        character not in "0123456789abcdef" for character in namespace_identity_digest
    ):
        raise ContainerNetworkPlanError("namespace identity must be a lowercase SHA-256 digest")
    if observed_at_epoch_ms < 0:
        raise ContainerNetworkPlanError("receipt timestamp must be non-negative")
    fields: dict[str, object] = {
        "plan_digest": plan.plan_digest,
        "containment_policy_digest": plan.containment_policy_digest,
        "namespace_identity_digest": namespace_identity_digest,
        "observed_at_epoch_ms": observed_at_epoch_ms,
        "outcome": outcome.value,
    }
    return ContainerNetworkReceipt(
        plan_digest=plan.plan_digest,
        containment_policy_digest=plan.containment_policy_digest,
        namespace_identity_digest=namespace_identity_digest,
        observed_at_epoch_ms=observed_at_epoch_ms,
        outcome=outcome,
        receipt_digest=framed_digest("guard.container-network-receipt.v1", fields),
    )


def build_verified_container_network_plan(
    *,
    oci_plan: OCIExecutionPlan,
    containment_policy: ContainmentPolicy,
) -> VerifiedContainerNetworkPlan:
    """Verify the OCI network boundary and bind it to the containment policy."""
    namespaces = oci_plan.namespaces
    network = oci_plan.network
    if namespaces is None or network is None:
        raise ContainerNetworkPlanError("OCI plan must declare network isolation")
    if not namespaces.net_isolated:
        raise ContainerNetworkPlanError("container must use an isolated network namespace")
    if network.port_mappings:
        raise ContainerNetworkPlanError("container network plan must not publish ports")
    mode = containment_policy.network_mode

    if mode is ContainmentNetworkMode.OFFLINE:
        if not network.loopback_only or network.mode not in {"default", "none"}:
            raise ContainerNetworkPlanError("offline container must be loopback-only")
        proxy_endpoint_digest = None
    elif mode is ContainmentNetworkMode.GUARDED_PROXY:
        if network.loopback_only or network.mode != "bridge":
            raise ContainerNetworkPlanError("proxy-only container requires an isolated bridge")
        proxy_endpoint_digest = containment_policy.proxy_endpoint_digest
    else:
        raise ContainerNetworkPlanError("unsupported containment network mode")

    fields: dict[str, object] = {
        "mode": mode.value,
        "mechanism": ContainerNetworkMechanism.NETWORK_NAMESPACE.value,
        "oci_plan_digest": oci_plan.plan_digest,
        "containment_policy_digest": containment_policy.digest,
        "loopback_only": network.loopback_only,
        "proxy_endpoint_digest": proxy_endpoint_digest or "",
    }
    return VerifiedContainerNetworkPlan(
        mode=mode,
        mechanism=ContainerNetworkMechanism.NETWORK_NAMESPACE,
        oci_plan_digest=oci_plan.plan_digest,
        containment_policy_digest=containment_policy.digest,
        loopback_only=network.loopback_only,
        proxy_endpoint_digest=proxy_endpoint_digest,
        plan_digest=framed_digest("guard.container-network-plan.v1", fields),
    )


__all__ = [
    "ContainerNetworkMechanism",
    "ContainerNetworkPlanError",
    "ContainerNetworkReceipt",
    "ContainerNetworkReceiptOutcome",
    "VerifiedContainerNetworkPlan",
    "build_verified_container_network_plan",
    "issue_container_network_receipt",
]
