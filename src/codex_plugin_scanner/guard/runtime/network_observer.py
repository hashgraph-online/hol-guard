"""Independent, privacy-safe projection of observed network flows."""

from __future__ import annotations

from dataclasses import dataclass

from codex_plugin_scanner.guard.runtime.network_local_core import logical_flow_id
from codex_plugin_scanner.guard.runtime.network_policy_contract import (
    EnforcementGrade,
    NetworkAction,
    NetworkEvidence,
    NetworkFlowRequest,
    NetworkProtocol,
    canonical_digest,
)


@dataclass(frozen=True, slots=True)
class NetworkObservation:
    """A read-only observation that does not imply an enforcement decision."""

    flow_id: str
    process_tree_digest: str
    destination_digest: str
    protocol: NetworkProtocol
    port: int
    observed_at_epoch_ms: int
    enforcement_observed: bool
    enforced_action: NetworkAction | None
    enforcement_grade: EnforcementGrade

    def __post_init__(self) -> None:
        if self.enforcement_observed != (self.enforced_action is not None):
            raise ValueError("enforced_action must be present exactly when enforcement was observed")
        if not self.enforcement_observed and self.enforcement_grade is not EnforcementGrade.OBSERVE:
            raise ValueError("observation without enforcement must report observe grade")


def project_network_observation(
    request: NetworkFlowRequest,
    *,
    enforcement: NetworkEvidence | None = None,
) -> NetworkObservation:
    """Project one flow without consulting or mutating policy or grant authority."""

    flow_id = logical_flow_id(request)
    process_tree_digest = request.process_tree.digest
    destination_digest = canonical_digest(request.destination)
    if enforcement is not None:
        expected = (
            flow_id,
            process_tree_digest,
            destination_digest,
            request.protocol,
            request.port,
        )
        actual = (
            enforcement.flow_id,
            enforcement.process_tree_digest,
            enforcement.destination_digest,
            enforcement.protocol,
            enforcement.port,
        )
        if actual != expected:
            raise ValueError("enforcement evidence does not describe the observed flow")

    return NetworkObservation(
        flow_id=flow_id,
        process_tree_digest=process_tree_digest,
        destination_digest=destination_digest,
        protocol=request.protocol,
        port=request.port,
        observed_at_epoch_ms=request.observed_at_epoch_ms,
        enforcement_observed=enforcement is not None,
        enforced_action=enforcement.action if enforcement is not None else None,
        enforcement_grade=enforcement.grade if enforcement is not None else EnforcementGrade.OBSERVE,
    )
